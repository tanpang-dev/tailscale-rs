//! UDP underlay transport: carries WireGuard traffic directly to peers over UDP,
//! demultiplexing disco and STUN off the same socket.
//!
//! This is the groundwork for direct connections. Peers that advertise UDP
//! endpoints (see the advertisement in [`crate::control_runner`]) receive disco
//! pings from full clients on this socket; once a path is established, WireGuard
//! data flows here instead of over a DERP relay.
//!
//! Scope note: this module binds the socket, registers an underlay transport
//! with the dataplane, and demultiplexes inbound packets. Actually *routing*
//! peers onto this transport (path selection / upgrade from DERP) is a separate
//! step and is not done here — until then the send pump is idle and only the
//! receive/demux path is exercised.
//!
//! Enabled with `TS_RS_UDP=1`; `TS_RS_UDP_PROBE=1` keeps the older
//! observe-only behavior (bind and log, no transport registration). The port is
//! `TS_RS_UDP_PORT` (default 41641, the Go client's default magicsock port).

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use kameo::actor::ActorRef;
use tokio::{net::UdpSocket, sync::mpsc};
use ts_packet::PacketMut;
use ts_transport::{BatchRecvIter, BatchSendIter, PeerId, UnderlayTransport, UnderlayTransportId};

use crate::{
    dataplane::{DataplaneActor, UnderlayFromDataplane, UnderlayToDataplane},
    env::Env,
    peer_tracker::PeerState,
};

/// How long after the last inbound UDP packet from a peer we keep treating the
/// direct path as live for routing. If the direct path dies, no more UDP
/// arrives, the peer goes stale, and routing reverts to DERP.
const DIRECT_TTL: Duration = Duration::from_secs(15);

/// Shared record of which peers have a live direct UDP path, plus the id of the
/// UDP underlay transport. Read by the route updater to route outbound traffic
/// for a peer over UDP when its path is fresh, falling back to DERP otherwise.
#[derive(Default)]
pub struct DirectState {
    /// The UDP underlay transport id, once registered with the dataplane.
    udp_transport_id: Option<UnderlayTransportId>,
    /// Last time an inbound UDP packet was received from each peer.
    last_recv: HashMap<PeerId, Instant>,
}

impl DirectState {
    /// The UDP transport to use for a peer, if its direct path is currently live.
    pub fn direct_transport(&self, peer: PeerId) -> Option<UnderlayTransportId> {
        let id = self.udp_transport_id?;
        let last = self.last_recv.get(&peer)?;
        (last.elapsed() < DIRECT_TTL).then_some(id)
    }

    /// The UDP underlay transport id, if registered. Used by the kernel-WG
    /// bridge as the fallback transport before per-peer routes are published.
    pub fn udp_transport_id(&self) -> Option<UnderlayTransportId> {
        self.udp_transport_id
    }
}

/// Shared handle to [`DirectState`].
pub type SharedDirect = Arc<RwLock<DirectState>>;

/// The default port, matching the Go client's default magicsock port.
const DEFAULT_PORT: u16 = 41641;

/// Maximum size of a received UDP datagram we will buffer.
const RECV_BUF: usize = 1 << 16;

/// Minimum interval between observation log lines for the same (source, kind) pair.
const LOG_INTERVAL: Duration = Duration::from_secs(1);

/// The configured UDP port, `Some` iff `TS_RS_UDP` or `TS_RS_UDP_PROBE` is `1`.
///
/// Used by the endpoint advertisement in [`crate::control_runner`] so the
/// advertised port always matches the port actually bound here.
pub(crate) fn configured_port() -> Option<u16> {
    if !enabled() {
        return None;
    }

    let port = match std::env::var("TS_RS_UDP_PORT") {
        Ok(v) => match v.trim().parse() {
            Ok(port) => port,
            Err(e) => {
                tracing::warn!(value = %v, error = %e, "unparseable TS_RS_UDP_PORT, using default");
                DEFAULT_PORT
            }
        },
        Err(_) => DEFAULT_PORT,
    };

    Some(port)
}

/// Whether the socket should be bound at all (transport or observe-only).
fn enabled() -> bool {
    env_is_1("TS_RS_UDP") || env_is_1("TS_RS_UDP_PROBE")
}

/// Whether the full underlay transport (not just observation) is enabled.
fn transport_enabled() -> bool {
    env_is_1("TS_RS_UDP")
}

fn env_is_1(key: &str) -> bool {
    std::env::var(key).map(|v| v == "1").unwrap_or(false)
}

/// Rough wire classification of a received UDP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PacketKind {
    Disco,
    Stun,
    WireguardLike,
    Unknown,
}

/// Classify `buf` by its leading bytes.
fn classify(buf: &[u8]) -> PacketKind {
    /// The STUN magic cookie (RFC 5389), bytes 4..8 of every STUN message.
    const STUN_MAGIC: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

    if ts_disco_protocol::is_disco_message(buf) {
        PacketKind::Disco
    } else if buf.len() >= 20 && buf[0] & 0xc0 == 0 && buf[4..8] == STUN_MAGIC {
        PacketKind::Stun
    } else if buf.len() >= 4 && (1..=4).contains(&buf[0]) && buf[1..4] == [0; 3] {
        // WireGuard message types 1-4, followed by three reserved zero bytes.
        PacketKind::WireguardLike
    } else {
        PacketKind::Unknown
    }
}

/// Error type for the UDP transport.
#[derive(Debug, thiserror::Error)]
pub enum UdpError {
    /// An I/O error on the socket.
    #[error("udp io error: {0}")]
    Io(#[from] std::io::Error),
}

/// A disco packet siphoned off the UDP socket, for the (future) disco engine.
pub type DiscoPacket = (SocketAddr, Vec<u8>);

/// UDP underlay transport keyed by peer socket address.
///
/// Disco and STUN packets are demultiplexed out of the receive path: disco is
/// forwarded on `disco_tx`, STUN is dropped, and only WireGuard-like packets are
/// returned to the caller.
struct UdpTransport {
    socket: Arc<UdpSocket>,
    disco_tx: mpsc::UnboundedSender<DiscoPacket>,
    /// For stamping direct-path liveness on inbound disco (see `recv`).
    table: Arc<RwLock<AddrTable>>,
    direct: SharedDirect,
}

impl UnderlayTransport for UdpTransport {
    type PeerKey = SocketAddr;
    type Error = UdpError;

    async fn send(
        &self,
        packet_batch: impl BatchSendIter<Self::PeerKey>,
    ) -> Result<(), Self::Error> {
        for (addr, pkts) in packet_batch.batch_iter() {
            for pkt in pkts {
                self.socket.send_to(pkt.as_ref(), addr).await?;
            }
        }
        Ok(())
    }

    async fn recv(&self) -> impl BatchRecvIter<Self::PeerKey, Error = Self::Error> {
        loop {
            let mut buf = vec![0u8; RECV_BUF];
            match self.socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    buf.truncate(len);
                    match classify(&buf) {
                        PacketKind::Disco => {
                            // Disco from a known peer also proves the direct path
                            // is live. Peers (e.g. macOS) ping every ~5s even when
                            // idle, so stamping here keeps the direct route from
                            // decaying to DERP between bulk transfers, when no
                            // WireGuard data is flowing to refresh it.
                            // NB: bind the lookup result first so the read
                            // guard is dropped before taking the write locks
                            // below (an `if let` on the guard expression would
                            // keep it alive across the body and self-deadlock).
                            let peer =
                                self.table.read().unwrap().addr_to_peer.get(&src).copied();
                            if let Some(peer) = peer {
                                self.direct
                                    .write()
                                    .unwrap()
                                    .last_recv
                                    .insert(peer, Instant::now());
                                // Learn the working address from disco too, so
                                // outbound WireGuard follows the same path.
                                self.table.write().unwrap().record_recv(peer, src);
                            }
                            // Best-effort: drop the packet if the observer has gone away.
                            drop(self.disco_tx.send((src, buf)));
                            continue;
                        }
                        PacketKind::Stun => continue,
                        PacketKind::WireguardLike | PacketKind::Unknown => {
                            return [Ok((src, [PacketMut::from(buf)]))];
                        }
                    }
                }
                Err(e) => return [Err(UdpError::Io(e))],
            }
        }
    }
}

/// Bidirectional map between peer socket addresses and [`PeerId`]s, rebuilt from
/// each peer-state update out of peers' advertised underlay endpoints.
#[derive(Default)]
struct AddrTable {
    /// The address to send a peer's traffic to (its first advertised endpoint).
    peer_to_addr: HashMap<PeerId, SocketAddr>,
    /// Reverse map for classifying inbound packets by source address.
    addr_to_peer: HashMap<SocketAddr, PeerId>,
    /// The source address we last received a valid packet from, per peer.
    ///
    /// A peer advertises several endpoints (LAN, WAN, STUN-reflexive), and only
    /// one of them is actually reachable from here. Sending to the *first*
    /// advertised endpoint often picks an unreachable one (e.g. the peer's WAN
    /// address, which does not hairpin on the local router). So, like
    /// magicsock's best-endpoint selection, we learn the working address from
    /// the source of packets the peer actually reaches us on (disco or
    /// WireGuard) and prefer it for our outbound traffic.
    learned: HashMap<PeerId, SocketAddr>,
}

impl AddrTable {
    fn rebuild(&mut self, state: &PeerState) {
        self.peer_to_addr.clear();
        self.addr_to_peer.clear();
        // `learned` is intentionally preserved across netmap updates: a working
        // path stays valid until we hear otherwise.

        for (id, node) in state.peers.peers() {
            for &addr in &node.underlay_addresses {
                self.addr_to_peer.insert(addr, *id);
                self.peer_to_addr.entry(*id).or_insert(addr);
            }
        }
    }

    /// The address to send a peer's traffic to: the learned working address if
    /// we have one, else its first advertised endpoint.
    fn send_addr(&self, peer: PeerId) -> Option<SocketAddr> {
        self.learned
            .get(&peer)
            .or_else(|| self.peer_to_addr.get(&peer))
            .copied()
    }

    /// Record the source address a peer reached us on as its working address.
    fn record_recv(&mut self, peer: PeerId, src: SocketAddr) {
        self.learned.insert(peer, src);
    }
}

/// Actor owning the UDP socket, the underlay transport, and its pumps.
pub struct UdpUnderlay {
    table: Arc<RwLock<AddrTable>>,
    ping_targets: crate::disco::PingTargets,
}

impl kameo::Actor for UdpUnderlay {
    type Args = (Env, ActorRef<DataplaneActor>, SharedDirect);
    type Error = crate::Error;

    async fn on_start(
        (env, dataplane, direct): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        let table = Arc::new(RwLock::new(AddrTable::default()));
        let ping_targets = crate::disco::PingTargets::default();

        let Some(port) = configured_port() else {
            tracing::trace!("udp transport disabled");
            return Ok(Self {
                table,
                ping_targets,
            });
        };

        // Panicking in on_start is fine, this is checked as part of Runtime::spawn.
        let socket = Arc::new(
            UdpSocket::bind(("0.0.0.0", port))
                .await
                .expect("binding udp socket"),
        );

        let (disco_tx, disco_rx) = mpsc::unbounded_channel();

        if !transport_enabled() {
            tracing::info!(port, "udp socket listening (observe only)");
            // Observe-only: log disco packets but never reply.
            spawn_disco_observer(disco_rx, env.shutdown.clone());
            spawn_observe_only(socket, disco_tx, env.shutdown.clone());
            return Ok(Self {
                table,
                ping_targets,
            });
        }

        // Transport mode: reply to disco pings and actively ping peers so a direct
        // path can be established in both directions.
        crate::disco::spawn(
            disco_rx,
            socket.clone(),
            env.keys.disco_keys.private.clone(),
            env.keys.node_keys.public,
            ping_targets.clone(),
            env.shutdown.clone(),
        );

        env.subscribe::<Arc<PeerState>>(&slf).await?;

        let (transport_id, from_dataplane, to_dataplane) = dataplane
            .ask(crate::dataplane::NewUnderlayTransport)
            .await?;
        tracing::info!(port, ?transport_id, "udp underlay transport listening");
        direct.write().unwrap().udp_transport_id = Some(transport_id);

        let transport = Arc::new(UdpTransport {
            socket,
            disco_tx,
            table: table.clone(),
            direct: direct.clone(),
        });

        spawn_recv_pump(
            transport.clone(),
            to_dataplane,
            table.clone(),
            direct.clone(),
            env.shutdown.clone(),
        );
        spawn_send_pump(
            transport,
            from_dataplane,
            table.clone(),
            env.shutdown.clone(),
        );

        Ok(Self {
            table,
            ping_targets,
        })
    }
}

impl kameo::message::Message<Arc<PeerState>> for UdpUnderlay {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<PeerState>,
        _ctx: &mut kameo::message::Context<Self, Self::Reply>,
    ) {
        self.table.write().unwrap().rebuild(&msg);

        // Rebuild the set of peers to actively ping: those with both a disco key
        // and at least one advertised endpoint.
        let targets = msg
            .peers
            .peers()
            .iter()
            .filter_map(|(id, node)| {
                let disco = node.disco_key?;
                if node.underlay_addresses.is_empty() {
                    return None;
                }
                Some((
                    *id,
                    crate::disco::PingTarget {
                        endpoints: node.underlay_addresses.clone(),
                        disco,
                    },
                ))
            })
            .collect();
        *self.ping_targets.write().unwrap() = targets;
    }
}

/// Log siphoned disco packets, rate-limited per (source, kind), preserving the
/// observation behavior of the earlier probe.
fn spawn_disco_observer(
    mut disco_rx: mpsc::UnboundedReceiver<DiscoPacket>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut last_log: HashMap<SocketAddr, Instant> = HashMap::new();
        loop {
            tokio::select! {
                _ = async { drop(shutdown.wait_for(|x| *x).await) } => break,
                pkt = disco_rx.recv() => match pkt {
                    Some((src, buf)) => {
                        let now = Instant::now();
                        let recent = last_log
                            .get(&src)
                            .is_some_and(|t| now.duration_since(*t) < LOG_INTERVAL);
                        if !recent {
                            if last_log.len() >= 1024 {
                                last_log.clear();
                            }
                            last_log.insert(src, now);
                            tracing::info!(%src, len = buf.len(), "disco packet received");
                        }
                    }
                    None => break,
                },
            }
        }
    });
}

/// In observe-only mode, drain the socket and classify without a transport.
fn spawn_observe_only(
    socket: Arc<UdpSocket>,
    disco_tx: mpsc::UnboundedSender<DiscoPacket>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            tokio::select! {
                _ = async { drop(shutdown.wait_for(|x| *x).await) } => break,
                recv = socket.recv_from(&mut buf) => match recv {
                    Ok((len, src)) => {
                        if classify(&buf[..len]) == PacketKind::Disco {
                            drop(disco_tx.send((src, buf[..len].to_vec())));
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "udp recv error");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
            }
        }
    });
}

/// Pump packets from the UDP socket to the dataplane, mapping the source address
/// to a [`PeerId`].
fn spawn_recv_pump(
    transport: Arc<UdpTransport>,
    to_dataplane: UnderlayToDataplane,
    table: Arc<RwLock<AddrTable>>,
    direct: SharedDirect,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        loop {
            let batch = tokio::select! {
                _ = async { drop(shutdown.wait_for(|x| *x).await) } => break,
                batch = transport.recv() => batch,
            };

            for item in batch.batch_iter() {
                let (src, pkts) = match item {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "udp recv error");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                let peer_id = table.read().unwrap().addr_to_peer.get(&src).copied();
                let Some(peer_id) = peer_id else {
                    tracing::trace!(%src, "udp packet from unknown source, dropping");
                    continue;
                };

                // Receiving real traffic direct from this peer means the direct
                // path is live: mark it so we route our outbound to it over UDP too.
                direct
                    .write()
                    .unwrap()
                    .last_recv
                    .insert(peer_id, Instant::now());

                // Learn the address the peer actually reaches us on, so our
                // outbound goes back over the same working path.
                table.write().unwrap().record_recv(peer_id, src);

                if to_dataplane
                    .send((peer_id, pkts.into_iter().collect()))
                    .is_err()
                {
                    tracing::warn!("dataplane receive channel closed");
                    return;
                }
            }
        }
    });
}

/// Pump packets from the dataplane to the UDP socket, mapping the [`PeerId`] to
/// the peer's advertised address.
fn spawn_send_pump(
    transport: Arc<UdpTransport>,
    mut from_dataplane: UnderlayFromDataplane,
    table: Arc<RwLock<AddrTable>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        loop {
            let item = tokio::select! {
                _ = async { drop(shutdown.wait_for(|x| *x).await) } => break,
                item = from_dataplane.recv() => item,
            };

            let Some((peer_id, pkts)) = item else {
                tracing::warn!("udp send queue closed");
                break;
            };

            let addr = table.read().unwrap().send_addr(peer_id);
            let Some(addr) = addr else {
                tracing::trace!(?peer_id, "no udp address for peer, dropping");
                continue;
            };

            if let Err(e) = transport.send([(addr, pkts)]).await {
                tracing::warn!(error = %e, %addr, "udp send error");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_kinds() {
        let mut disco = b"TS\xf0\x9f\x92\xac".to_vec();
        disco.extend_from_slice(&[0u8; 32 + 24]);
        assert_eq!(classify(&disco), PacketKind::Disco);

        let mut stun = vec![0u8; 20];
        stun[1] = 0x01;
        stun[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(classify(&stun), PacketKind::Stun);

        let mut wg = vec![0u8; 148];
        wg[0] = 1;
        assert_eq!(classify(&wg), PacketKind::WireguardLike);

        assert_eq!(classify(&[0xff, 0x00, 0x12]), PacketKind::Unknown);
    }
}
