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
use ts_transport::{BatchRecvIter, BatchSendIter, PeerId, UnderlayTransport};

use crate::{
    dataplane::{DataplaneActor, UnderlayFromDataplane, UnderlayToDataplane},
    env::Env,
    peer_tracker::PeerState,
};

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
}

impl AddrTable {
    fn rebuild(&mut self, state: &PeerState) {
        self.peer_to_addr.clear();
        self.addr_to_peer.clear();

        for (id, node) in state.peers.peers() {
            for &addr in &node.underlay_addresses {
                self.addr_to_peer.insert(addr, *id);
                self.peer_to_addr.entry(*id).or_insert(addr);
            }
        }
    }
}

/// Actor owning the UDP socket, the underlay transport, and its pumps.
pub struct UdpUnderlay {
    table: Arc<RwLock<AddrTable>>,
}

impl kameo::Actor for UdpUnderlay {
    type Args = (Env, ActorRef<DataplaneActor>);
    type Error = crate::Error;

    async fn on_start(
        (env, dataplane): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        let table = Arc::new(RwLock::new(AddrTable::default()));

        let Some(port) = configured_port() else {
            tracing::trace!("udp transport disabled");
            return Ok(Self { table });
        };

        // Panicking in on_start is fine, this is checked as part of Runtime::spawn.
        let socket = Arc::new(
            UdpSocket::bind(("0.0.0.0", port))
                .await
                .expect("binding udp socket"),
        );

        let (disco_tx, disco_rx) = mpsc::unbounded_channel();
        spawn_disco_observer(disco_rx, env.shutdown.clone());

        if !transport_enabled() {
            tracing::info!(port, "udp socket listening (observe only)");
            // Drain the socket so the observer sees traffic; no transport.
            spawn_observe_only(socket, disco_tx, env.shutdown.clone());
            return Ok(Self { table });
        }

        env.subscribe::<Arc<PeerState>>(&slf).await?;

        let (transport_id, from_dataplane, to_dataplane) = dataplane
            .ask(crate::dataplane::NewUnderlayTransport)
            .await?;
        tracing::info!(port, ?transport_id, "udp underlay transport listening");

        let transport = Arc::new(UdpTransport { socket, disco_tx });

        spawn_recv_pump(
            transport.clone(),
            to_dataplane,
            table.clone(),
            env.shutdown.clone(),
        );
        spawn_send_pump(
            transport,
            from_dataplane,
            table.clone(),
            env.shutdown.clone(),
        );

        Ok(Self { table })
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

            let addr = table.read().unwrap().peer_to_addr.get(&peer_id).copied();
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
