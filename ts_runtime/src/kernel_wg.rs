//! Kernel WireGuard bridge: an alternative dataplane that hands the actual
//! WireGuard crypto to a Linux kernel `wireguard` device instead of running it
//! in userspace (`ts_tunnel`) on top of the smoltcp netstack.
//!
//! # Why
//!
//! On very slow hardware (the Wii: 729 MHz single core) the userspace WG +
//! smoltcp path tops out around ~29 KB/s, while the kernel WireGuard engine
//! reaches multiple MB/s on the same box. But a bare kernel WG device cannot
//! join a tailnet on its own: Tailscale's `magicsock` drops WireGuard
//! handshakes from a source it has not first validated over the *disco*
//! endpoint-discovery protocol.
//!
//! So we keep the whole tailscale-rs control plane — login, netmap, STUN,
//! disco, DERP — running (all of it is lightweight), and replace only the
//! data plane. This module is that replacement: it shovels raw WireGuard UDP
//! payloads between the runtime's underlay transports (the real 41641 socket
//! and the DERP relays) and a kernel `wg0` device over the loopback interface.
//!
//! # Plumbing (per-peer loopback socket)
//!
//! For each peer the bridge binds a loopback UDP socket `L_i` (127.0.0.1:port)
//! and points the kernel device's endpoint for that peer at it
//! (`wg set wg0 peer <pub> endpoint 127.0.0.1:L_i`). Then:
//!
//! * inbound (peer → us): a WG payload arrives on an underlay transport as
//!   `(PeerId, bytes)`; the bridge sends the bytes from `L_i` to the kernel
//!   device's listen port. The kernel treats `L_i` as the peer's endpoint.
//! * outbound (us → peer): the kernel device emits a WG payload to `L_i`; the
//!   bridge reads it there, looks up the peer's currently selected transport
//!   (direct UDP or DERP, from [`crate::route_updater::PeerRouteUpdate`]) and
//!   forwards the bytes out that transport.
//!
//! All crypto stays in the kernel; userspace only does a memcpy and a route
//! lookup per packet. Decrypted L3 traffic surfaces on `wg0` and is handled by
//! the kernel IP stack directly (e.g. the box's real `sshd`), so no netstack or
//! port-forwarding is needed in this mode.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU32, Ordering},
    },
};

use tokio::{net::UdpSocket, process::Command, task::JoinHandle};
use ts_packet::PacketMut;
use ts_transport::{OverlayTransportId, PeerId, UnderlayTransportId};

use crate::{peer_tracker::PeerState, udp_transport::SharedDirect};

/// The kernel device's own listen port, on loopback. Real peers never talk to
/// this port directly — everything reaches it through the per-peer `L_i`
/// sockets — so its exact value only matters for our own loopback traffic.
const WG_LISTEN_PORT: u16 = 51821;

/// Conservative tunnel MTU, matching Tailscale's own default, to stay well
/// under any path MTU on the underlay.
const WG_MTU: u32 = 1280;

/// The CGNAT range Tailscale hands out 100.x addresses from; routed to `wg0` so
/// the kernel sends tailnet-destined traffic through the device.
const TAILNET_CIDR: &str = "100.64.0.0/10";

/// Outbound queue toward one underlay transport (bridge → transport).
type OutboundTx = tokio::sync::mpsc::UnboundedSender<(PeerId, Vec<PacketMut>)>;
/// Inbound queue from all underlay transports (transport → bridge).
type InboundTx = tokio::sync::mpsc::UnboundedSender<(PeerId, Vec<PacketMut>)>;
type InboundRx = tokio::sync::mpsc::UnboundedReceiver<(PeerId, Vec<PacketMut>)>;

/// The interface name to run the kernel-WG bridge on, from `TS_RS_KERNEL_WG`,
/// or `None` to use the normal userspace dataplane.
pub fn configured() -> Option<String> {
    std::env::var("TS_RS_KERNEL_WG")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// A peer's live loopback link to the kernel device.
struct PeerLink {
    /// Bound to `127.0.0.1:L_i`, connected to `127.0.0.1:WG_LISTEN_PORT`.
    sock: Arc<UdpSocket>,
    /// The reader task forwarding kernel output for this peer to its transport.
    reader: JoinHandle<()>,
    /// The peer's WG public key, base64, for `wg set ... peer <pub> remove`.
    pubkey: String,
}

impl Drop for PeerLink {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

struct Shared {
    ifname: String,
    /// Written by transports (inbound WG payloads), read by the inbound task.
    inbound_tx: InboundTx,
    /// Outbound queues, one per registered underlay transport.
    transports: RwLock<HashMap<UnderlayTransportId, OutboundTx>>,
    next_transport: AtomicU32,
    /// Per-peer selected transport, from `PeerRouteUpdate` (direct vs DERP).
    routes: RwLock<HashMap<PeerId, UnderlayTransportId>>,
    /// Fallback transport (the direct UDP one) before routes are published.
    direct: SharedDirect,
    peers: Mutex<HashMap<PeerId, PeerLink>>,
}

impl Shared {
    /// The transport to send a peer's outbound WG payloads over: its published
    /// route if any, else the direct UDP transport.
    fn transport_for(&self, peer: PeerId) -> Option<UnderlayTransportId> {
        self.routes
            .read()
            .unwrap()
            .get(&peer)
            .copied()
            .or_else(|| self.direct.read().unwrap().udp_transport_id())
    }
}

/// The kernel-WG bridge dataplane.
pub struct KernelWg {
    shared: Arc<Shared>,
    _inbound_task: JoinHandle<()>,
}

impl KernelWg {
    /// Bring up the kernel device and start the inbound pump.
    pub async fn new(ifname: String, direct: SharedDirect, key: [u8; 32]) -> Result<Self, String> {
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::unbounded_channel();

        let shared = Arc::new(Shared {
            ifname: ifname.clone(),
            inbound_tx,
            transports: RwLock::new(HashMap::new()),
            next_transport: AtomicU32::new(0),
            routes: RwLock::new(HashMap::new()),
            direct,
            peers: Mutex::new(HashMap::new()),
        });

        init_device(&ifname, &key).await?;

        let inbound_task = tokio::spawn(inbound_pump(shared.clone(), inbound_rx));

        Ok(Self {
            shared,
            _inbound_task: inbound_task,
        })
    }

    /// Allocate an underlay transport, mirroring
    /// [`ts_dataplane::async_tokio::DataPlane::new_underlay_transport`].
    ///
    /// Returns the id, the receiver the transport reads outbound packets from,
    /// and the sender it writes inbound packets to.
    pub fn new_underlay_transport(
        &self,
    ) -> (
        UnderlayTransportId,
        tokio::sync::mpsc::UnboundedReceiver<(PeerId, Vec<PacketMut>)>,
        InboundTx,
    ) {
        let id: UnderlayTransportId = self.shared.next_transport.fetch_add(1, Ordering::Relaxed).into();
        let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
        self.shared.transports.write().unwrap().insert(id, out_tx);
        (id, out_rx, self.shared.inbound_tx.clone())
    }

    /// A dummy overlay transport. Nothing consumes it in kernel mode (there is
    /// no netstack); it exists only so the `RouteUpdater` has an id.
    pub fn new_overlay_transport(
        &self,
    ) -> (
        OverlayTransportId,
        tokio::sync::mpsc::UnboundedSender<Vec<PacketMut>>,
        tokio::sync::mpsc::UnboundedReceiver<Vec<PacketMut>>,
    ) {
        let (up_tx, _up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_down_tx, down_rx) = tokio::sync::mpsc::unbounded_channel();
        (0u32.into(), up_tx, down_rx)
    }

    /// Apply the per-peer transport selection from a `PeerRouteUpdate`.
    pub fn set_routes(&self, routes: HashMap<PeerId, UnderlayTransportId>) {
        *self.shared.routes.write().unwrap() = routes;
    }

    /// Set the device's own tailnet IPv4 address (from the self node).
    pub async fn set_self_addr(&self, addr: Ipv4Addr) {
        let cidr = format!("{addr}/32");
        run(&["ip", "addr", "replace", &cidr, "dev", &self.shared.ifname]).await;
    }

    /// Reconcile the kernel device's peers with a netmap update.
    pub async fn program_peers(&self, state: &PeerState) {
        for id in &state.deletions {
            // Drop the lock before awaiting (the guard is not `Send`).
            let removed = self.shared.peers.lock().unwrap().remove(id);
            if let Some(link) = removed {
                run(&[
                    "wg", "set", &self.shared.ifname, "peer", &link.pubkey, "remove",
                ])
                .await;
            }
        }

        for id in &state.upserts {
            let Some((_, node)) = state.peers.get(id) else {
                continue;
            };
            let pubkey = base64_encode(&node.node_key.to_bytes());

            // Allowed IPs: the peer's own /32 plus any IPv4 subnet routes it
            // advertises. IPv6 is left out — the underlay is v4-only here.
            let mut allowed: Vec<String> = vec![format!("{}/32", node.tailnet_address.ipv4.addr())];
            for route in &node.accepted_routes {
                if route.addr().is_ipv4() {
                    allowed.push(route.to_string());
                }
            }
            let allowed = allowed.join(",");

            let port = self.ensure_link(*id, pubkey.clone()).await;
            let endpoint = format!("127.0.0.1:{port}");

            run(&[
                "wg",
                "set",
                &self.shared.ifname,
                "peer",
                &pubkey,
                "endpoint",
                &endpoint,
                "persistent-keepalive",
                "25",
                "allowed-ips",
                &allowed,
            ])
            .await;
        }

        // Also route each peer's /32 through the device so the kernel sends
        // return traffic over wg0.
        for node in state.peers.peers().values() {
            let cidr = format!("{}/32", node.tailnet_address.ipv4.addr());
            run(&["ip", "route", "replace", &cidr, "dev", &self.shared.ifname]).await;
        }
    }

    /// Ensure a loopback link exists for `peer`, returning its local port.
    async fn ensure_link(&self, peer: PeerId, pubkey: String) -> u16 {
        if let Some(link) = self.shared.peers.lock().unwrap().get(&peer) {
            return link.sock.local_addr().map(|a| a.port()).unwrap_or(0);
        }

        let sock = match bind_loopback().await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                tracing::error!(error = %e, "binding loopback socket for peer");
                return 0;
            }
        };
        let port = sock.local_addr().map(|a| a.port()).unwrap_or(0);

        let reader = tokio::spawn(reader_pump(self.shared.clone(), peer, sock.clone()));

        self.shared
            .peers
            .lock()
            .unwrap()
            .insert(peer, PeerLink { sock, reader, pubkey });

        port
    }
}

/// Forward inbound WG payloads (from any transport) to the kernel device via
/// each peer's loopback socket.
async fn inbound_pump(shared: Arc<Shared>, mut inbound_rx: InboundRx) {
    while let Some((peer, pkts)) = inbound_rx.recv().await {
        let sock = shared.peers.lock().unwrap().get(&peer).map(|l| l.sock.clone());
        let Some(sock) = sock else {
            // No link yet (peer not programmed); the sender will retransmit.
            continue;
        };
        for pkt in pkts {
            if let Err(e) = sock.send(pkt.as_ref()).await {
                tracing::trace!(?peer, error = %e, "forwarding inbound to kernel wg");
            }
        }
    }
}

/// Forward kernel-device output for one peer to its selected transport.
async fn reader_pump(shared: Arc<Shared>, peer: PeerId, sock: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 2048];
    loop {
        let n = match sock.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::trace!(?peer, error = %e, "kernel wg loopback closed");
                return;
            }
        };

        let Some(tid) = shared.transport_for(peer) else {
            continue;
        };
        let tx = shared.transports.read().unwrap().get(&tid).cloned();
        if let Some(tx) = tx {
            let pkt: PacketMut = buf[..n].to_vec().into();
            drop(tx.send((peer, vec![pkt])));
        }
    }
}

/// Bind a loopback UDP socket connected to the kernel device's listen port.
async fn bind_loopback() -> std::io::Result<UdpSocket> {
    let sock = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).await?;
    sock.connect(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        WG_LISTEN_PORT,
    )))
    .await?;
    Ok(sock)
}

/// Create (or reset) the kernel WireGuard device and set its private key.
async fn init_device(ifname: &str, key: &[u8; 32]) -> Result<(), String> {
    // Start from a clean slate so leftover peers from a previous run don't
    // linger (the kernel device survives a userspace restart).
    run(&["ip", "link", "del", "dev", ifname]).await;

    if !run(&["ip", "link", "add", "dev", ifname, "type", "wireguard"]).await {
        return Err(format!("could not create wireguard device {ifname}"));
    }

    // Feed the private key through a 0600 tmpfile so it never appears in argv.
    let key_b64 = base64_encode(key);
    let key_path = format!("/tmp/.tsrs_wg_{ifname}.key");
    if let Err(e) = write_private_key(&key_path, &key_b64) {
        return Err(format!("writing wg key file: {e}"));
    }
    let ok = run(&[
        "wg",
        "set",
        ifname,
        "listen-port",
        &WG_LISTEN_PORT.to_string(),
        "private-key",
        &key_path,
    ])
    .await;
    drop(std::fs::remove_file(&key_path));
    if !ok {
        return Err("could not set wg private key / listen port".to_string());
    }

    run(&["ip", "link", "set", "dev", ifname, "mtu", &WG_MTU.to_string(), "up"]).await;
    run(&["ip", "route", "replace", TAILNET_CIDR, "dev", ifname]).await;

    tracing::info!(ifname, "kernel wireguard device up");
    Ok(())
}

fn write_private_key(path: &str, key_b64: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    writeln!(f, "{key_b64}")
}

/// Run a command, logging failures. Returns whether it exited successfully.
async fn run(args: &[&str]) -> bool {
    match Command::new(args[0]).args(&args[1..]).output().await {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            tracing::debug!(
                cmd = ?args,
                status = ?out.status.code(),
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "command failed"
            );
            false
        }
        Err(e) => {
            tracing::warn!(cmd = ?args, error = %e, "spawning command");
            false
        }
    }
}

/// Standard base64 (with padding), as WireGuard tools expect for keys.
fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64_encode;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        // 32 zero bytes → the canonical all-zero WG key.
        assert_eq!(
            base64_encode(&[0u8; 32]),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }
}
