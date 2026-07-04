//! Kernel WireGuard bridge: an alternative dataplane that hands WireGuard
//! crypto to a Linux kernel `wireguard` device instead of running it in
//! userspace (`ts_tunnel` + smoltcp).
//!
//! A bare kernel WG device cannot join a tailnet: magicsock drops handshakes
//! from endpoints it has not validated over disco first. So the tailscale-rs
//! control plane (login, netmap, STUN, disco, DERP) keeps running, and only
//! the packet path is replaced.
//!
//! For each peer the bridge binds a loopback UDP socket `L_i` and sets the
//! kernel device's endpoint for that peer to it:
//!
//! * inbound: `(PeerId, bytes)` from an underlay transport → sent from `L_i`
//!   to the device's listen port; the kernel sees `L_i` as the peer.
//! * outbound: the device emits to `L_i` → forwarded out the peer's currently
//!   selected transport (direct UDP or DERP, per `PeerRouteUpdate`).
//!
//! Crypto stays in the kernel and decrypted L3 surfaces on the device itself,
//! so services (sshd, smbd) answer on the tailnet IP without a netstack or
//! port forwards. Enabled with `TS_RS_KERNEL_WG=<ifname>`.

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

/// The kernel device's listen port on loopback. Only our `L_i` sockets ever
/// talk to it.
const WG_LISTEN_PORT: u16 = 51821;

/// Tunnel MTU, matching Tailscale's default.
const WG_MTU: u32 = 1280;

/// The Tailscale CGNAT range, routed to the device as a whole; individual
/// peer /32s all fall inside it.
const TAILNET_CIDR: &str = "100.64.0.0/10";

type PacketTx = tokio::sync::mpsc::UnboundedSender<(PeerId, Vec<PacketMut>)>;
type PacketRx = tokio::sync::mpsc::UnboundedReceiver<(PeerId, Vec<PacketMut>)>;

/// The interface name from `TS_RS_KERNEL_WG`, or `None` for the normal
/// userspace dataplane.
pub fn configured() -> Option<String> {
    std::env::var("TS_RS_KERNEL_WG")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// A peer's loopback link to the kernel device.
struct PeerLink {
    sock: Arc<UdpSocket>,
    reader: JoinHandle<()>,
    /// Base64 public key, for `wg set ... peer <pub> remove`.
    pubkey: String,
}

impl Drop for PeerLink {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

struct Shared {
    ifname: String,
    inbound_tx: PacketTx,
    /// Outbound queue per registered underlay transport.
    transports: RwLock<HashMap<UnderlayTransportId, PacketTx>>,
    next_transport: AtomicU32,
    /// Per-peer transport selection from `PeerRouteUpdate`.
    routes: RwLock<HashMap<PeerId, UnderlayTransportId>>,
    /// Fallback (direct UDP) before routes are first published.
    direct: SharedDirect,
    peers: Mutex<HashMap<PeerId, PeerLink>>,
}

impl Shared {
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
    pub fn new_underlay_transport(&self) -> (UnderlayTransportId, PacketRx, PacketTx) {
        let id = self
            .shared
            .next_transport
            .fetch_add(1, Ordering::Relaxed)
            .into();
        let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
        self.shared.transports.write().unwrap().insert(id, out_tx);
        (id, out_rx, self.shared.inbound_tx.clone())
    }

    /// A dummy overlay transport; nothing consumes it in kernel mode. It only
    /// exists so the `RouteUpdater` has an id.
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

    pub fn set_routes(&self, routes: HashMap<PeerId, UnderlayTransportId>) {
        *self.shared.routes.write().unwrap() = routes;
    }

    /// Set the device's own tailnet IPv4 address.
    pub async fn set_self_addr(&self, addr: Ipv4Addr) {
        let cidr = format!("{addr}/32");
        run(&["ip", "addr", "replace", &cidr, "dev", &self.shared.ifname]).await;
    }

    /// Reconcile the kernel device's peers with a netmap update.
    pub async fn program_peers(&self, state: &PeerState) {
        for id in &state.deletions {
            // Bind before the await: the guard must not live across it.
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

            // The peer's /32 plus its IPv4 subnet routes; the underlay is
            // v4-only here so IPv6 is skipped.
            let mut allowed = vec![format!("{}/32", node.tailnet_address.ipv4.addr())];
            allowed.extend(
                node.accepted_routes
                    .iter()
                    .filter(|r| r.addr().is_ipv4())
                    .map(|r| r.to_string()),
            );
            let allowed = allowed.join(",");

            let Some(port) = self.ensure_link(*id, pubkey.clone()).await else {
                continue;
            };
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
    }

    /// Ensure a loopback link exists for `peer`, returning its local port.
    async fn ensure_link(&self, peer: PeerId, pubkey: String) -> Option<u16> {
        let existing = self
            .shared
            .peers
            .lock()
            .unwrap()
            .get(&peer)
            .and_then(|l| l.sock.local_addr().ok());
        if let Some(addr) = existing {
            return Some(addr.port());
        }

        let sock = match bind_loopback().await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                tracing::error!(error = %e, "binding loopback socket for peer");
                return None;
            }
        };
        let port = sock.local_addr().ok()?.port();

        let reader = tokio::spawn(reader_pump(self.shared.clone(), peer, sock.clone()));

        self.shared.peers.lock().unwrap().insert(
            peer,
            PeerLink {
                sock,
                reader,
                pubkey,
            },
        );
        Some(port)
    }
}

/// Inbound WG payloads (any transport) → the kernel device.
async fn inbound_pump(shared: Arc<Shared>, mut inbound_rx: PacketRx) {
    while let Some((peer, pkts)) = inbound_rx.recv().await {
        let sock = shared
            .peers
            .lock()
            .unwrap()
            .get(&peer)
            .map(|l| l.sock.clone());
        let Some(sock) = sock else {
            // Peer not programmed yet; the sender will retransmit.
            continue;
        };
        for pkt in pkts {
            if let Err(e) = sock.send(pkt.as_ref()).await {
                tracing::trace!(?peer, error = %e, "forwarding inbound to kernel wg");
            }
        }
    }
}

/// Kernel-device output for one peer → its selected transport.
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

/// Bind a loopback socket connected to the kernel device's listen port.
async fn bind_loopback() -> std::io::Result<UdpSocket> {
    let sock = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).await?;
    sock.connect(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        WG_LISTEN_PORT,
    )))
    .await?;
    Ok(sock)
}

/// Create (or reset) the kernel device and set its private key.
async fn init_device(ifname: &str, key: &[u8; 32]) -> Result<(), String> {
    // Clean slate: the device survives userspace restarts and may hold stale
    // peers.
    run(&["ip", "link", "del", "dev", ifname]).await;

    if !run(&["ip", "link", "add", "dev", ifname, "type", "wireguard"]).await {
        return Err(format!("could not create wireguard device {ifname}"));
    }

    // The key goes through a 0600 tmpfile so it never appears in argv.
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

    let mtu = WG_MTU.to_string();
    run(&["ip", "link", "set", "dev", ifname, "mtu", &mtu, "up"]).await;
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

/// Standard base64 with padding, as WireGuard tools expect.
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
        out.push(if chunk.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
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
        assert_eq!(
            base64_encode(&[0u8; 32]),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }
}
