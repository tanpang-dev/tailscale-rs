//! Opt-in UDP probe: bind the node's prospective magicsock UDP port and log
//! classified inbound packets (disco / STUN / WireGuard-like) without replying.
//!
//! Direct connections aren't implemented yet, but once this node advertises
//! UDP endpoints to control (see the endpoint advertisement in
//! [`crate::control_runner`]), peers running full clients start sending disco
//! pings to those endpoints. Observing them here proves the endpoints are
//! reachable before any of the real UDP data path exists.
//!
//! Enabled by setting `TS_RS_UDP_PROBE=1`; the port is `TS_RS_UDP_PORT`
//! (default 41641, the Go client's default magicsock port).

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use kameo::actor::ActorRef;

use crate::env::Env;

/// The default probe port, matching the Go client's default magicsock port.
const DEFAULT_PORT: u16 = 41641;

/// Minimum interval between log lines for the same (source, kind) pair.
const LOG_INTERVAL: Duration = Duration::from_secs(1);

/// The configured probe port: `Some` iff `TS_RS_UDP_PROBE=1`.
///
/// Also used by the endpoint advertisement in [`crate::control_runner`] so
/// that the advertised port always matches the port actually bound here.
pub(crate) fn configured_port() -> Option<u16> {
    if std::env::var("TS_RS_UDP_PROBE").ok()? != "1" {
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

/// Actor owning the probe socket. Does nothing when the probe is not enabled.
pub struct UdpProbe {}

impl kameo::Actor for UdpProbe {
    type Args = Env;
    type Error = crate::Error;

    async fn on_start(env: Env, _slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        let Some(port) = configured_port() else {
            tracing::trace!("udp probe disabled");
            return Ok(Self {});
        };

        // Panicking in on_start is fine, this is checked as part of Runtime::spawn.
        let socket = tokio::net::UdpSocket::bind(("0.0.0.0", port))
            .await
            .expect("binding udp probe socket");
        tracing::info!(port, "udp probe listening");

        let mut shutdown = env.shutdown.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let mut last_log = HashMap::new();

            loop {
                tokio::select! {
                    // Discard the non-Send `watch::Ref` inside the arm so the
                    // spawned future stays `Send`.
                    _ = async { drop(shutdown.wait_for(|x| *x).await) } => break,
                    recv = socket.recv_from(&mut buf) => match recv {
                        Ok((len, src)) => log_packet(&buf[..len], src, &mut last_log),
                        Err(e) => {
                            tracing::warn!(error = %e, "udp probe recv error");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    },
                }
            }
        });

        Ok(Self {})
    }
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

/// Log a received packet, rate-limited per (source, kind).
fn log_packet(
    buf: &[u8],
    src: SocketAddr,
    last_log: &mut HashMap<(SocketAddr, PacketKind), Instant>,
) {
    let kind = classify(buf);
    let now = Instant::now();

    if let Some(prev) = last_log.get(&(src, kind))
        && now.duration_since(*prev) < LOG_INTERVAL
    {
        return;
    }

    // Bound the rate-limit table so a flood of spoofed sources can't grow it
    // without limit.
    if last_log.len() >= 1024 {
        last_log.clear();
    }

    last_log.insert((src, kind), now);
    tracing::info!(%src, len = buf.len(), ?kind, "udp probe received packet");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_kinds() {
        // Disco: magic + 32-byte sender key + 24-byte nonce.
        let mut disco = b"TS\xf0\x9f\x92\xac".to_vec();
        disco.extend_from_slice(&[0u8; 32 + 24]);
        assert_eq!(classify(&disco), PacketKind::Disco);

        // STUN binding request: type 0x0001, magic cookie at bytes 4..8.
        let mut stun = vec![0u8; 20];
        stun[1] = 0x01;
        stun[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(classify(&stun), PacketKind::Stun);

        // WireGuard handshake initiation: type 1 + three reserved zero bytes.
        let mut wg = vec![0u8; 148];
        wg[0] = 1;
        assert_eq!(classify(&wg), PacketKind::WireguardLike);

        assert_eq!(classify(&[0xff, 0x00, 0x12]), PacketKind::Unknown);
    }
}
