//! Disco responder: answers disco pings received on the UDP socket with pongs.
//!
//! This is the passive half of direct-connection setup. A peer running a full
//! client actively probes our advertised endpoints with disco pings; replying
//! with a pong (echoing the ping's transaction id and reporting the source
//! address we saw) is what tells the peer the path works, so it marks the direct
//! path usable. We don't need to run the active NAT-traversal state machine
//! ourselves — the peer drives that.
//!
//! Disco packets are siphoned off the UDP socket by [`crate::udp_transport`] and
//! delivered here on a channel.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use rand::Rng;
use tokio::{net::UdpSocket, sync::mpsc, sync::watch};
use ts_disco_protocol::{Encrypted, Packet, Ping, Plaintext, Pong};
use ts_keys::{DiscoPrivateKey, DiscoPublicKey, NodePublicKey};
use ts_transport::PeerId;

use crate::udp_transport::DiscoPacket;

/// How often we send disco pings to each peer's endpoints.
///
/// This keeps NAT mappings open and, more importantly, drives the *bidirectional*
/// disco handshake: a full-client peer only commits to sending real traffic over
/// the direct path once it has seen pings from us as well as answered ours.
const PING_INTERVAL: Duration = Duration::from_secs(5);

/// A peer we actively ping to try to open a direct path.
#[derive(Clone)]
pub struct PingTarget {
    /// The peer's advertised UDP endpoints.
    pub endpoints: Vec<SocketAddr>,
    /// The peer's disco public key, to encrypt pings to.
    pub disco: DiscoPublicKey,
}

/// Shared, rebuilt-from-netmap set of peers to ping, keyed by peer id.
pub type PingTargets = Arc<RwLock<HashMap<PeerId, PingTarget>>>;

/// Spawn the disco responder and the active pinger. They run until `shutdown`
/// flips or the channel closes.
pub fn spawn(
    mut rx: mpsc::UnboundedReceiver<DiscoPacket>,
    socket: Arc<UdpSocket>,
    disco_private: DiscoPrivateKey,
    node_public: NodePublicKey,
    targets: PingTargets,
    mut shutdown: watch::Receiver<bool>,
) {
    // Responder: reply to incoming pings.
    {
        let socket = socket.clone();
        let disco_private = disco_private.clone();
        let mut shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = async { drop(shutdown.wait_for(|x| *x).await) } => break,
                    pkt = rx.recv() => match pkt {
                        Some((src, buf)) => handle(src, buf, &socket, &disco_private).await,
                        None => break,
                    },
                }
            }
        });
    }

    // Active pinger: periodically ping each peer's endpoints.
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PING_INTERVAL);
        loop {
            tokio::select! {
                _ = async { drop(shutdown.wait_for(|x| *x).await) } => break,
                _ = ticker.tick() => {
                    send_pings(&socket, &disco_private, node_public, &targets).await;
                }
            }
        }
    });
}

/// Send a disco ping to every endpoint of every known peer.
async fn send_pings(
    socket: &UdpSocket,
    disco_private: &DiscoPrivateKey,
    node_public: NodePublicKey,
    targets: &PingTargets,
) {
    // Snapshot under the lock so we don't hold it across awaits.
    let snapshot: Vec<PingTarget> = targets.read().unwrap().values().cloned().collect();

    for target in snapshot {
        let ping = match build_ping(node_public, target.disco, disco_private) {
            Ok(ping) => ping,
            Err(e) => {
                tracing::warn!(error = %e, "building disco ping");
                continue;
            }
        };

        for endpoint in target.endpoints {
            if let Err(e) = socket.send_to(&ping, endpoint).await {
                tracing::trace!(%endpoint, error = %e, "sending disco ping");
            }
        }
    }
}

/// Build and encrypt a disco ping to `peer_disco`.
fn build_ping(
    node_public: NodePublicKey,
    peer_disco: DiscoPublicKey,
    disco_private: &DiscoPrivateKey,
) -> Result<Vec<u8>, DiscoError> {
    let mut buf = Packet::<Plaintext>::vec_for_message(Ping::size_with_padding(0));

    {
        let pkt = Packet::<Plaintext>::init_from_bytes::<Ping>(&mut buf, |ping: &mut Ping| {
            let mut tx_id = [0u8; 12];
            rand::rng().fill_bytes(&mut tx_id);
            ping.tx_id = tx_id;
            ping.node_key = node_public;
        })?;

        let mut nonce = [0u8; 24];
        rand::rng().fill_bytes(&mut nonce);
        pkt.encrypt_in_place(disco_private, &peer_disco, nonce)?;
    }

    Ok(buf)
}

/// Decrypt a received disco packet and, if it is a ping, reply with a pong.
async fn handle(
    src: SocketAddr,
    buf: Vec<u8>,
    socket: &UdpSocket,
    disco_private: &DiscoPrivateKey,
) {
    let reply = match pong_reply(&buf, src, disco_private) {
        Ok(Some(reply)) => reply,
        Ok(None) => return,
        Err(e) => {
            tracing::debug!(%src, error = %e, "ignoring disco packet");
            return;
        }
    };

    tracing::info!(%src, "disco ping received, replying with pong");
    if let Err(e) = socket.send_to(&reply, src).await {
        tracing::warn!(%src, error = %e, "sending disco pong");
    }
}

/// Errors that can occur while processing a disco packet.
type DiscoError = Box<dyn std::error::Error + Send + Sync>;

/// Decrypt `buf` and, if it is a ping, return the encrypted pong bytes to send
/// back to `src`. Returns `Ok(None)` for a valid disco message that is not a
/// ping (e.g. a pong or call-me-maybe), and `Err` for malformed or
/// undecryptable packets.
fn pong_reply(
    buf: &[u8],
    src: SocketAddr,
    disco_private: &DiscoPrivateKey,
) -> Result<Option<Vec<u8>>, DiscoError> {
    // Decrypt into a scratch copy so the caller's buffer is untouched.
    let mut scratch = buf.to_vec();
    let pkt = Packet::<Encrypted>::from_encrypted_bytes_mut(&mut scratch)?;

    // The peer's disco public key is carried in the packet header; it is both the
    // key we decrypt against and the key we encrypt our reply to.
    let peer_disco = *pkt.sender_pubkey();
    let plaintext = pkt.decrypt_in_place(disco_private)?;

    let Some(ping) = plaintext.as_msg::<Ping>() else {
        return Ok(None);
    };

    // Copy the transaction id out before dropping the borrow of `scratch`.
    let tx_id = ping.tx_id;
    Ok(Some(build_pong(tx_id, src, peer_disco, disco_private)?))
}

/// Build and encrypt a pong echoing `tx_id` and reporting `src` back to
/// the pinging peer.
fn build_pong(
    tx_id: [u8; 12],
    src: SocketAddr,
    peer_disco: DiscoPublicKey,
    disco_private: &DiscoPrivateKey,
) -> Result<Vec<u8>, DiscoError> {
    let mut buf = Packet::<Plaintext>::vec_for_message(Pong::size());

    {
        let pkt = Packet::<Plaintext>::init_from_bytes::<Pong>(&mut buf, |pong| {
            pong.tx_id = tx_id;
            pong.src = src.into();
        })?;

        let mut nonce = [0u8; 24];
        rand::rng().fill_bytes(&mut nonce);

        // Encrypts `buf` in place; afterwards it holds the full encrypted packet.
        pkt.encrypt_in_place(disco_private, &peer_disco, nonce)?;
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ping we generate as a "peer" is answered with a pong that the peer can
    /// decrypt, echoing the transaction id and reporting the source address.
    #[test]
    fn ping_gets_pong() {
        let us = DiscoPrivateKey::random();
        let peer = DiscoPrivateKey::random();
        let src: SocketAddr = "203.0.113.7:41641".parse().unwrap();
        let tx_id = [7u8; 12];

        // Peer builds a ping addressed to us, encrypted to our disco key.
        let mut ping_buf = Packet::<Plaintext>::vec_for_message(Ping::size_with_padding(0));
        {
            let pkt =
                Packet::<Plaintext>::init_from_bytes::<Ping>(&mut ping_buf, |ping: &mut Ping| {
                    ping.tx_id = tx_id;
                })
                .unwrap();
            pkt.encrypt_in_place(&peer, &us.public_key(), [1u8; 24])
                .unwrap();
        }

        // We process it and produce a pong.
        let reply = pong_reply(&ping_buf, src, &us)
            .unwrap()
            .expect("a ping should produce a pong");

        // The peer decrypts our pong and checks the fields.
        let mut reply = reply;
        let pkt = Packet::<Encrypted>::from_encrypted_bytes_mut(&mut reply).unwrap();
        assert_eq!(*pkt.sender_pubkey(), us.public_key());
        let plaintext = pkt.decrypt_in_place(&peer).unwrap();
        let pong = plaintext.as_msg::<Pong>().expect("reply is a pong");
        assert_eq!(pong.tx_id, tx_id);
        assert_eq!(pong.src.socket_addr(), src);
    }

    /// A pong (not a ping) does not trigger a reply.
    #[test]
    fn pong_gets_no_reply() {
        let us = DiscoPrivateKey::random();
        let peer = DiscoPrivateKey::random();
        let src: SocketAddr = "203.0.113.7:41641".parse().unwrap();

        let mut pong_buf = Packet::<Plaintext>::vec_for_message(Pong::size());
        {
            let pkt =
                Packet::<Plaintext>::init_from_bytes::<Pong>(&mut pong_buf, |pong: &mut Pong| {
                    pong.tx_id = [0u8; 12];
                    pong.src = src.into();
                })
                .unwrap();
            pkt.encrypt_in_place(&peer, &us.public_key(), [2u8; 24])
                .unwrap();
        }

        assert!(pong_reply(&pong_buf, src, &us).unwrap().is_none());
    }
}
