//! Expose local TCP services on the tailnet.
//!
//! `tailscale-rs` is an embedded (tsnet-style) library: the node joins the tailnet
//! but there is no system TUN device, so the host's own listeners (sshd, etc.) are
//! not automatically reachable over Tailscale. This example bridges that gap: it
//! listens on the node's tailnet IP and forwards each accepted connection to a
//! local (loopback) address.
//!
//! Primary use case: make a headless box (e.g. a Wii running Linux) reachable over
//! the tailnet for SSH without needing a kernel WireGuard / TUN device.
//!
//! Example: forward tailnet :22 to the local sshd, and tailnet :8080 to a local web
//! server:
//!
//!     TS_RS_EXPERIMENT=this_is_unstable_software \
//!     TS_AUTH_KEY=tskey-auth-... \
//!         wii_forward -f 22:127.0.0.1:22 -f 8080:127.0.0.1:80

use std::{error::Error, net::SocketAddr, path::PathBuf};

use clap::Parser;
use tailscale::{Config, Device};
use tokio::{net::TcpStream, task::spawn};
use tracing_subscriber::filter::LevelFilter;

/// A single `TAILNET_PORT:LOCAL_IP:LOCAL_PORT` forwarding rule.
#[derive(Clone, Debug)]
struct Forward {
    /// Port to listen on, on the node's tailnet IPv4 address.
    tailnet_port: u16,
    /// Local address to forward accepted connections to.
    local: SocketAddr,
}

/// Parse a `TAILNET_PORT:LOCAL_IP:LOCAL_PORT` rule (e.g. `22:127.0.0.1:22`).
fn parse_forward(s: &str) -> Result<Forward, String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        return Err(format!(
            "expected TAILNET_PORT:LOCAL_IP:LOCAL_PORT, got {s:?}"
        ));
    }
    let tailnet_port = parts[0]
        .parse::<u16>()
        .map_err(|e| format!("bad tailnet port {:?}: {e}", parts[0]))?;
    let local_ip = parts[1]
        .parse::<std::net::IpAddr>()
        .map_err(|e| format!("bad local IP {:?}: {e}", parts[1]))?;
    let local_port = parts[2]
        .parse::<u16>()
        .map_err(|e| format!("bad local port {:?}: {e}", parts[2]))?;
    Ok(Forward {
        tailnet_port,
        local: SocketAddr::new(local_ip, local_port),
    })
}

/// Expose local TCP services on the tailnet by forwarding tailnet connections to
/// loopback addresses.
#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// Path to a key file to use. Will be created if it doesn't exist.
    #[arg(short = 'c', long, default_value = "tsrs_keys.json")]
    key_file: PathBuf,

    /// The auth key to connect with.
    ///
    /// Can be omitted if the key file is already authenticated.
    #[arg(short = 'k', long, env = "TS_AUTH_KEY")]
    auth_key: Option<String>,

    /// The hostname this node will request.
    #[arg(short = 'H', long, default_value = "wii")]
    hostname: Option<String>,

    /// The URL of the control server to connect to.
    ///
    /// Uses the Tailscale control server by default if unspecified.
    #[arg(long, env = "TS_CONTROL_URL")]
    control_url: Option<url::Url>,

    /// Forwarding rule `TAILNET_PORT:LOCAL_IP:LOCAL_PORT`. May be repeated.
    ///
    /// Defaults to `22:127.0.0.1:22` (expose local SSH on the tailnet).
    #[arg(short = 'f', long = "forward", value_parser = parse_forward)]
    forwards: Vec<Forward>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();

    let forwards = if args.forwards.is_empty() {
        vec![parse_forward("22:127.0.0.1:22").expect("valid default rule")]
    } else {
        args.forwards
    };

    let mut config = Config::default_with_key_file(&args.key_file).await?;
    config.requested_hostname = args.hostname;
    if let Some(url) = args.control_url {
        config.control_server_url = url;
    }

    let dev = Device::new(&config, args.auth_key).await?;
    let tailnet_ip = dev.ipv4_addr().await?;
    tracing::info!(%tailnet_ip, "joined tailnet");

    let mut listeners = Vec::new();
    for fwd in forwards {
        let listen_addr: SocketAddr = (tailnet_ip, fwd.tailnet_port).into();
        let listener = dev.tcp_listen(listen_addr).await?;
        tracing::info!(%listen_addr, local = %fwd.local, "forwarding");
        listeners.push(spawn(run_forward(listener, fwd.local)));
    }

    // Run until any listener task ends (which only happens on a fatal accept error).
    for l in listeners {
        if let Err(e) = l.await {
            tracing::error!(error = %e, "listener task failed");
        }
    }
    Ok(())
}

/// Accept tailnet connections on `listener` and splice each to `local`.
async fn run_forward(
    listener: tailscale::netstack::TcpListener,
    local: SocketAddr,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        let mut conn = listener.accept().await?;
        let remote = conn.remote_addr();
        spawn(async move {
            tracing::info!(%remote, %local, "accepted; dialing local service");
            match TcpStream::connect(local).await {
                Ok(mut local_conn) => {
                    match tokio::io::copy_bidirectional(&mut conn, &mut local_conn).await {
                        Ok((to_local, to_tailnet)) => {
                            tracing::info!(%remote, to_local, to_tailnet, "connection closed");
                        }
                        Err(e) => tracing::warn!(%remote, error = %e, "forward error"),
                    }
                }
                Err(e) => tracing::error!(%local, error = %e, "failed to reach local service"),
            }
        });
    }
}
