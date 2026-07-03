use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use std::sync::Arc;

use futures::StreamExt;
use kameo::{
    actor::{ActorRef, Spawn},
    message::{Context, StreamMessage},
    prelude::Message,
    reply::DelegatedReply,
};
use tokio::sync::watch;
use ts_control::{
    AsyncControlClient, Endpoint, EndpointType, Error as ControlError, Node, StateUpdate,
};

use crate::{
    derp_latency::{DerpLatencyMeasurement, DerpLatencyMeasurer},
    stunner::StunAddress,
};

/// Actor responsible for maintaining the connection to control.
///
/// This actor is responsible for proxying the map response stream onto the message bus.
pub struct ControlRunner {
    client: AsyncControlClient,
    params: Params,

    self_node: watch::Sender<Option<Node>>,

    /// Endpoint advertisement state; `None` when advertisement is disabled.
    advertise: Option<AdvertiseState>,
}

/// Control runner args.
pub struct Params {
    /// Control config.
    pub(crate) config: ts_control::Config,

    /// Auth key (if needed).
    pub(crate) auth_key: Option<String>,

    /// The [`crate::Env`] for this actor.
    pub(crate) env: crate::Env,
}

#[doc(hidden)]
#[derive(Debug, Clone, thiserror::Error)]
pub enum ControlRunnerError {
    #[error(transparent)]
    Control(#[from] ControlError),

    #[error(transparent)]
    Crate(#[from] crate::Error),
}

impl kameo::Actor for ControlRunner {
    type Args = Params;
    type Error = ControlRunnerError;

    async fn on_start(params: Params, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        loop {
            match AsyncControlClient::check_auth(
                &params.config,
                &params.env.keys,
                params.auth_key.as_deref(),
            )
            .await
            {
                Ok(()) => break,
                Err(ControlError::MachineNotAuthorized(u)) => {
                    tracing::info!(auth_url = %u, "please authorize this machine or pass an auth key");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Err(e) => return Err(e.into()),
            }
        }

        let (mut client, stream) = AsyncControlClient::connect(
            &params.config,
            &params.env.keys,
            params.auth_key.as_deref(),
        )
        .await?;

        params.env.subscribe::<DerpLatencyMeasurement>(&slf).await?;
        DerpLatencyMeasurer::supervise(&slf, params.env.clone())
            .spawn()
            .await;

        let mut advertise = AdvertiseState::from_env();
        if let Some(adv) = &mut advertise {
            params.env.subscribe::<StunAddress>(&slf).await?;
            tracing::info!(
                static_endpoints = ?adv.static_endpoints,
                stun_port = ?adv.stun_port,
                "endpoint advertisement enabled"
            );

            // Advertise any statically-configured endpoints right away; the
            // STUN-derived one follows once the first measurement arrives.
            let endpoints = adv.compose(None);
            if !endpoints.is_empty() {
                client.set_endpoints(endpoints.clone()).await;
                adv.last_sent = endpoints;
            }
        }

        slf.attach_stream(stream.boxed(), (), ());

        Ok(Self {
            client,
            params,
            self_node: Default::default(),
            advertise,
        })
    }
}

/// State for advertising this node's magicsock UDP endpoints to control.
///
/// Direct connections aren't implemented yet, but advertising endpoints (and
/// observing the disco pings that peers then send; see [`crate::udp_transport`])
/// validates the groundwork for them.
struct AdvertiseState {
    /// Endpoints from `TS_RS_ADVERTISE_ENDPOINT`, always advertised. Useful
    /// when the node sits behind a port-forwarded router and its public
    /// endpoint is known and fixed.
    static_endpoints: Vec<SocketAddr>,

    /// Port to combine with STUN-discovered public addresses; `None` when no
    /// local UDP socket is bound (i.e. the probe is disabled), in which case
    /// STUN results are not advertised.
    stun_port: Option<u16>,

    /// The most recently advertised endpoint set, to suppress resends.
    last_sent: Vec<Endpoint>,
}

impl AdvertiseState {
    /// Build from `TS_RS_ADVERTISE_ENDPOINT` (a comma-separated `ip:port`
    /// list) and the UDP probe configuration. Returns `None` when neither is
    /// configured, which disables endpoint advertisement entirely and leaves
    /// upstream behavior unchanged.
    fn from_env() -> Option<Self> {
        let raw = std::env::var("TS_RS_ADVERTISE_ENDPOINT").ok();
        let static_endpoints = Self::parse_static(raw.as_deref().unwrap_or_default());
        let stun_port = crate::udp_transport::configured_port();

        if static_endpoints.is_empty() && stun_port.is_none() {
            return None;
        }

        Some(Self {
            static_endpoints,
            stun_port,
            last_sent: Vec::new(),
        })
    }

    /// Parse a comma-separated `ip:port` list, warning on (and skipping) any
    /// entry that doesn't parse.
    fn parse_static(raw: &str) -> Vec<SocketAddr> {
        raw.split(',')
            .filter_map(|part| {
                let part = part.trim();
                if part.is_empty() {
                    return None;
                }

                match part.parse() {
                    Ok(sa) => Some(sa),
                    Err(e) => {
                        tracing::warn!(
                            endpoint = %part,
                            error = %e,
                            "ignoring unparseable TS_RS_ADVERTISE_ENDPOINT entry"
                        );
                        None
                    }
                }
            })
            .collect()
    }

    /// Compose the endpoint set to advertise given the latest STUN-discovered
    /// public address, deduplicating while preserving order.
    fn compose(&self, stun_addr: Option<IpAddr>) -> Vec<Endpoint> {
        let mut out: Vec<Endpoint> = self
            .static_endpoints
            .iter()
            .map(|&endpoint| Endpoint {
                endpoint,
                ty: EndpointType::ExplicitConf,
            })
            .collect();

        if let (Some(addr), Some(port)) = (stun_addr, self.stun_port) {
            let endpoint = SocketAddr::new(addr, port);
            if !out.iter().any(|e| e.endpoint == endpoint) {
                out.push(Endpoint {
                    endpoint,
                    ty: EndpointType::Stun,
                });
            }
        }

        out
    }
}

impl Message<StunAddress> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: StunAddress, _ctx: &mut Context<Self, Self::Reply>) {
        let Some(advertise) = &mut self.advertise else {
            return;
        };

        let endpoints = advertise.compose(Some(msg.addr));
        if endpoints.is_empty() || endpoints == advertise.last_sent {
            return;
        }

        tracing::info!(?endpoints, "advertising updated endpoints to control");
        self.client.set_endpoints(endpoints.clone()).await;
        advertise.last_sent = endpoints;
    }
}

impl ControlRunner {
    fn with_self_node<F, R>(&self, f: F) -> impl Future<Output = Option<R>> + use<F, R>
    where
        F: FnOnce(&Node) -> R,
    {
        let mut sub = self.self_node.subscribe();
        let mut shutdown = self.params.env.shutdown.clone();

        async move {
            tokio::select! {
                _ = shutdown.wait_for(|x| *x) => {
                    None
                },
                node = sub.wait_for(Option::is_some) => {
                    Some(f(node.ok()?.as_ref()?))
                },
            }
        }
    }
}

#[kameo::messages]
impl ControlRunner {
    /// Fetch the IPv4 address for this tailscale device.
    #[message(ctx)]
    pub fn ipv4(
        &self,
        ctx: &mut Context<Self, DelegatedReply<Option<Ipv4Addr>>>,
    ) -> DelegatedReply<Option<Ipv4Addr>> {
        let (deleg, replier) = ctx.reply_sender();

        if let Some(replier) = replier {
            let fut = self.with_self_node(|node| node.tailnet_address.ipv4.addr());

            tokio::spawn(async move {
                let ip = fut.await;
                replier.send(ip);
            });
        }

        deleg
    }

    /// Fetch the IPv6 address for this tailscale device.
    #[message(ctx)]
    pub fn ipv6(
        &self,
        ctx: &mut Context<Self, DelegatedReply<Option<Ipv6Addr>>>,
    ) -> DelegatedReply<Option<Ipv6Addr>> {
        let (deleg, replier) = ctx.reply_sender();

        if let Some(replier) = replier {
            let fut = self.with_self_node(|node| node.tailnet_address.ipv6.addr());

            tokio::spawn(async move {
                let ip = fut.await;
                replier.send(ip);
            });
        }

        deleg
    }

    /// Fetch the self node for this tailscale device.
    #[message(ctx)]
    pub fn self_node(
        &self,
        ctx: &mut Context<Self, DelegatedReply<Option<Node>>>,
    ) -> DelegatedReply<Option<Node>> {
        let (deleg, replier) = ctx.reply_sender();

        if let Some(replier) = replier {
            let node = self.with_self_node(|node| node.clone());

            tokio::spawn(async move {
                let node = node.await;
                replier.send(node)
            });
        }

        deleg
    }
}

impl Message<StreamMessage<Arc<StateUpdate>, (), ()>> for ControlRunner {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<Arc<StateUpdate>, (), ()>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        match msg {
            StreamMessage::Started(_) => {
                tracing::trace!("started listening to state updates");
            }

            StreamMessage::Next(msg) => {
                if let Some(node) = msg.node.as_ref() {
                    self.self_node.send_replace(Some(node.clone()));
                }

                if let Err(e) = self.params.env.publish(msg).await {
                    tracing::error!(error = %e, "publishing netmap update");
                }
            }

            StreamMessage::Finished(_) => {
                tracing::error!("state update stream terminated")
            }
        }
    }
}

impl Message<DerpLatencyMeasurement> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: DerpLatencyMeasurement, _ctx: &mut Context<Self, Self::Reply>) {
        let measurements = msg.measurement.as_ref().clone();

        // Optionally pin the home DERP region unconditionally. On the Wii,
        // netcheck measures latency via a TLS handshake, which is extremely
        // jittery on the slow CPU: the measurement terminates early (after a
        // few regions respond), so the nearest region (Tokyo) is often absent
        // from the results and latency-based selection drifts to a far or
        // poorly-reachable region — which can even leave the node unreachable.
        // When TS_RS_HOME_REGION is set we force that region regardless of the
        // measurement (the region must exist in the control-provided DERP map).
        let pinned = std::env::var("TS_RS_HOME_REGION")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .and_then(std::num::NonZeroU32::new)
            .map(ts_derp::RegionId);

        let region_id = match pinned {
            Some(id) => id,
            None => match measurements.first() {
                Some(result) => result.id,
                None => {
                    tracing::debug!("derp latency measurements empty");
                    return;
                }
            },
        };

        let iter = measurements.iter().map(|result| {
            (
                result.latency_map_key.as_str(),
                result.latency.as_secs_f64(),
            )
        });

        tracing::debug!(selected_region_id = ?region_id, ?pinned, "updating home region");

        self.client.set_home_region(region_id, iter).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_static_endpoints() {
        assert_eq!(AdvertiseState::parse_static(""), vec![]);
        assert_eq!(
            AdvertiseState::parse_static("203.0.113.5:41641, [2001:db8::1]:22,bogus"),
            vec![
                "203.0.113.5:41641".parse::<SocketAddr>().unwrap(),
                "[2001:db8::1]:22".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn compose_endpoints() {
        let state = AdvertiseState {
            static_endpoints: vec!["203.0.113.5:41641".parse().unwrap()],
            stun_port: Some(41641),
            last_sent: Vec::new(),
        };

        // Static only.
        assert_eq!(
            state.compose(None),
            vec![Endpoint {
                endpoint: "203.0.113.5:41641".parse().unwrap(),
                ty: EndpointType::ExplicitConf,
            }]
        );

        // Static + STUN-discovered address.
        assert_eq!(
            state.compose(Some("198.51.100.7".parse().unwrap())),
            vec![
                Endpoint {
                    endpoint: "203.0.113.5:41641".parse().unwrap(),
                    ty: EndpointType::ExplicitConf,
                },
                Endpoint {
                    endpoint: "198.51.100.7:41641".parse().unwrap(),
                    ty: EndpointType::Stun,
                },
            ]
        );

        // A STUN address equal to a static endpoint is deduplicated.
        assert_eq!(state.compose(Some("203.0.113.5".parse().unwrap())).len(), 1);

        // No STUN port bound: STUN results are not advertised.
        let no_probe = AdvertiseState {
            stun_port: None,
            ..state
        };
        assert_eq!(
            no_probe
                .compose(Some("198.51.100.7".parse().unwrap()))
                .len(),
            1
        );
    }
}
