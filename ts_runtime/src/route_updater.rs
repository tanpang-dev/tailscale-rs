use std::{collections::HashMap, sync::Arc, time::Duration};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use tokio::time::MissedTickBehavior;
use ts_bart::RoutingTable;
use ts_overlay_router::{
    inbound::RouteAction as InboundRouteAction, outbound::RouteAction as OutboundRouteAction,
};
use ts_transport::{OverlayTransportId, PeerId, UnderlayTransportId};

use crate::{
    Error, env::Env, multiderp, multiderp::Multiderp, peer_tracker::PeerState,
    udp_transport::SharedDirect,
};

/// How often to re-evaluate routes so that direct paths are adopted when they
/// go live and dropped when they go stale, independent of netmap updates.
const REEVAL_INTERVAL: Duration = Duration::from_secs(5);

pub struct RouteUpdater {
    multiderp: ActorRef<Multiderp>,
    default_overlay_transport: OverlayTransportId,
    env: Env,
    /// Live direct-path state, written by the UDP transport.
    direct: SharedDirect,
    /// The most recent peer state, so routes can be recomputed on a timer.
    last_peers: Option<Arc<PeerState>>,
}

/// Timer message that triggers a route re-evaluation.
#[derive(Clone, Copy)]
struct Reeval;

impl kameo::Actor for RouteUpdater {
    type Args = (ActorRef<Multiderp>, Env, OverlayTransportId, SharedDirect);
    type Error = Error;

    async fn on_start(
        (multiderp, env, default_transport, direct): Self::Args,
        actor_ref: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<PeerState>>(&actor_ref).await?;
        env.subscribe::<Arc<ts_control::StateUpdate>>(&actor_ref)
            .await?;

        env.scheduler
            .tell(
                kameo_actors::scheduler::SetInterval::new(
                    actor_ref.downgrade(),
                    REEVAL_INTERVAL,
                    Reeval,
                )
                .set_missed_tick_behaviour(MissedTickBehavior::Skip),
            )
            .await?;

        Ok(Self {
            multiderp,
            default_overlay_transport: default_transport,
            env,
            direct,
            last_peers: None,
        })
    }
}

#[derive(Clone)]
pub struct SelfRouteUpdate {
    pub overlay_in_routes: Arc<ts_bart::Table<InboundRouteAction>>,
}

#[derive(Clone)]
pub struct PeerRouteUpdate {
    pub inner: Arc<PeerRoutesInner>,
}

pub struct PeerRoutesInner {
    pub underlay_routes: HashMap<PeerId, UnderlayTransportId>,
    pub overlay_out_routes: ts_bart::Table<OutboundRouteAction>,
}

impl RouteUpdater {
    /// Recompute and publish peer routes from the latest peer state.
    ///
    /// Each peer's outbound traffic is routed over UDP if its direct path is
    /// currently live (recent inbound UDP), otherwise over its DERP region.
    async fn rebuild(&self, state: &PeerState) {
        tracing::trace!(
            n_peers = state.peers.peers().len(),
            "reconstructing routes for peer update"
        );

        let mut overlay_out = ts_bart::Table::default();
        let mut underlay_out = HashMap::default();

        for (id, peer) in state.peers.peers() {
            let span = tracing::trace_span!(
                "peer_update",
                peer_key = %peer.node_key,
                region = ?peer.derp_region,
                underlay_transport = tracing::field::Empty,
                peer_id = ?id,
            );

            for route in &peer.accepted_routes {
                tracing::trace!(parent: &span, %route, "routes");
                overlay_out.insert(*route, OutboundRouteAction::Wireguard(*id));
            }

            // Prefer a live direct UDP path; fall back to the peer's DERP region.
            let direct = self.direct.read().unwrap().direct_transport(*id);
            if let Some(transport_id) = direct {
                span.record("underlay_transport", tracing::field::debug(transport_id));
                underlay_out.insert(*id, transport_id);
                tracing::trace!(parent: &span, "set direct underlay route");
                continue;
            }

            let Some(region) = peer.derp_region else {
                tracing::trace!(parent: &span, "peer has no derp region");
                continue;
            };

            match self
                .multiderp
                .ask(multiderp::TransportIdForRegion { id: region })
                .await
            {
                Ok(Some(transport_id)) => {
                    span.record("underlay_transport", tracing::field::debug(transport_id));
                    underlay_out.insert(*id, transport_id);
                    tracing::trace!(parent: &span, "set derp underlay route");
                }
                Ok(None) => {
                    tracing::error!(parent: &span, "no region stored in multiderp, no underlay route");
                }
                Err(e) => {
                    tracing::error!(error = %e, "multiderp unavailable");
                }
            }
        }

        if let Err(e) = self
            .env
            .publish(PeerRouteUpdate {
                inner: Arc::new(PeerRoutesInner {
                    underlay_routes: underlay_out,
                    overlay_out_routes: overlay_out,
                }),
            })
            .await
        {
            tracing::error!(error = %e, "publishing peer route update");
        }
    }
}

impl Message<Arc<PeerState>> for RouteUpdater {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        self.rebuild(&msg).await;
        self.last_peers = Some(msg);
    }
}

impl Message<Reeval> for RouteUpdater {
    type Reply = ();

    async fn handle(&mut self, _: Reeval, _ctx: &mut Context<Self, Self::Reply>) {
        if let Some(peers) = self.last_peers.clone() {
            self.rebuild(&peers).await;
        }
    }
}

impl Message<Arc<ts_control::StateUpdate>> for RouteUpdater {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Some(node) = msg.node.as_ref() else {
            return;
        };

        let mut out = ts_bart::Table::default();

        tracing::debug!(accepted_routes = ?node.accepted_routes, "populating accepted routes");

        for &accepted_route in &node.accepted_routes {
            out.insert(
                accepted_route,
                InboundRouteAction::ToOverlay(self.default_overlay_transport),
            );
        }

        if let Err(e) = self
            .env
            .publish(SelfRouteUpdate {
                overlay_in_routes: Arc::new(out),
            })
            .await
        {
            tracing::error!(error = %e, "publishing self route update");
        }
    }
}
