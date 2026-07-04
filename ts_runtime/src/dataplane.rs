use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use tokio::sync::mpsc;
use ts_packet::PacketMut;
use ts_transport::{OverlayTransportId, PeerId, UnderlayTransportId};

use crate::{
    Error,
    env::Env,
    kernel_wg::KernelWg,
    packetfilter::PacketFilterState,
    peer_tracker::PeerState,
    route_updater::{PeerRouteUpdate, SelfRouteUpdate},
    src_filter::SourceFilterState,
    udp_transport::SharedDirect,
};

/// Queue for packets sent from the overlay to the dataplane.
pub type OverlayToDataplane = mpsc::UnboundedSender<Vec<PacketMut>>;

/// Queue for packets entering the overlay from the dataplane.
pub type OverlayFromDataplane = mpsc::UnboundedReceiver<Vec<PacketMut>>;

/// Queue for packets leaving the underlay to the dataplane.
pub type UnderlayToDataplane = mpsc::UnboundedSender<(PeerId, Vec<PacketMut>)>;

/// Queue for packets entering an underlay from the dataplane.
pub type UnderlayFromDataplane = mpsc::UnboundedReceiver<(PeerId, Vec<PacketMut>)>;

/// The dataplane implementation in use.
///
/// The userspace backend runs WireGuard (`ts_tunnel`) and routes decrypted L3
/// packets to the smoltcp netstack. The kernel backend hands WireGuard to a
/// Linux kernel device and only shuffles raw payloads (see [`crate::kernel_wg`]).
enum Backend {
    Userspace {
        dataplane: Arc<ts_dataplane::async_tokio::DataPlane>,
        task: tokio::task::JoinHandle<()>,
    },
    Kernel(Arc<KernelWg>),
}

pub struct DataplaneActor {
    backend: Backend,
}

impl Drop for DataplaneActor {
    fn drop(&mut self) {
        if let Backend::Userspace { task, .. } = &self.backend {
            task.abort();
        }
    }
}

#[kameo::messages]
impl DataplaneActor {
    #[message]
    pub async fn new_overlay_transport(
        &self,
    ) -> (OverlayTransportId, OverlayToDataplane, OverlayFromDataplane) {
        match &self.backend {
            Backend::Userspace { dataplane, .. } => dataplane.new_overlay_transport().await,
            Backend::Kernel(kernel) => kernel.new_overlay_transport(),
        }
    }

    #[message]
    pub async fn new_underlay_transport(
        &self,
    ) -> (
        UnderlayTransportId,
        UnderlayFromDataplane,
        UnderlayToDataplane,
    ) {
        match &self.backend {
            Backend::Userspace { dataplane, .. } => dataplane.new_underlay_transport().await,
            Backend::Kernel(kernel) => kernel.new_underlay_transport(),
        }
    }
}

impl kameo::Actor for DataplaneActor {
    type Args = (Env, SharedDirect);
    type Error = Error;

    async fn on_start((env, direct): Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<PeerRouteUpdate>(&slf).await?;
        env.subscribe::<SelfRouteUpdate>(&slf).await?;
        env.subscribe::<PacketFilterState>(&slf).await?;
        env.subscribe::<SourceFilterState>(&slf).await?;
        env.subscribe::<Arc<PeerState>>(&slf).await?;

        let backend = if let Some(ifname) = crate::kernel_wg::configured() {
            // Self address programming needs the self node from control.
            env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;

            let key = env.keys.node_keys.private.to_bytes();
            // Bridge bring-up runs `ip`/`wg`; failure here means the runtime is
            // unusable, so fail fast (checked as part of `Runtime::spawn`).
            let kernel = KernelWg::new(ifname, direct, key)
                .await
                .expect("bringing up kernel wireguard bridge");

            tracing::info!("dataplane running (kernel wireguard bridge)");
            Backend::Kernel(Arc::new(kernel))
        } else {
            let dataplane = Arc::new(ts_dataplane::async_tokio::DataPlane::new(
                env.keys.node_keys.clone(),
            ));

            let task_dataplane = dataplane.clone();
            let task = tokio::task::spawn(async move {
                task_dataplane.run().await;
            });

            tracing::trace!("dataplane running");
            Backend::Userspace { dataplane, task }
        };

        Ok(Self { backend })
    }
}

impl Message<PeerRouteUpdate> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: PeerRouteUpdate, _ctx: &mut Context<Self, Self::Reply>) {
        match &self.backend {
            Backend::Userspace { dataplane, .. } => {
                tracing::trace!("applying peer route update");
                let dp = &mut *dataplane.inner().await;
                dp.or_out.swap(msg.inner.overlay_out_routes.clone());
                dp.ur_out.table = msg.inner.underlay_routes.clone();
            }
            Backend::Kernel(kernel) => {
                kernel.set_routes(msg.inner.underlay_routes.clone());
            }
        }
    }
}

impl Message<SelfRouteUpdate> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: SelfRouteUpdate, _ctx: &mut Context<Self, Self::Reply>) {
        if let Backend::Userspace { dataplane, .. } = &self.backend {
            let dp = &mut *dataplane.inner().await;
            dp.or_in.swap(msg.overlay_in_routes.as_ref().clone());
            tracing::trace!("applied self route update");
        }
    }
}

impl Message<PacketFilterState> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: PacketFilterState, _ctx: &mut Context<Self, Self::Reply>) {
        if let Backend::Userspace { dataplane, .. } = &self.backend {
            let dp = &mut *dataplane.inner().await;
            dp.packet_filter = msg.0;
            tracing::trace!("applied new packet filter");
        }
    }
}

impl Message<SourceFilterState> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: SourceFilterState, _ctx: &mut Context<Self, Self::Reply>) {
        if let Backend::Userspace { dataplane, .. } = &self.backend {
            let dp = &mut *dataplane.inner().await;
            dp.src_filter_in = msg.0;
            tracing::trace!("applied new source filter");
        }
    }
}

impl Message<Arc<PeerState>> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        match &self.backend {
            Backend::Userspace { dataplane, .. } => {
                let mut dp = dataplane.inner().await;
                let wg = &mut dp.wireguard;

                for &upsert in &msg.upserts {
                    let (_, node) = msg.peers.get(&upsert).unwrap();
                    wg.upsert_peer(
                        ts_tunnel::PeerId(upsert.0),
                        ts_tunnel::PeerConfig {
                            key: node.node_key,
                            psk: [0u8; 32],
                        },
                    );
                }

                for delete in &msg.deletions {
                    wg.remove_peer(ts_tunnel::PeerId(delete.0));
                }

                tracing::trace!("applied new peer state");
            }
            Backend::Kernel(kernel) => {
                kernel.program_peers(&msg).await;
            }
        }
    }
}

impl Message<Arc<ts_control::StateUpdate>> for DataplaneActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        if let (Backend::Kernel(kernel), Some(node)) = (&self.backend, &msg.node) {
            kernel.set_self_addr(node.tailnet_address.ipv4.addr()).await;
        }
    }
}
