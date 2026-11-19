use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use concord_common::addr::unmap;
use concord_common::sync;
use concord_common::{
    Address, BoxStream, FlowHandler, FlowMeta, InboundInfo, InboundKind, Network, UdpFlow,
    UdpPayload, UdpReply,
};

use crate::spec::Policy;
use crate::udp::Associations;

struct Unset;

impl FlowHandler for Unset {
    fn handle_tcp(&self, _meta: FlowMeta, _stream: BoxStream) {}

    fn handle_udp(&self, _flow: UdpFlow<'_>, _payload: UdpPayload<'_>, _reply: &Arc<dyn UdpReply>) {
    }
}

/// What every listener of one `Listeners` reads at accept time.
/// Bounds the first byte, a SOCKS handshake and an HTTP request head that has not yet been
/// served, so idle clients on an `allow-lan` port cannot hold descriptors.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) struct Shared {
    handler: RwLock<Arc<dyn FlowHandler>>,
    policy: RwLock<Arc<Policy>>,
}

impl Shared {
    pub(crate) fn new(policy: Policy) -> Self {
        Shared {
            handler: RwLock::new(Arc::new(Unset)),
            policy: RwLock::new(Arc::new(policy)),
        }
    }

    pub(crate) fn update(&self, handler: Arc<dyn FlowHandler>, policy: Policy) {
        *sync::write(&self.handler) = handler;
        *sync::write(&self.policy) = Arc::new(policy);
    }

    pub(crate) fn handler(&self) -> Arc<dyn FlowHandler> {
        sync::read(&self.handler).clone()
    }

    pub(crate) fn policy(&self) -> Arc<Policy> {
        sync::read(&self.policy).clone()
    }
}

/// One listener's view: its inbound name (`in-name`) and the UDP associations
/// its SOCKS5 control connections open.
pub(crate) struct ListenCtx {
    pub(crate) shared: Arc<Shared>,
    pub(crate) name: Arc<str>,
    pub(crate) assoc: Arc<Associations>,
}

/// Who a proxy client proved to be: the user it named, or the host itself, which names none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Client {
    pub(crate) user: Option<Arc<str>>,
    pub(crate) host: bool,
}

impl Client {
    pub(crate) fn named(user: &str) -> Self {
        Client {
            user: user_of(user),
            host: false,
        }
    }

    pub(crate) fn host() -> Self {
        Client {
            user: None,
            host: true,
        }
    }
}

/// Both ends of an accepted connection with IPv4-mapped addresses unmapped.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Peer {
    pub(crate) src: SocketAddr,
    pub(crate) local: SocketAddr,
}

pub(crate) fn unmap_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(unmap(addr.ip()), addr.port())
}

impl ListenCtx {
    pub(crate) fn tcp_meta(
        &self,
        kind: InboundKind,
        peer: &Peer,
        dst: Address,
        client: Client,
    ) -> FlowMeta {
        FlowMeta {
            dscp: 0,
            network: Network::Tcp,
            inbound: InboundInfo {
                kind,
                name: self.name.clone(),
                addr: Some(peer.local),
                user: client.user,
                host: client.host,
                user_agent: None,
            },
            src: peer.src,
            dst,
        }
    }

    pub(crate) fn hand_off(&self, meta: FlowMeta, stream: BoxStream) {
        self.shared.handler().handle_tcp(meta, stream);
    }
}

/// A trailing dot is trimmed from a name as the Go inbound does (`#737`).
pub(crate) fn dst_address(host: &str, port: u16) -> Address {
    Address::new(host.trim_end_matches('.'), port)
}

pub(crate) fn user_of(user: &str) -> Option<Arc<str>> {
    (!user.is_empty()).then(|| Arc::from(user))
}
