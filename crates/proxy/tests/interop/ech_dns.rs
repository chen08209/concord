//! A loopback DNS server that serves the ECH HTTPS record, and the real resolver in front of it.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, HostResolver, Initiator, IpVersion, LookupIps, PacketSession, SockOpts,
};
use concord_config::dns::{DnsConfig, parse_upstream};
use concord_config::hosts::HostsConfig;
use concord_dns::{NoRules, Resolver, ResolverDeps, UpstreamDialer};
use concord_net::Sockets;
use concord_platform::NativePlatform;
use concord_tls::TrustStore;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::HTTPS;
use hickory_proto::rr::rdata::svcb::{Alpn, EchConfigList, SVCB, SvcParamKey, SvcParamValue};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

use super::IpOnly;

struct NoTunnel;

#[async_trait]
impl UpstreamDialer for NoTunnel {
    fn knows(&self, _via: &str) -> bool {
        false
    }

    async fn connect(&self, _via: &str, _target: &Address) -> io::Result<BoxStream> {
        Err(io::Error::other("no tunnel"))
    }

    async fn bind_udp(&self, _via: &str, _target: &Address) -> io::Result<Arc<dyn PacketSession>> {
        Err(io::Error::other("no tunnel"))
    }
}

fn answer(request: &Message, list: &[u8], names: &[&str]) -> Message {
    let mut reply = Message::response(request.metadata.id, request.metadata.op_code);
    reply.metadata.message_type = MessageType::Response;
    reply.metadata.recursion_desired = true;
    reply.metadata.recursion_available = true;
    reply.metadata.response_code = ResponseCode::NoError;
    reply.queries.clone_from(&request.queries);
    let Some(query) = request.queries.first() else {
        return reply;
    };
    let served = names.iter().any(|name| {
        query
            .name
            .to_ascii()
            .eq_ignore_ascii_case(&format!("{name}."))
    });
    if query.query_type == RecordType::HTTPS && served {
        let params = vec![
            (
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(vec!["h2".into()])),
            ),
            (
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(list.to_vec())),
            ),
        ];
        reply.answers.push(Record::from_rdata(
            query.name.clone(),
            30,
            RData::HTTPS(HTTPS(SVCB::new(1, Name::root(), params))),
        ));
    }
    reply
}

struct WithDns {
    ips: IpOnly,
    dns: Arc<Resolver>,
}

#[async_trait]
impl HostResolver for WithDns {
    async fn lookup(
        &self,
        host: &str,
        version: IpVersion,
        initiator: Initiator,
    ) -> io::Result<LookupIps> {
        self.ips.lookup(host, version, initiator).await
    }

    async fn resolve_ech(&self, host: &str, initiator: Initiator) -> io::Result<Vec<u8>> {
        self.dns.resolve_ech(host, initiator).await
    }
}

/// `names` get the record; every other name gets an empty NOERROR.
pub(super) async fn start(list: Vec<u8>, names: &'static [&'static str]) -> Arc<dyn HostResolver> {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr: SocketAddr = socket.local_addr().unwrap();
    let served = socket.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, from)) = served.recv_from(&mut buf).await {
            let Ok(request) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let reply = answer(&request, &list, names);
            let _ = served.send_to(&reply.to_vec().unwrap(), from).await;
        }
    });
    let config = DnsConfig {
        enable: true,
        nameserver: vec![parse_upstream(&format!("udp://{addr}")).unwrap()],
        default_nameserver: vec![parse_upstream("127.0.0.1").unwrap()],
        ipv6: true,
        ..DnsConfig::default()
    };
    let platform = Arc::new(NativePlatform::new());
    let dialer: Weak<dyn UpstreamDialer> = Weak::<NoTunnel>::new();
    let dns = Resolver::new(
        &config,
        &HostsConfig::default(),
        ResolverDeps {
            sockets: Arc::new(Sockets::new(platform.clone())),
            trust: TrustStore::new(b"", Vec::new()),
            events: Arc::new(concord_common::NullSink),
            platform,
            rules: Arc::new(NoRules),
            dialer,
            sock_opts: SockOpts::default(),
            ipv6: true,
            store_fake_ip: false,
            tasks: Default::default(),
            scripts: Arc::new(concord_common::scripts::ScriptSlot::default()),
        },
    )
    .unwrap();
    Arc::new(WithDns { ips: IpOnly, dns })
}
