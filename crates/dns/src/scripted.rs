use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use concord_common::scripts::{DnsScriptAnswer, ScriptHooks};
use concord_common::sync::lock;
use concord_common::{Initiator, IpVersion, LookupIps};
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use tokio::sync::OnceCell;

use crate::client::ClientRef;
use crate::dialer::{Connector, Cx, Via};
use crate::engine::Resolver;
use crate::msg;
use crate::plain::{PlainClient, Transport};
use crate::resolver::batch_exchange;

/// The `dns` scripts' answers: concurrent queries for one domain share a run, and an answer
/// with a `ttl` is kept that long, as Surge adds it to its cache; any other is not kept.
pub(crate) struct ScriptAnswers {
    hooks: Arc<dyn ScriptHooks>,
    slots: Mutex<HashMap<(Arc<str>, String), Slot>>,
}

enum Slot {
    Running(Arc<OnceCell<DnsScriptAnswer>>),
    Kept(DnsScriptAnswer, Instant),
}

impl ScriptAnswers {
    pub(crate) fn new(hooks: Arc<dyn ScriptHooks>) -> Self {
        ScriptAnswers {
            hooks,
            slots: Mutex::default(),
        }
    }

    pub(crate) async fn answer(&self, script: &Arc<str>, domain: &str) -> DnsScriptAnswer {
        let key = (script.clone(), domain.to_ascii_lowercase());
        let cell = {
            let mut slots = lock(&self.slots);
            let now = Instant::now();
            slots.retain(|_, slot| !matches!(slot, Slot::Kept(_, until) if *until <= now));
            match slots.get(&key) {
                Some(Slot::Kept(answer, _)) => return answer.clone(),
                Some(Slot::Running(cell)) => cell.clone(),
                None => {
                    let cell = Arc::new(OnceCell::new());
                    slots.insert(key.clone(), Slot::Running(cell.clone()));
                    cell
                }
            }
        };
        let answer = cell
            .get_or_init(|| self.hooks.dns(script, domain))
            .await
            .clone();
        let mut slots = lock(&self.slots);
        if matches!(slots.get(&key), Some(Slot::Running(running)) if Arc::ptr_eq(running, &cell)) {
            match &answer {
                DnsScriptAnswer::Addresses { ttl: Some(ttl), .. } => {
                    slots.insert(key, Slot::Kept(answer.clone(), Instant::now() + *ttl));
                }
                _ => {
                    slots.remove(&key);
                }
            }
        }
        answer
    }
}

impl Resolver {
    /// The addresses a `dns` script gives for `host`, or `None` when it leaves the host to
    /// the rest of the resolver.
    pub(crate) async fn scripted_lookup(
        &self,
        script: &Arc<str>,
        host: &str,
        version: IpVersion,
        initiator: Initiator,
    ) -> io::Result<Option<LookupIps>> {
        let ips = match self.scripts.answer(script, host).await {
            DnsScriptAnswer::Addresses { ips, .. } => ips,
            DnsScriptAnswer::Servers(servers) => {
                let mut ips = Vec::new();
                for qtype in [RecordType::A, RecordType::AAAA] {
                    let Some(query) = msg::build_query(host, qtype) else {
                        continue;
                    };
                    if let Ok(answer) = self.ask_servers(&servers, &query, initiator).await {
                        ips.extend(msg::answer_ips(&answer));
                    }
                }
                ips
            }
            DnsScriptAnswer::Resolve => return Ok(None),
        };
        let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) = ips.into_iter().partition(IpAddr::is_ipv4);
        Ok(match version {
            IpVersion::Ipv4 if v4.is_empty() => None,
            IpVersion::Ipv6 if v6.is_empty() => None,
            IpVersion::Ipv4 => Some(LookupIps { v4, v6: Vec::new() }),
            IpVersion::Ipv6 => Some(LookupIps { v4: Vec::new(), v6 }),
            _ => Some(LookupIps { v4, v6 }),
        })
    }

    /// `req` asked of the servers a `dns` script named, over UDP and not through a proxy.
    pub(crate) async fn ask_servers(
        &self,
        servers: &[SocketAddr],
        req: &Message,
        initiator: Initiator,
    ) -> io::Result<Message> {
        let clients: Vec<ClientRef> = servers
            .iter()
            .map(|server| {
                let connector = Connector::new(self.dial.clone(), Via::Direct, None);
                Arc::new(PlainClient::new(
                    Transport::Udp,
                    server.ip().to_string(),
                    server.port(),
                    Arc::new(connector),
                )) as ClientRef
            })
            .collect();
        Ok(batch_exchange(&clients, req, Cx { initiator }).await?.msg)
    }
}
