use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use concord_common::scripts::{DnsScriptAnswer, ScriptHooks};
use concord_common::sync::lock;
use concord_common::{Initiator, IpVersion, LookupIps};
use hickory_proto::op::{Message, ResponseCode};
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
/// The reply of the servers a script names is kept for the shortest TTL among its records,
/// so the script is not run again for that domain until then. Everything kept goes when the
/// scripts in force change.
pub(crate) struct ScriptAnswers {
    hooks: Arc<dyn ScriptHooks>,
    kept: Mutex<Kept>,
}

#[derive(Default)]
struct Kept {
    generation: u64,
    slots: HashMap<(Arc<str>, String), Slot>,
    replies: HashMap<(Arc<str>, String, RecordType), (Message, Instant)>,
}

impl Kept {
    /// Forgets everything once the scripts are no longer `generation`.
    fn follow(&mut self, generation: u64) {
        if self.generation != generation {
            *self = Kept {
                generation,
                ..Kept::default()
            };
        }
    }

    /// Drops what has run out. Only a write calls it: a lookup checks the one entry it finds,
    /// so a query costs the same however many domains are kept.
    fn prune(&mut self) {
        let now = Instant::now();
        self.slots
            .retain(|_, slot| !matches!(slot, Slot::Kept(_, until) if *until <= now));
        self.replies.retain(|_, (_, until)| *until > now);
    }
}

enum Slot {
    Running(Arc<OnceCell<DnsScriptAnswer>>),
    Kept(DnsScriptAnswer, Instant),
}

impl ScriptAnswers {
    pub(crate) fn new(hooks: Arc<dyn ScriptHooks>) -> Self {
        ScriptAnswers {
            hooks,
            kept: Mutex::default(),
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.hooks.generation()
    }

    /// The reply `script`'s servers gave for `domain` and `qtype`, while its TTL lasts.
    pub(crate) fn kept_reply(
        &self,
        script: &Arc<str>,
        domain: &str,
        qtype: RecordType,
    ) -> Option<Message> {
        let mut kept = lock(&self.kept);
        kept.follow(self.hooks.generation());
        if kept.replies.is_empty() {
            return None;
        }
        let key = (script.clone(), domain.to_ascii_lowercase(), qtype);
        let (reply, until) = kept.replies.get(&key)?;
        let left = until.checked_duration_since(Instant::now())?.as_secs();
        let mut reply = reply.clone();
        msg::update_msg_ttl(&mut reply, u32::try_from(left).unwrap_or(u32::MAX).max(1));
        Some(reply)
    }

    /// Keeps `reply` to a question about `domain` from `script`'s servers, unless it is an
    /// error, has no record with a TTL to keep it by, or the scripts changed since `generation`.
    fn keep_reply(&self, script: &Arc<str>, domain: &str, generation: u64, reply: &Message) {
        let Some(qtype) = reply.queries.first().map(|query| query.query_type) else {
            return;
        };
        let ttl = msg::minimal_ttl(reply);
        if reply.metadata.response_code != ResponseCode::NoError || ttl == 0 {
            return;
        }
        let mut kept = lock(&self.kept);
        kept.follow(self.hooks.generation());
        if kept.generation != generation {
            return;
        }
        kept.prune();
        let until = Instant::now() + Duration::from_secs(u64::from(ttl));
        let key = (script.clone(), domain.to_ascii_lowercase(), qtype);
        kept.replies.insert(key, (reply.clone(), until));
    }

    pub(crate) async fn answer(&self, script: &Arc<str>, domain: &str) -> DnsScriptAnswer {
        let key = (script.clone(), domain.to_ascii_lowercase());
        let cell = {
            let mut kept = lock(&self.kept);
            kept.follow(self.hooks.generation());
            let slots = &mut kept.slots;
            match slots.get(&key) {
                Some(Slot::Kept(answer, until)) if *until > Instant::now() => {
                    return answer.clone();
                }
                Some(Slot::Running(cell)) => cell.clone(),
                _ => {
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
        let mut kept = lock(&self.kept);
        if matches!(kept.slots.get(&key), Some(Slot::Running(running)) if Arc::ptr_eq(running, &cell))
        {
            match &answer {
                DnsScriptAnswer::Addresses { ttl: Some(ttl), .. } => {
                    kept.prune();
                    let until = Instant::now() + *ttl;
                    kept.slots.insert(key, Slot::Kept(answer.clone(), until));
                }
                _ => {
                    kept.slots.remove(&key);
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
        const BOTH: [RecordType; 2] = [RecordType::A, RecordType::AAAA];
        let wanted: &[RecordType] = match version {
            IpVersion::Ipv4 => &BOTH[..1],
            IpVersion::Ipv6 => &BOTH[1..],
            _ => &BOTH,
        };
        let kept: Option<Vec<Message>> = wanted
            .iter()
            .map(|qtype| self.scripts.kept_reply(script, host, *qtype))
            .collect();
        let generation = self.scripts.generation();
        let ips = match kept {
            Some(replies) => replies.iter().flat_map(msg::answer_ips).collect(),
            None => match self.scripts.answer(script, host).await {
                DnsScriptAnswer::Addresses { ips, .. } => ips,
                DnsScriptAnswer::Servers(servers) => {
                    let mut ips = Vec::new();
                    for qtype in BOTH {
                        let Some(query) = msg::build_query(host, qtype) else {
                            continue;
                        };
                        let asked = self
                            .ask_script_servers(
                                script, host, generation, &servers, &query, initiator,
                            )
                            .await;
                        if let Ok(answer) = asked {
                            ips.extend(msg::answer_ips(&answer));
                        }
                    }
                    ips
                }
                DnsScriptAnswer::Resolve => return Ok(None),
            },
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

    /// As [Resolver::ask_servers] for the servers `script` named for `host` under the scripts
    /// of `generation`, keeping the reply for [ScriptAnswers::kept_reply].
    pub(crate) async fn ask_script_servers(
        &self,
        script: &Arc<str>,
        host: &str,
        generation: u64,
        servers: &[SocketAddr],
        req: &Message,
        initiator: Initiator,
    ) -> io::Result<Message> {
        let reply = self.ask_servers(servers, req, initiator).await?;
        self.scripts.keep_reply(script, host, generation, &reply);
        Ok(reply)
    }

    /// `req` asked of the servers a `dns` script named, over UDP and not through a proxy.
    async fn ask_servers(
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
