use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use concord_common::{ConnRecord, OutboundKind, io_error};

use crate::flow::FlowState;
use crate::intercept::{
    ConnMark, DialFailure, HeldConn, InterceptFlow, Reject, Route, RuleLabel, Upstream,
    UpstreamDialer, UpstreamRequest,
};
use crate::route::Decision;
use crate::runtime::{Inner, Runtime};
use crate::table::{ConnTable, Tracked};
use crate::tcp::{FailedDial, MeteredStream, dial_decided, record_of, route_traced};

/// `dialMITM`. It holds the tunnel weakly, because the tunnel's interceptor holds this.
pub(crate) struct TunnelUpstream {
    pub inner: Weak<Inner>,
}

fn label_of(decision: &Decision) -> Option<RuleLabel> {
    decision.rule.as_ref().map(|rule| RuleLabel {
        name: rule.type_name.clone(),
        payload: rule.payload.clone(),
    })
}

impl From<FailedDial> for DialFailure {
    fn from(failed: FailedDial) -> Self {
        let outermost = failed
            .decision
            .as_ref()
            .and_then(|decision| decision.chain.last().cloned());
        DialFailure {
            chain: outermost.into_iter().collect(),
            rule: failed.decision.as_deref().and_then(label_of),
            error: failed.error,
        }
    }
}

struct Held {
    table: Arc<ConnTable>,
    tracked: Arc<Tracked>,
    released: AtomicBool,
    closes: u64,
}

impl Held {
    fn close_if_all_closed(&self) {
        if self.table.closes() != self.closes {
            self.tracked.record.close();
        }
    }
}

impl HeldConn for Held {
    fn id(&self) -> &str {
        &self.tracked.record.id
    }

    fn release(&self, mark: ConnMark) {
        if self.released.swap(true, Ordering::AcqRel) {
            return;
        }
        match mark {
            ConnMark::Plain => {}
            ConnMark::Decrypted => self.tracked.record.mitm.store(true, Ordering::Relaxed),
            ConnMark::Refused => self
                .tracked
                .record
                .mitm_refused
                .store(true, Ordering::Relaxed),
        }
        self.close_if_all_closed();
        self.table.list(&self.tracked);
        self.close_if_all_closed();
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.release(ConnMark::Plain);
    }
}

/// What [TunnelUpstream::route] decided, kept for the dial.
struct Plan {
    flow: FlowState,
    decision: Decision,
    runtime: Arc<Runtime>,
    closes: u64,
}

#[async_trait]
impl UpstreamDialer for TunnelUpstream {
    async fn route(&self, request: &UpstreamRequest) -> Result<Route, DialFailure> {
        let inner = self
            .inner
            .upgrade()
            .ok_or_else(|| io_error("the tunnel is gone"))?;
        let closes = inner.table.closes();
        let runtime = inner
            .runtime_for(request.flow.meta.inbound.kind)
            .ok_or_else(|| io_error("the core is not running"))?;
        let mut flow = FlowState::of_intercept(&request.flow);
        flow.http = request.http.clone();
        let decision = route_traced(&inner, &runtime, &mut flow).await?;
        let reject = match decision.leaf.info().kind {
            OutboundKind::Reject => Some(Reject::Reply),
            OutboundKind::RejectDrop => Some(Reject::Drop),
            _ => None,
        };
        let chain = Arc::from(decision.chain.clone());
        let rule = label_of(&decision);
        let http_pending = decision.http_pending;
        let plan = Plan {
            flow,
            decision,
            runtime,
            closes,
        };
        Ok(Route::new(
            chain,
            rule,
            reject,
            http_pending,
            Box::new(plan),
        ))
    }

    async fn dial_routed(
        &self,
        request: UpstreamRequest,
        mut route: Route,
    ) -> Result<Upstream, DialFailure> {
        if route.reject.is_some() {
            return Err(route.rejected());
        }
        let Plan {
            mut flow,
            decision,
            runtime,
            closes,
        } = *route
            .take_plan()
            .and_then(|plan| plan.downcast::<Plan>().ok())
            .ok_or_else(|| io_error("a route is dialed once"))?;
        let inner = self
            .inner
            .upgrade()
            .ok_or_else(|| io_error("the tunnel is gone"))?;
        let (remote, decision) = dial_decided(&inner, &runtime, &mut flow, decision).await?;
        tracing::info!("{}", decision.match_text(&flow, &inner.live()));
        let record = record_of(&flow, &decision, &remote);
        let all_closed = || DialFailure {
            chain: decision.chain.to_vec(),
            rule: label_of(&decision),
            error: io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "every connection was closed while this one was dialing",
            ),
        };
        if request.hold {
            if inner.table.closes() != closes {
                return Err(all_closed());
            }
            let registration = inner.table.prepare(record, 0);
            let held = Held {
                table: inner.table.clone(),
                tracked: registration.tracked().clone(),
                released: AtomicBool::new(false),
                closes,
            };
            return Ok(Upstream {
                stream: Box::new(MeteredStream::new(remote, registration)),
                id: None,
                held: Some(Arc::new(held)),
            });
        }
        record.mitm.store(true, Ordering::Relaxed);
        let id = Arc::from(record.id.as_str());
        let Some(registration) = inner.table.register_since(record, closes) else {
            return Err(all_closed());
        };
        Ok(Upstream {
            stream: Box::new(MeteredStream::new(remote, registration)),
            id: Some(id),
            held: None,
        })
    }

    fn reads_http(&self, flow: &InterceptFlow) -> bool {
        self.inner
            .upgrade()
            .and_then(|inner| inner.runtime_for(flow.meta.inbound.kind))
            .is_some_and(|runtime| runtime.program.demands().http)
    }

    fn record_closed(
        &self,
        flow: &InterceptFlow,
        chain: &[Arc<str>],
        rule: Option<&RuleLabel>,
    ) -> Option<Arc<str>> {
        let inner = self.inner.upgrade()?;
        let meta = FlowState::of_intercept(flow).conn_meta(String::new());
        let (name, payload) = match rule {
            Some(rule) => (rule.name.clone(), rule.payload.clone()),
            None => (Arc::from(""), Arc::from("")),
        };
        let record = Arc::new(ConnRecord::new(
            meta,
            chain.into(),
            Box::new([]),
            name,
            payload,
            false,
            0,
        ));
        record.mitm.store(true, Ordering::Relaxed);
        let id = Arc::from(record.id.as_str());
        drop(inner.table.register(record, 0));
        Some(id)
    }
}
