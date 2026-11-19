use std::sync::Arc;

use concord_common::HttpFacts;
use concord_common::intercept::{Reject, Route, RuleLabel, UpstreamRequest};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, UPGRADE, USER_AGENT};
use http::{Extensions, HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Incoming};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use rand::RngCore;
use tokio::sync::OwnedSemaphorePermit;

use crate::body::{Body, Tap, empty, from_incoming, full};
use crate::capture::Cap;
use crate::forward::request_text;
use crate::headers::{remove_hop_by_hop, text, to_list, version_text, with_host};
use crate::heads::Heads;
use crate::rules::{UrlAction, tiny_gif};
use crate::session::{ActivityGuard, Routed, Session};
use crate::target::{TargetUrl, default_port};

pub(crate) const ANSWER_REJECT: &str = "REJECT";
pub(crate) const ANSWER_REDIRECT: &str = "REDIRECT";
pub(crate) const ANSWER_MAP_LOCAL: &str = "MAP-LOCAL";
pub(crate) const ANSWER_SCRIPT: &str = "SCRIPT";
pub(crate) const RULE_URL_REWRITE: &str = "URL-REWRITE";
pub(crate) const RULE_MAP_LOCAL: &str = "MAP-LOCAL";
pub(crate) const RULE_SCRIPT: &str = "SCRIPT";

#[derive(Debug)]
pub(crate) struct Abort;

impl std::fmt::Display for Abort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("aborted by a script")
    }
}

impl std::error::Error for Abort {}

/// Why a response could not be passed on.
pub(crate) enum ReplyError {
    Abort,
    Failed(String),
}

impl From<std::io::Error> for ReplyError {
    fn from(err: std::io::Error) -> Self {
        ReplyError::Failed(err.to_string())
    }
}

pub(crate) struct Answer {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// One exchange as it passes the rules.
pub(crate) struct Target {
    pub url: TargetUrl,
    pub rewritten: bool,
    /// An upgrade, a WebSocket, which HTTP/2 cannot carry upstream.
    pub http1: bool,
    /// The version the client spoke, as a head's first line writes it.
    pub version: &'static str,
    pub id: String,
    pub answer: Option<Answer>,
    pub abort: bool,
    /// Room in the body buffer, held until the exchange ends.
    pub reserved: Vec<OwnedSemaphorePermit>,
    pub cap: Cap,
}

/// The request about to go upstream.
pub(crate) struct OutRequest {
    pub method: Method,
    pub headers: HeaderMap,
    pub host: Option<String>,
    pub url: TargetUrl,
    pub body: Body,
    pub has_body: bool,
    pub length: Option<u64>,
}

impl OutRequest {
    pub fn host_header(&self) -> String {
        self.host
            .clone()
            .unwrap_or_else(|| self.url.authority.clone())
    }

    pub fn set_body(&mut self, body: Body, length: Option<u64>) {
        self.body = body;
        self.length = length;
        set_length(&mut self.headers, length);
    }
}

/// What the response phase needs to know of the request that was sent.
pub(crate) struct Sent {
    pub method: Method,
    pub url: TargetUrl,
    pub headers: HeaderMap,
    pub host: String,
}

/// Keeps `Content-Length` true to the body, which has a length only when it is known.
pub(crate) fn set_length(headers: &mut HeaderMap, length: Option<u64>) {
    match length {
        Some(length) => {
            headers.insert(CONTENT_LENGTH, HeaderValue::from(length));
            headers.remove(http::header::TRANSFER_ENCODING);
        }
        None => {
            headers.remove(CONTENT_LENGTH);
        }
    }
}

pub(crate) fn new_request_id() -> String {
    let mut id = [0u8; 8];
    rand::rng().fill_bytes(&mut id);
    hex::encode(id)
}

pub(crate) fn has_response_body(method: &Method, status: StatusCode) -> bool {
    method != Method::HEAD
        && status.as_u16() >= 200
        && status != StatusCode::NO_CONTENT
        && status != StatusCode::NOT_MODIFIED
}

fn request_host(parts: &http::request::Parts) -> String {
    let header = text(&parts.headers, HOST);
    if !header.is_empty() {
        return header.to_string();
    }
    parts
        .uri
        .authority()
        .map(|authority| authority.as_str().to_string())
        .unwrap_or_default()
}

fn local(
    cap: &Cap,
    status: StatusCode,
    mut headers: HeaderMap,
    body: Vec<u8>,
    guard: ActivityGuard,
) -> Response<Body> {
    headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
    cap.responded(status.as_u16(), to_list(&headers));
    cap.add_response_size(body.len());
    cap.keep_response(&body);
    cap.finish();
    drop(guard);
    let mut response = Response::new(full(body));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

/// The reply a REJECT variant asks for, by the name it leaves in the chain.
fn reject_action(route: &Route) -> UrlAction {
    match route.chain.first().map(|exit| &**exit) {
        Some("REJECT-TINYGIF" | "REJECT-IMG") => UrlAction::RejectImg,
        Some("REJECT-DICT") => UrlAction::RejectDict,
        Some("REJECT-ARRAY") => UrlAction::RejectArray,
        Some("REJECT-200" | "REJECT-VIDEO") => UrlAction::Reject200,
        _ => UrlAction::Reject,
    }
}

/// What the request shows the rules once the rules before the dial have run.
fn http_facts(out: &OutRequest) -> Arc<HttpFacts> {
    Arc::new(HttpFacts {
        url: out.url.raw.as_str().into(),
        host: out.url.host.to_ascii_lowercase().into(),
        user_agent: out
            .headers
            .get(USER_AGENT)
            .and_then(|agent| agent.to_str().ok())
            .map(Into::into),
    })
}

/// Why a request did not go upstream.
pub(crate) enum Unsent {
    /// The rules rejected it with this reply.
    Answer(StatusCode, HeaderMap, Vec<u8>),
    /// The rules rejected it without one.
    Drop,
    Failed(String),
}

fn reject_response(action: UrlAction) -> (StatusCode, Option<&'static str>, Vec<u8>) {
    match action {
        UrlAction::Reject => (StatusCode::NOT_FOUND, None, Vec::new()),
        UrlAction::RejectImg => (StatusCode::OK, Some("image/gif"), tiny_gif()),
        UrlAction::RejectDict => (StatusCode::OK, Some("application/json"), b"{}".to_vec()),
        UrlAction::RejectArray => (StatusCode::OK, Some("application/json"), b"[]".to_vec()),
        _ => (StatusCode::OK, None, Vec::new()),
    }
}

impl Session {
    fn request_url(&self, parts: &http::request::Parts, host: &str) -> Option<TargetUrl> {
        let authority = if let Some(authority) = parts.uri.authority() {
            authority.as_str().to_string()
        } else if !host.is_empty() {
            host.to_string()
        } else if self.flow.port == default_port(self.https()) {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.flow.port)
        };
        let path = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
        TargetUrl::from_request(self.https(), &authority, path)
    }

    /// Lists a request that went out on no connection, as one closed at once, under the
    /// rule that answered it.
    pub(crate) fn answered(&self, target: &Target, chain: &str, rule: &str, payload: &str) {
        if !target.cap.is_some() {
            return;
        }
        let flow = self.upstream_flow(&target.url.host, target.url.port);
        let chain = [Arc::<str>::from(chain)];
        let rule = RuleLabel {
            name: rule.into(),
            payload: payload.into(),
        };
        target.cap.routed(&chain, Some(&rule));
        if let Some(id) = self
            .core
            .shared
            .dialer
            .record_closed(&flow, &chain, Some(&rule))
        {
            target.cap.attach(&id);
        }
    }

    /// Routes a request the session's route may not hold for; `None` leaves it to the
    /// session's.
    pub(crate) fn route_request<'a>(
        &'a self,
        out: &OutRequest,
        target: &'a Target,
    ) -> impl Future<Output = Result<Option<Routed>, Unsent>> + Send + 'a {
        let apart = self
            .routes_apart(&out.url.host, out.url.port)
            .then(|| (out.url.clone(), http_facts(out)));
        async move {
            match apart {
                Some((url, http)) => self.routed(&url, http, target).await,
                None => Ok(None),
            }
        }
    }

    async fn routed(
        &self,
        url: &TargetUrl,
        http: Arc<HttpFacts>,
        target: &Target,
    ) -> Result<Option<Routed>, Unsent> {
        let flow = self.upstream_flow(&url.host, url.port);
        let dialer = &self.core.shared.dialer;
        let request = UpstreamRequest {
            flow: flow.clone(),
            hold: false,
            http: Some(http.clone()),
        };
        let route = match dialer.route(&request).await {
            Ok(route) => route,
            Err(failure) => {
                if !failure.chain.is_empty() {
                    target.cap.routed(&failure.chain, failure.rule.as_ref());
                    if let Some(id) =
                        dialer.record_closed(&flow, &failure.chain, failure.rule.as_ref())
                    {
                        target.cap.attach(&id);
                    }
                }
                return Err(Unsent::Failed(failure.error.to_string()));
            }
        };
        let Some(reject) = route.reject else {
            return Ok(Some(Routed {
                route: Some(route),
                http,
            }));
        };
        target.cap.routed(&route.chain, route.rule.as_ref());
        if let Some(id) = dialer.record_closed(&flow, &route.chain, route.rule.as_ref()) {
            target.cap.attach(&id);
        }
        let exit = route.chain.first().map_or("", |exit| &**exit);
        match &route.rule {
            Some(rule) => tracing::info!(
                "[MITM] {exit} {} (match {}/{})",
                url.raw,
                rule.name,
                rule.payload
            ),
            None => tracing::info!("[MITM] {exit} {}", url.raw),
        }
        if reject == Reject::Drop {
            return Err(Unsent::Drop);
        }
        let (status, content_type, data) = reject_response(reject_action(&route));
        let mut headers = HeaderMap::new();
        if let Some(content_type) = content_type {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
        Err(Unsent::Answer(status, headers, data))
    }

    fn unsent(
        &self,
        unsent: Unsent,
        cap: &Cap,
        guard: ActivityGuard,
    ) -> Result<Response<Body>, Abort> {
        match unsent {
            Unsent::Answer(status, headers, data) => Ok(local(cap, status, headers, data, guard)),
            Unsent::Drop => {
                cap.fail("rejected by the rules");
                cap.finish();
                Err(Abort)
            }
            Unsent::Failed(message) => self.proxy_error(cap, &message, guard),
        }
    }

    /// Header rewrites, then a URL rewrite and Map Local, in Surge's order: the answer the
    /// last two give in place of the server's, or `None` when the request goes on.
    fn rewrite_head(
        &self,
        out: &mut OutRequest,
        target: &mut Target,
    ) -> Option<(StatusCode, HeaderMap, Vec<u8>)> {
        self.rewrite_request_headers(out, target);
        target.url = out.url.clone();
        let answer = {
            let version = target.version;
            let head = || request_text(out, version);
            self.answer_locally(&Heads::new(Some(&head), None), target)
        };
        if answer.is_none() && target.rewritten {
            out.url = target.url.clone();
            out.host = None;
        }
        answer
    }

    /// The answer a URL rewrite or Map Local gives in place of the server's, or `None` when
    /// the request goes on, perhaps to the URL a rewrite moved it to.
    fn answer_locally(
        &self,
        heads: &Heads<'_>,
        target: &mut Target,
    ) -> Option<(StatusCode, HeaderMap, Vec<u8>)> {
        let rules = &self.core.config.rules;
        if let Some((rule, replaced)) = rules.rewrite_url(&target.url.raw, heads) {
            match rule.action {
                UrlAction::Redirect302 | UrlAction::Redirect307 => {
                    target.cap.note(
                        "url-rewrite",
                        "",
                        rule.action.name(),
                        rule.module.as_deref(),
                    );
                    self.answered(target, ANSWER_REDIRECT, RULE_URL_REWRITE, rule.source());
                    tracing::info!(
                        "[MITM] {} {} --> {replaced}",
                        rule.action.name(),
                        target.url.raw
                    );
                    let mut headers = HeaderMap::new();
                    if let Ok(location) = HeaderValue::from_str(&replaced) {
                        headers.insert(LOCATION, location);
                    }
                    let status = if rule.action == UrlAction::Redirect307 {
                        StatusCode::TEMPORARY_REDIRECT
                    } else {
                        StatusCode::FOUND
                    };
                    return Some((status, headers, Vec::new()));
                }
                UrlAction::Header => match TargetUrl::parse_http(&replaced) {
                    Some(rewritten) => {
                        target.cap.note(
                            "url-rewrite",
                            "",
                            rule.action.name(),
                            rule.module.as_deref(),
                        );
                        tracing::info!("[MITM] rewrite {} --> {}", target.url.raw, rewritten.raw);
                        target.url = rewritten;
                        target.rewritten = true;
                    }
                    None => tracing::warn!(
                        "[MITM] rewrite of {} gave {replaced:?}, which is not an http or https URL",
                        target.url.raw
                    ),
                },
                action => {
                    target
                        .cap
                        .note("url-rewrite", "", action.name(), rule.module.as_deref());
                    self.answered(target, ANSWER_REJECT, RULE_URL_REWRITE, rule.source());
                    tracing::info!("[MITM] {} {}", action.name(), target.url.raw);
                    let (status, content_type, data) = reject_response(action);
                    let mut headers = HeaderMap::new();
                    if let Some(content_type) = content_type {
                        headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
                    }
                    return Some((status, headers, data));
                }
            }
        }
        let rule = rules.map_local(&target.url.raw, heads)?;
        target.cap.note("map-local", "", "", rule.module.as_deref());
        self.answered(target, ANSWER_MAP_LOCAL, RULE_MAP_LOCAL, rule.source());
        tracing::info!("[MITM] map local {}", target.url.raw);
        Some((rule.status, rule.header.clone(), rule.body.clone()))
    }

    pub(crate) async fn handle(
        self: Arc<Self>,
        mut request: Request<Incoming>,
    ) -> Result<Response<Body>, Abort> {
        let guard = self.begin_request();
        if request.method() == Method::CONNECT {
            let mut response = Response::new(empty());
            *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
            return Ok(response);
        }
        let upgrading = !text(request.headers(), UPGRADE).is_empty();
        let client_upgrade = upgrading.then(|| hyper::upgrade::on(&mut request));
        let (mut parts, incoming) = request.into_parts();
        let in_host = request_host(&parts);
        let Some(url) = self.request_url(&parts, &in_host) else {
            let mut response = Response::new(empty());
            *response.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(response);
        };
        let cap = self.core.shared.captures.begin(
            parts.method.as_str(),
            &url.raw,
            version_text(parts.version),
            with_host(&parts.headers, &in_host),
        );
        let has_body = !incoming.is_end_stream();
        let length = incoming.size_hint().exact();
        let mut body = from_incoming(incoming);
        if has_body && cap.is_some() {
            let counter = cap.clone();
            body = Tap::new(
                body,
                Some(Box::new(move |data| counter.add_request_size(data.len()))),
                None,
            )
            .boxed_unsync();
        }
        parts.headers.remove(HOST);
        let mut target = Target {
            url,
            rewritten: false,
            http1: upgrading,
            version: version_text(parts.version),
            id: String::new(),
            answer: None,
            abort: false,
            reserved: Vec::new(),
            cap: cap.clone(),
        };
        let mut out = OutRequest {
            method: parts.method.clone(),
            headers: std::mem::take(&mut parts.headers),
            host: Some(in_host),
            url: target.url.clone(),
            body,
            has_body,
            length,
        };
        if let Some((status, headers, data)) = self.rewrite_head(&mut out, &mut target) {
            return Ok(local(&cap, status, headers, data, guard));
        }
        if !self.core.config.rules.scripts.is_empty() {
            target.id = new_request_id();
        }
        tracing::debug!("[MITM] {} {}", out.method, target.url.raw);
        self.rewrite_request(&mut out, &mut target).await;
        if target.abort {
            cap.fail("aborted by a script");
            cap.finish();
            return Err(Abort);
        }
        let sent = Sent {
            method: out.method.clone(),
            url: out.url.clone(),
            headers: out.headers.clone(),
            host: out.host_header(),
        };
        let (mut head, body, upstream_upgrade) = match target.answer.take() {
            Some(answer) => {
                let mut head = Response::new(()).into_parts().0;
                head.status = answer.status;
                head.headers = answer.headers;
                (head, full(answer.body), None)
            }
            None => {
                let (response, upgrade) = match self.round_trip(out, &target).await {
                    Ok(reply) => reply,
                    Err(unsent) => return self.unsent(unsent, &cap, guard),
                };
                let (mut head, incoming) = response.into_parts();
                let mut body = from_incoming(incoming);
                match self
                    .rewrite_response(&mut head, &mut body, &sent, &mut target)
                    .await
                {
                    Ok(()) => {}
                    Err(ReplyError::Abort) => {
                        cap.fail("aborted by a script");
                        cap.finish();
                        return Err(Abort);
                    }
                    Err(ReplyError::Failed(message)) => {
                        return self.proxy_error(&cap, &message, guard);
                    }
                }
                (head, body, upgrade)
            }
        };
        let mut body = body;
        if head.status == StatusCode::SWITCHING_PROTOCOLS {
            let Some((client, upstream)) = client_upgrade.zip(upstream_upgrade) else {
                return self.proxy_error(&cap, "unexpected 101 Switching Protocols", guard);
            };
            self.spawn_relay(relay(client, upstream));
            body = empty();
        } else {
            remove_hop_by_hop(&mut head.headers, false);
        }
        head.version = Version::HTTP_11;
        head.extensions = Extensions::new();
        cap.responded(head.status.as_u16(), to_list(&head.headers));
        let permits = std::mem::take(&mut target.reserved);
        let counter = cap.clone();
        let finisher = cap;
        let tapped = Tap::new(
            body,
            Some(Box::new(move |data| {
                counter.add_response_size(data.len());
                counter.keep_response(data);
            })),
            Some(Box::new(move || {
                finisher.finish();
                drop(permits);
                drop(guard);
            })),
        );
        Ok(Response::from_parts(head, tapped.boxed_unsync()))
    }

    fn proxy_error(
        &self,
        cap: &Cap,
        message: &str,
        guard: ActivityGuard,
    ) -> Result<Response<Body>, Abort> {
        cap.fail(message);
        tracing::warn!("[MITM] request failed: {message}");
        Ok(local(
            cap,
            StatusCode::BAD_GATEWAY,
            HeaderMap::new(),
            Vec::new(),
            guard,
        ))
    }
}

async fn relay(client: OnUpgrade, upstream: OnUpgrade) {
    let (client, upstream) = tokio::join!(client, upstream);
    let (Ok(client), Ok(upstream)) = (client, upstream) else {
        return;
    };
    let (mut client, mut upstream) = (TokioIo::new(client), TokioIo::new(upstream));
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}
