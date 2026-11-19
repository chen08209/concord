use std::sync::Arc;

use http::header::HOST;
use http::{HeaderMap, StatusCode};

use crate::body::{Body, Buffered, buffer_body, empty, failing, full};
use crate::capture::{PHASE_REQUEST, PHASE_RESPONSE};
use crate::exchange::{
    ANSWER_SCRIPT, Answer, OutRequest, RULE_SCRIPT, ReplyError, Sent, Target, has_response_body,
    set_length,
};
use crate::headers::{is_grpc, script_header, to_list, with_host};
use crate::limits::PRESSURE_NO_SCRIPTS;
use crate::script::{Script, ScriptInvocation, ScriptRequest, ScriptResponse, ScriptResult};
use crate::session::{Session, SessionDial};
use crate::target::TargetUrl;

fn non_empty(data: &[u8]) -> Option<Vec<u8>> {
    (!data.is_empty()).then(|| data.to_vec())
}

fn script_answer(answer: ScriptResponse) -> Answer {
    let status = StatusCode::from_u16(answer.status)
        .ok()
        .filter(|_| (100..=999).contains(&answer.status))
        .unwrap_or(StatusCode::OK);
    let mut headers = script_header(&answer.header);
    let body = answer.body.unwrap_or_default();
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from(body.len()),
    );
    Answer {
        status,
        headers,
        body,
    }
}

impl Session {
    fn scripts_paused(&self) -> bool {
        self.core.shared.pressure.level() >= PRESSURE_NO_SCRIPTS
    }

    /// Leaves what it was to change as it was when the script fails, runs out
    /// of time or finds no slot within its timeout.
    async fn run_script(
        self: &Arc<Self>,
        script: &Script,
        address: &str,
        invocation: ScriptInvocation,
    ) -> Option<ScriptResult> {
        let dial = Arc::new(SessionDial {
            session: self.clone(),
        });
        match self
            .core
            .invoke(&self.core.session_gate, script, invocation, dial)
            .await
        {
            Ok(result) => Some(result),
            Err(err) => {
                tracing::warn!("[MITM] script {} on {address}: {err}", script.name);
                None
            }
        }
    }

    fn base_invocation(self: &Arc<Self>) -> ScriptInvocation {
        ScriptInvocation::base(Arc::new(SessionDial {
            session: self.clone(),
        }))
    }

    pub(crate) async fn run_request_script(
        self: &Arc<Self>,
        out: &mut OutRequest,
        target: &mut Target,
        script: &Arc<Script>,
    ) {
        if target.http1 || self.scripts_paused() {
            return;
        }
        let address = out.url.raw.clone();
        let mut request = ScriptRequest {
            id: target.id.clone(),
            url: address.clone(),
            method: out.method.to_string(),
            header: with_host(&out.headers, &out.host_header()),
            body: None,
        };
        let mut buffered = false;
        if script.requires_body && out.has_body {
            let body = std::mem::replace(&mut out.body, empty());
            let (body, length, data) = self
                .buffer_for_script(target, script, &address, &mut out.headers, body, out.length)
                .await;
            out.set_body(body, length);
            let Some(data) = data else { return };
            request.header = with_host(&out.headers, &out.host_header());
            request.body = non_empty(&data);
            buffered = true;
        }
        let mut invocation = self.base_invocation();
        invocation.request = Some(request);
        let Some(result) = self.run_script(script, &address, invocation).await else {
            return;
        };
        target.cap.note("script", PHASE_REQUEST, &script.name);
        if result.abort {
            target.abort = true;
            self.answered(target, ANSWER_SCRIPT, RULE_SCRIPT, &script.name);
            tracing::info!("[MITM] script {} aborted {address}", script.name);
            return;
        }
        if let Some(response) = result.response {
            target.answer = Some(script_answer(response));
            self.answered(target, ANSWER_SCRIPT, RULE_SCRIPT, &script.name);
            tracing::info!("[MITM] script {} answered {address}", script.name);
            return;
        }
        let mut changed = false;
        if !result.url.is_empty() {
            match TargetUrl::parse_http(&result.url) {
                Some(rewritten) => {
                    out.url = rewritten;
                    changed = true;
                }
                None => tracing::warn!(
                    "[MITM] script {} gave {:?} for {address}, which is not an http or https URL",
                    script.name,
                    result.url
                ),
            }
        }
        if let Some(list) = &result.header {
            let mut header = script_header(list);
            let script_host = header
                .remove(HOST)
                .and_then(|value| value.to_str().ok().map(str::to_string))
                .filter(|host| !host.is_empty());
            if script_host.is_some() {
                out.host = script_host;
            }
            out.headers = header;
            changed = true;
            if let Some(length) = out.length {
                set_length(&mut out.headers, Some(length));
            }
        }
        if buffered && let Some(data) = result.body {
            let length = data.len() as u64;
            out.set_body(full(data), Some(length));
            changed = true;
        }
        if changed {
            tracing::info!(
                "[MITM] script {} rewrote the request of {address}",
                script.name
            );
        }
    }

    pub(crate) async fn run_response_script(
        self: &Arc<Self>,
        head: &mut http::response::Parts,
        body: &mut Body,
        sent: &Sent,
        target: &mut Target,
        script: &Arc<Script>,
    ) -> Result<(), ReplyError> {
        if self.scripts_paused() {
            return Ok(());
        }
        let address = sent.url.raw.clone();
        let request = ScriptRequest {
            id: target.id.clone(),
            url: address.clone(),
            method: sent.method.to_string(),
            header: with_host(&sent.headers, &sent.host),
            body: None,
        };
        let length = hyper::body::Body::size_hint(body).exact();
        let mut data_seen = None;
        if script.requires_body && has_response_body(&sent.method, head.status) {
            let source = std::mem::replace(body, empty());
            let (replaced, length, data) = self
                .buffer_for_script(target, script, &address, &mut head.headers, source, length)
                .await;
            *body = replaced;
            set_length(&mut head.headers, length);
            if data.is_none() {
                return Ok(());
            }
            data_seen = data;
        }
        let response = ScriptResponse {
            status: head.status.as_u16(),
            header: to_list(&head.headers),
            body: data_seen.as_deref().and_then(non_empty),
        };
        let mut invocation = self.base_invocation();
        invocation.request = Some(request);
        invocation.response = Some(response);
        let Some(result) = self.run_script(script, &address, invocation).await else {
            return Ok(());
        };
        target.cap.note("script", PHASE_RESPONSE, &script.name);
        if result.abort {
            tracing::info!(
                "[MITM] script {} aborted the response of {address}",
                script.name
            );
            return Err(ReplyError::Abort);
        }
        let mut changed = false;
        if result.status != 0 {
            match StatusCode::from_u16(result.status)
                .ok()
                .filter(|_| (100..=999).contains(&result.status))
            {
                Some(status) => {
                    head.status = status;
                    changed = true;
                }
                None => tracing::warn!(
                    "[MITM] script {} gave status {} for {address}",
                    script.name,
                    result.status
                ),
            }
        }
        if let Some(list) = &result.header {
            head.headers = script_header(list);
            changed = true;
            if let Some(length) = hyper::body::Body::size_hint(body).exact() {
                set_length(&mut head.headers, Some(length));
            }
        }
        if data_seen.is_some()
            && let Some(data) = result.body
        {
            let length = data.len() as u64;
            *body = full(data);
            set_length(&mut head.headers, Some(length));
            changed = true;
        }
        if changed {
            tracing::info!(
                "[MITM] script {} rewrote the response of {address}",
                script.name
            );
        }
        Ok(())
    }

    /// Reads the body for a script that requires it, or leaves it to stream on
    /// and the script unrun when the body is too large, cannot be decoded or is
    /// not text for a script that takes text.
    async fn buffer_for_script(
        &self,
        target: &mut Target,
        script: &Script,
        address: &str,
        headers: &mut HeaderMap,
        body: Body,
        length: Option<u64>,
    ) -> (Body, Option<u64>, Option<Vec<u8>>) {
        if is_grpc(headers) && !script.binary_body {
            return (body, length, None);
        }
        let limit = script.body_limit(self.core.config.limits.max_body_size);
        if !self
            .reserve_body(target, address, headers, length, limit)
            .await
        {
            return (body, length, None);
        }
        match buffer_body(headers, body, length, limit).await {
            Err(err) => (failing(err), None, None),
            Ok(Buffered::Rest { body, length }) => {
                tracing::info!(
                    "[MITM] script {} skips {address}, whose body is too large or in an unknown encoding",
                    script.name
                );
                (body, length, None)
            }
            Ok(Buffered::Whole(data)) => {
                let size = data.len() as u64;
                if !script.binary_body && std::str::from_utf8(&data).is_err() {
                    return (full(data), Some(size), None);
                }
                (full(data.clone()), Some(size), Some(data))
            }
        }
    }
}
