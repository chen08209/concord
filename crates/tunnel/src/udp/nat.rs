use super::*;

#[derive(Default)]
pub(crate) struct UdpNat {
    pub(super) flows: DashMap<FlowId, Arc<Flow>>,
    pub(super) slots: DashMap<SessionKey, Arc<OnceCell<Arc<Session>>>>,
    pub(super) clock: AtomicU32,
    pub(super) scanning: AtomicBool,
}

impl UdpNat {
    pub(super) fn now(&self) -> u32 {
        self.clock.load(Ordering::Relaxed)
    }

    pub(super) fn drop_session(&self, session: &Session) {
        let flows = std::mem::take(&mut *lock(&session.flows));
        for id in flows {
            self.flows.remove(&id);
        }
        self.slots.remove_if(&session.key, |_, slot| {
            slot.get()
                .is_some_and(|current| std::ptr::eq(Arc::as_ptr(current), session))
        });
        session.inner.close();
        session.reply.load().session_ended();
    }

    /// Scanning a full table on each new flow would let a port scan burn the CPU,
    /// so a full table gives back a sixteenth of itself at once.
    pub(super) fn evict_oldest(&self) {
        let mut ages: Vec<(u32, FlowId)> = self
            .flows
            .iter()
            .map(|entry| {
                (
                    entry.value().last_active.load(Ordering::Relaxed),
                    entry.key().clone(),
                )
            })
            .collect();
        let count = (ages.len() / 16).max(1);
        if count < ages.len() {
            ages.select_nth_unstable_by_key(count, |(age, _)| *age);
        }
        for (_, id) in ages.into_iter().take(count) {
            if let Some((id, flow)) = self.flows.remove(&id) {
                flow.detach(&id);
            }
        }
    }
}

pub(crate) fn handle(
    inner: &Arc<Inner>,
    flow: UdpFlow<'_>,
    payload: UdpPayload<'_>,
    reply: &Arc<dyn UdpReply>,
) {
    if !inner.handles(flow.inbound.kind) {
        return;
    }
    let (cached, lease) = take_round_flow(flow.src, &flow.dst);
    let known = cached.or_else(|| {
        let id = FlowId {
            src: flow.src,
            dst: flow.dst.clone(),
        };
        let known = inner.nat.flows.get(&id).map(|known| known.clone());
        known.map(|known| (id, known))
    });
    if let Some((id, known)) = known {
        deliver(inner, &known, payload, reply);
        lease.keep(id, known);
        return;
    }
    let Some(runtime) = inner.runtime_for(flow.inbound.kind) else {
        return;
    };
    let id = FlowId {
        src: flow.src,
        dst: flow.dst.clone(),
    };
    start_flow(inner, runtime, id, flow.meta(), payload, reply.clone());
}

pub(super) fn deliver(
    inner: &Arc<Inner>,
    flow: &Arc<Flow>,
    payload: UdpPayload<'_>,
    reply: &Arc<dyn UdpReply>,
) {
    let now = inner.nat.now();
    flow.last_active.store(now, Ordering::Relaxed);
    if let Some(ready) = flow.ready.get() {
        ready.session.update_reply(reply);
        send(inner, &ready.session, payload, &ready.target);
        return;
    }
    let mut pending = lock(&flow.pending);
    if let Some(ready) = flow.ready.get() {
        drop(pending);
        send(inner, &ready.session, payload, &ready.target);
        return;
    }
    if let Some(sniffer) = &mut pending.sniffer {
        sniffer.feed(payload.as_slice());
        if sniffer.finished() {
            flow.sniffed.notify_one();
        }
    }
    if pending.queue.len() < PENDING_CAPACITY {
        pending.queue.push_back(Queued::unsent(payload.as_slice()));
    }
}

pub(super) fn start_flow(
    inner: &Arc<Inner>,
    runtime: Arc<Runtime>,
    id: FlowId,
    meta: FlowMeta,
    payload: UdpPayload<'_>,
    reply: Arc<dyn UdpReply>,
) {
    let mut state = FlowState::new(meta);
    if !state.valid() {
        tracing::warn!(
            "[Metadata] not valid: {} --> {}",
            state.meta.src,
            state.meta.dst
        );
        return;
    }
    let mut handled = state.clone();
    if let Err(err) = pre_handle(&mut handled, &runtime.dns) {
        tracing::debug!("[Metadata PreHandle] error: {err}");
        return;
    }
    if let Some(slot) = inner.interceptor.load_full()
        && slot.0.drop_quic(&handled.intercept())
    {
        return;
    }

    let sniffer = if runtime.sniffer.enabled() {
        let mut target = state.sniff_target();
        match runtime.sniffer.sniff_udp(payload.as_slice(), &mut target) {
            UdpSniff::Done => None,
            UdpSniff::Quic(sniffer) => Some(sniffer),
        }
    } else {
        None
    };

    if inner.nat.flows.len() >= MAX_FLOWS {
        forget_round_flow();
        inner.nat.evict_oldest();
    }
    let mut queue = VecDeque::with_capacity(4);
    queue.push_back(Queued::unsent(payload.as_slice()));
    let flow = Arc::new(Flow {
        ready: OnceLock::new(),
        pending: Mutex::new(Pending { queue, sniffer }),
        sniffed: Notify::new(),
        last_active: AtomicU32::new(inner.nat.now()),
    });
    inner.nat.flows.insert(id.clone(), flow.clone());
    start_scanner(inner);

    let task = establish(inner.clone(), runtime, flow, id, state, reply);
    inner.tasks.spawn_to_end(task);
}

pub(super) async fn establish(
    inner: Arc<Inner>,
    runtime: Arc<Runtime>,
    flow: Arc<Flow>,
    id: FlowId,
    mut state: FlowState,
    reply: Arc<dyn UdpReply>,
) {
    let closing = inner.table.closing();
    let set_up = async {
        finish_sniffing(&flow, &mut state).await;
        let _ = pre_handle(&mut state, &runtime.dns);
        connect(&inner, &runtime, &flow, &id, &mut state, reply).await
    };
    match closing.run_until_cancelled(set_up).await {
        Some(Ok(())) => {}
        Some(Err(err)) => {
            tracing::debug!(
                "[UDP] {} --> {} failed: {err}",
                state.source_detail(),
                state.remote_text()
            );
            inner.nat.flows.remove(&id);
        }
        None => {
            inner.nat.flows.remove(&id);
        }
    }
}

pub(super) async fn finish_sniffing(flow: &Flow, state: &mut FlowState) {
    let waiting = lock(&flow.pending)
        .sniffer
        .as_ref()
        .is_some_and(|sniffer| !sniffer.finished());
    if waiting {
        let _ = timeout(QUIC_WAIT, flow.sniffed.notified()).await;
    }
    let sniffer = lock(&flow.pending).sniffer.take();
    if let Some(mut sniffer) = sniffer {
        if !sniffer.finished() {
            sniffer.close();
        }
        sniffer.apply(&mut state.sniff_target());
    }
}

pub(super) async fn connect(
    inner: &Arc<Inner>,
    runtime: &Arc<Runtime>,
    flow: &Arc<Flow>,
    id: &FlowId,
    state: &mut FlowState,
    reply: Arc<dyn UdpReply>,
) -> io::Result<()> {
    let live = inner.live();
    let decision = route(state, runtime, &live, Touch::Yes)
        .await
        .inspect_err(|err| {
            tracing::warn!("[UDP] Parse metadata failed: {err}");
        })?;

    let target = resolve_target(runtime, state, &decision).await?;
    let session = session_for(inner, runtime, state, &decision, &reply, &target).await?;

    if let (Some(origin), Some(ip)) = (id.dst.ip(), target.ip()) {
        session.map_target(unmap(ip), unmap(origin));
    }
    lock(&session.flows).insert(id.clone());
    session.update_reply(&reply);
    flush_pending(inner, flow, session, target).await;
    Ok(())
}

pub(super) async fn resolve_target(
    runtime: &Runtime,
    state: &FlowState,
    decision: &Decision,
) -> io::Result<Address> {
    let pure = state.pure_address();
    let Address::Domain(host, port) = &pure else {
        return Ok(pure);
    };
    let env = runtime.env_for(state);
    let cx = DialCx::new(
        &env,
        Initiator::Other,
        Some(Instant::now() + ASSOCIATE_TIMEOUT),
    );
    let own = timeout(ASSOCIATE_TIMEOUT, decision.leaf.resolve_udp(&cx, host))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
    if let Some(ip) = own {
        return Ok(Address::Socket(SocketAddr::new(ip?, *port)));
    }
    if let Some(ip) = state.dst_ip {
        return Ok(Address::Socket(SocketAddr::new(ip, *port)));
    }
    let initiator = if decision.leaf.info().kind.is_direct() {
        Initiator::Direct
    } else {
        Initiator::Other
    };
    let version = decision.leaf.info().ip_version;
    let ips = timeout(
        ASSOCIATE_TIMEOUT,
        runtime.dns_lookup(state, host, version, initiator),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    match ips.first(version) {
        Some(ip) => Ok(Address::Socket(SocketAddr::new(ip, *port))),
        None => Err(concord_common::CoreError::IpNotFound(host.to_string()).into()),
    }
}

/// Everything queued so far goes first and in order, and new arrivals keep
/// queueing until the queue is seen empty under the lock that publishes `ready`.
pub(super) async fn flush_pending(
    inner: &Arc<Inner>,
    flow: &Flow,
    session: Arc<Session>,
    target: Address,
) {
    loop {
        let batch = {
            let mut pending = lock(&flow.pending);
            if pending.queue.is_empty() {
                let _ = flow.ready.set(Ready {
                    session: session.clone(),
                    target: target.clone(),
                });
                return;
            }
            std::mem::take(&mut pending.queue)
        };
        for queued in batch {
            let mut packet = queued.into_packet();
            let bytes = packet.len() as u64;
            if send_packet(&*session.inner, &mut packet, &target)
                .await
                .is_ok()
            {
                session.registration.tracked().uploaded(bytes);
            }
        }
        session
            .last_active
            .store(inner.nat.now(), Ordering::Relaxed);
    }
}
