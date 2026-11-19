use std::pin::pin;

use super::*;

pub(super) async fn session_for(
    inner: &Arc<Inner>,
    runtime: &Arc<Runtime>,
    state: &FlowState,
    decision: &Decision,
    reply: &Arc<dyn UdpReply>,
    target: &Address,
) -> io::Result<Arc<Session>> {
    let multi = decision.leaf.multi_destination_udp();
    let v6 = if decision.leaf.info().kind.is_direct() {
        target.ip().map(|ip| ip.is_ipv6())
    } else {
        None
    };
    let key = SessionKey {
        src: state.meta.src,
        outbound: Arc::as_ptr(&decision.leaf).cast::<()>() as usize,
        v6,
        dst: (!multi).then(|| state.meta.dst.clone()),
    };
    let slot = inner
        .nat
        .slots
        .entry(key.clone())
        .or_insert_with(|| Arc::new(OnceCell::new()))
        .clone();
    let _unfilled = Unfilled {
        slots: &inner.nat.slots,
        key: &key,
        slot: &slot,
    };
    slot.get_or_try_init(|| {
        new_session(inner, runtime, state, decision, reply, key.clone(), target)
    })
    .await
    .cloned()
}

/// Takes the slot back out when its session failed or its setup was dropped, so a later flow
/// starts a new one and the scanner sees the table empty.
struct Unfilled<'a> {
    slots: &'a DashMap<SessionKey, Arc<OnceCell<Arc<Session>>>>,
    key: &'a SessionKey,
    slot: &'a Arc<OnceCell<Arc<Session>>>,
}

impl Drop for Unfilled<'_> {
    fn drop(&mut self) {
        if !self.slot.initialized() {
            self.slots
                .remove_if(self.key, |_, current| Arc::ptr_eq(current, self.slot));
        }
    }
}

pub(super) async fn new_session(
    inner: &Arc<Inner>,
    runtime: &Arc<Runtime>,
    state: &FlowState,
    decision: &Decision,
    reply: &Arc<dyn UdpReply>,
    key: SessionKey,
    hint: &Address,
) -> io::Result<Arc<Session>> {
    let leaf = &decision.leaf;
    let closes = inner.table.closes();
    let associated = associate(inner, runtime, state, decision, hint).await?;
    tracing::info!("{}", decision.match_text(state, &inner.live()));

    let record = new_record(state, decision, server_host(&leaf.info().addr));
    let Some(registration) = inner.table.register_since(record, closes) else {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "every connection was closed while this one was set up",
        ));
    };
    let first_target = match *hint {
        Address::Socket(addr) => addr,
        Address::Domain(_, port) => {
            SocketAddr::new(state.dst_ip.unwrap_or(IpAddr::from([0, 0, 0, 0])), port)
        }
    };
    let now = inner.nat.now();
    let session = Arc::new(Session {
        key,
        inner: associated,
        registration,
        reply: ArcSwap::from_pointee(reply.clone()),
        first_target,
        restore: RwLock::new(HashMap::new()),
        has_restore: AtomicBool::new(false),
        flows: Mutex::new(HashSet::new()),
        last_active: AtomicU32::new(now),
        overflow: Mutex::new(VecDeque::new()),
        overflow_len: AtomicUsize::new(0),
        sender_running: AtomicBool::new(false),
        ended: AtomicBool::new(false),
        replies: Mutex::new(None),
    });
    if !adopt(inner, &session, reply) {
        inner
            .tasks
            .spawn_to_end(receive_loop(inner.clone(), session.clone()));
    }
    Ok(session)
}

pub(super) async fn associate(
    inner: &Arc<Inner>,
    runtime: &Runtime,
    state: &FlowState,
    decision: &Decision,
    hint: &Address,
) -> io::Result<Arc<dyn PacketSession>> {
    let leaf: &Arc<dyn Outbound> = &decision.leaf;
    let kind = leaf.info().kind;
    let deadline = Instant::now() + ASSOCIATE_TIMEOUT;
    if kind.is_direct()
        && let Err(err) = inner
            .loopback
            .check_udp_source(state.meta.src, |ip| runtime.platform.is_local_ip(ip))
    {
        return Err(err);
    }
    let env = runtime.env_for(state);
    let cx = DialCx::new(&env, Initiator::Other, Some(deadline)).with_source(state.meta.src);
    let outcome = match timeout_at(deadline, leaf.associate(&cx, hint)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::from(io::ErrorKind::TimedOut)),
    };
    match outcome {
        Ok(session) => Ok(session),
        Err(err) => {
            runtime.outbounds.note_dial_failed(
                &decision.chain,
                kind,
                concord_common::Network::Udp,
                &err,
            );
            tracing::warn!(
                "[UDP] dial {} {} --> {} error: {err}",
                decision.dial_label(),
                state.source_detail(),
                state.remote_text()
            );
            Err(err)
        }
    }
}

/// The fast path polls inline with a waker nobody listens to: a socket that is
/// ready costs no task, and one that is not hands the packet to `drain_overflow`,
/// which polls with a real waker.
pub(super) fn send(
    inner: &Arc<Inner>,
    session: &Arc<Session>,
    payload: UdpPayload<'_>,
    target: &Address,
) {
    session
        .last_active
        .store(inner.nat.now(), Ordering::Relaxed);
    if let Some(dst) = batch_target(session, target)
        && idle(session)
        && stage(inner, session, payload.as_slice(), dst)
    {
        return;
    }
    if is_staged(session) {
        flush_batch(inner);
    }
    if !idle(session) {
        enqueue(
            inner,
            session,
            [(Queued::unsent(payload.as_slice()), target.clone())],
        );
        return;
    }
    let mut packet = payload.into_packet();
    let bytes = packet.len() as u64;
    match poll_inline(|cx| session.inner.poll_send(cx, &mut packet, target)) {
        Poll::Ready(Ok(())) => session.registration.tracked().uploaded(bytes),
        Poll::Ready(Err(err)) => {
            tracing::debug!("[UDP] send to {target} failed: {err}");
            if is_gone(&err) {
                retire(inner, session);
            }
        }
        Poll::Pending => enqueue(inner, session, [(Queued::Polled(packet), target.clone())]),
    }
}

/// Polls a send once from the reader's call, with no waker. Tokio's cooperative budget does not
/// apply: a spent budget returns `Pending` as a full socket does, nothing polls this again, and
/// the datagram would go to the overflow task for no reason.
pub(super) fn poll_inline<T>(poll: impl FnMut(&mut Context<'_>) -> Poll<T>) -> Poll<T> {
    let mut cx = Context::from_waker(Waker::noop());
    pin!(tokio::task::coop::unconstrained(poll_fn(poll))).poll(&mut cx)
}

/// A session that returned Pending holds that packet's half-sent state, so no other
/// packet may be polled while the drain task has one in flight.
pub(super) fn idle(session: &Session) -> bool {
    session.overflow_len.load(Ordering::Acquire) == 0
        && !session.sender_running.load(Ordering::Acquire)
}

pub(super) fn enqueue(
    inner: &Arc<Inner>,
    session: &Arc<Session>,
    packets: impl IntoIterator<Item = (Queued, Address)>,
) {
    let mut overflow = lock(&session.overflow);
    let before = overflow.len();
    for packet in packets {
        if overflow.len() >= OVERFLOW_CAPACITY {
            break;
        }
        overflow.push_back(packet);
    }
    if overflow.len() == before {
        return;
    }
    session
        .overflow_len
        .store(overflow.len(), Ordering::Release);
    drop(overflow);
    if !session.sender_running.swap(true, Ordering::AcqRel) {
        inner
            .tasks
            .spawn_to_end(drain_overflow(inner.clone(), session.clone()));
    }
}

pub(super) async fn drain_overflow(inner: Arc<Inner>, session: Arc<Session>) {
    loop {
        let next = {
            let mut overflow = lock(&session.overflow);
            let next = overflow.pop_front();
            session
                .overflow_len
                .store(overflow.len(), Ordering::Release);
            if next.is_none() {
                session.sender_running.store(false, Ordering::Release);
            }
            next
        };
        let Some((queued, target)) = next else {
            return;
        };
        let mut packet = queued.into_packet();
        let bytes = packet.len() as u64;
        match send_packet(&*session.inner, &mut packet, &target).await {
            Ok(()) => session.registration.tracked().uploaded(bytes),
            Err(err) => {
                tracing::debug!("[UDP] send to {target} failed: {err}");
                if is_gone(&err) {
                    retire(&inner, &session);
                    return;
                }
            }
        }
    }
}

pub(super) fn is_gone(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::NotConnected
    )
}

/// The receive loop is parked on the dead session and only wakes on cancel, so the
/// next packet must not find this session in the table.
pub(super) fn retire(inner: &Inner, session: &Session) {
    forget_round_flow();
    session.close();
    end_session(inner, session);
}

/// Runs once, whichever of the session's closers gets here first.
pub(super) fn end_session(inner: &Inner, session: &Session) {
    if session.ended.swap(true, Ordering::AcqRel) {
        return;
    }
    inner.nat.drop_session(session);
}
