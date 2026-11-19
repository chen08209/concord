use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use concord_common::Tasks;
use concord_common::addr::unmap;
use concord_common::sync::lock;
use concord_common::{Address, InboundInfo, InboundKind, PacketBuf, UdpFlow, UdpPayload, UdpReply};
use tokio::net::UdpSocket;
use tokio::task::coop::consume_budget;
use tokio_util::sync::CancellationToken;

use crate::accept::next_backoff;
use crate::ctx::{ListenCtx, unmap_addr};
use crate::socks5::{MAX_UDP_HEADER, Writer, addr_len, decode_udp, write_addr};

const DRAIN_BATCH: usize = 64;

/// The one UDP socket of a listener. Many flows write back through it, and a
/// tokio socket keeps only the latest waker per direction, so a send that would
/// block parks its waker here and a single task wakes them all.
pub(crate) struct UdpOut {
    socket: Arc<UdpSocket>,
    v6: bool,
    waiters: Mutex<Vec<Waker>>,
    tasks: Tasks,
}

impl UdpOut {
    pub(crate) fn new(socket: Arc<UdpSocket>, tasks: Tasks) -> Arc<Self> {
        let v6 = socket.local_addr().is_ok_and(|addr| addr.is_ipv6());
        Arc::new(UdpOut {
            socket,
            v6,
            waiters: Mutex::new(Vec::new()),
            tasks,
        })
    }

    fn poll_send(
        self: &Arc<Self>,
        cx: &mut Context<'_>,
        data: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<()>> {
        let target = match (self.v6, target) {
            (true, SocketAddr::V4(v4)) => {
                SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
            }
            (_, target) => target,
        };
        match self.socket.try_send_to(data, target) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                self.park(cx.waker());
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn park(self: &Arc<Self>, waker: &Waker) {
        let mut waiters = lock(&self.waiters);
        let first = waiters.is_empty();
        if !waiters.iter().any(|queued| queued.will_wake(waker)) {
            waiters.push(waker.clone());
        }
        drop(waiters);
        if first {
            let out = self.clone();
            self.tasks.spawn(async move {
                let _ = out.socket.writable().await;
                let woken = std::mem::take(&mut *lock(&out.waiters));
                woken.into_iter().for_each(Waker::wake);
            });
        }
    }
}

/// Holds the socket weakly: a session that outlives its listener must not keep
/// the port bound, and its next datagram arrives through the new listener.
struct SocksUdpReply {
    out: Weak<UdpOut>,
    client: SocketAddr,
}

impl UdpReply for SocksUdpReply {
    fn poll_write_back(
        &self,
        cx: &mut Context<'_>,
        payload: &[u8],
        from: &Address,
    ) -> Poll<io::Result<()>> {
        let Some(out) = self.out.upgrade() else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        let header = match addr_len(from) {
            Ok(len) => 3 + len,
            Err(err) => return Poll::Ready(Err(err)),
        };
        let mut packet = PacketBuf::with_headroom(header.min(MAX_UDP_HEADER));
        packet.extend_from_slice(payload);
        let mut writer = Writer::new(packet.prepend(header));
        writer.put(&[0, 0, 0]);
        write_addr(&mut writer, from);
        out.poll_send(cx, packet.as_slice(), self.client)
    }
}

struct Assoc {
    count: usize,
    user: Option<Arc<str>>,
    replies: HashMap<SocketAddr, Arc<SocksUdpReply>>,
}

/// Which client hosts hold a SOCKS5 UDP association, kept alive by their TCP
/// control connection. A datagram from any other host is dropped.
#[derive(Default)]
pub(crate) struct Associations {
    hosts: Mutex<HashMap<IpAddr, Assoc>>,
}

pub(crate) struct AssocGuard {
    assoc: Arc<Associations>,
    ip: IpAddr,
}

impl Associations {
    pub(crate) fn register(self: &Arc<Self>, ip: IpAddr, user: Option<Arc<str>>) -> AssocGuard {
        let ip = unmap(ip);
        let mut hosts = lock(&self.hosts);
        let entry = hosts.entry(ip).or_insert_with(|| Assoc {
            count: 0,
            user: None,
            replies: HashMap::new(),
        });
        entry.count += 1;
        entry.user = user;
        AssocGuard {
            assoc: self.clone(),
            ip,
        }
    }

    fn reply_for(
        &self,
        out: &Arc<UdpOut>,
        client: SocketAddr,
    ) -> Option<(Arc<SocksUdpReply>, Option<Arc<str>>)> {
        let mut hosts = lock(&self.hosts);
        let entry = hosts.get_mut(&unmap(client.ip()))?;
        let reply = entry
            .replies
            .entry(client)
            .or_insert_with(|| {
                Arc::new(SocksUdpReply {
                    out: Arc::downgrade(out),
                    client,
                })
            })
            .clone();
        Some((reply, entry.user.clone()))
    }
}

impl Drop for AssocGuard {
    fn drop(&mut self) {
        let mut hosts = lock(&self.assoc.hosts);
        if let Some(entry) = hosts.get_mut(&self.ip) {
            entry.count -= 1;
            if entry.count == 0 {
                hosts.remove(&self.ip);
            }
        }
    }
}

pub(crate) async fn run(ctx: Arc<ListenCtx>, out: Arc<UdpOut>, cancel: CancellationToken) {
    let local = out.socket.local_addr().ok();
    let mut delay = Duration::ZERO;
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            ready = out.socket.readable() => {
                if ready.is_err() {
                    delay = next_backoff(delay);
                    tokio::time::sleep(delay).await;
                    continue;
                }
            }
        }
        for _ in 0..DRAIN_BATCH {
            // Readiness and a `try_` receive take none of tokio's budget, so a socket that
            // keeps reporting ready would hold the worker and any task woken into its slot.
            consume_budget().await;
            let mut packet = PacketBuf::take();
            match out.socket.try_recv_from(packet.spare_mut()) {
                Ok((len, from)) => {
                    packet.advance(len);
                    dispatch(&ctx, &out, local, packet, from);
                    delay = Duration::ZERO;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    delay = next_backoff(delay);
                    tokio::time::sleep(delay).await;
                    break;
                }
            }
        }
    }
}

fn dispatch(
    ctx: &ListenCtx,
    out: &Arc<UdpOut>,
    local: Option<SocketAddr>,
    mut packet: PacketBuf,
    from: SocketAddr,
) {
    let Some((dst, header)) = decode_udp(packet.as_slice()) else {
        return;
    };
    let Some((reply, user)) = ctx.assoc.reply_for(out, from) else {
        return;
    };
    packet.consume(header);
    let inbound = InboundInfo {
        kind: InboundKind::Socks5,
        name: ctx.name.clone(),
        addr: local,
        user,
        host: false,
        user_agent: None,
    };
    let flow = UdpFlow {
        inbound: &inbound,
        src: unmap_addr(from),
        dst,
        dscp: 0,
    };
    let reply: Arc<dyn UdpReply> = reply;
    ctx.shared
        .handler()
        .handle_udp(flow, UdpPayload::Owned(packet), &reply);
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "test sockets bind loopback directly"
)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    use super::*;

    #[derive(Default)]
    struct Counter(AtomicUsize);

    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn out() -> Arc<UdpOut> {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        UdpOut::new(Arc::new(socket), Tasks::default())
    }

    #[derive(Default)]
    struct Count(AtomicUsize);

    impl concord_common::FlowHandler for Count {
        fn handle_tcp(&self, _meta: concord_common::FlowMeta, _stream: concord_common::BoxStream) {}

        fn handle_udp(
            &self,
            _flow: UdpFlow<'_>,
            _payload: UdpPayload<'_>,
            _reply: &Arc<dyn UdpReply>,
        ) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn a_socket_that_stays_readable_lets_other_tasks_run() {
        const QUEUED: usize = 1000;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket2::SockRef::from(&socket)
            .set_recv_buffer_size(8 << 20)
            .unwrap();
        let listen = socket.local_addr().unwrap();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let datagram = [0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 0xab];
        for _ in 0..QUEUED {
            client.send_to(&datagram, listen).unwrap();
        }

        let count = Arc::new(Count::default());
        let shared = Arc::new(crate::ctx::Shared::new(crate::spec::Policy::from_spec(
            &crate::spec::ListenSpec::default(),
        )));
        shared.update(
            count.clone(),
            crate::spec::Policy::from_spec(&crate::spec::ListenSpec::default()),
        );
        let assoc = Arc::new(Associations::default());
        let _guard = assoc.register(client.local_addr().unwrap().ip(), None);
        let ctx = Arc::new(ListenCtx {
            shared,
            name: Arc::from("test"),
            assoc,
        });
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run(
            ctx,
            UdpOut::new(Arc::new(socket), Tasks::default()),
            cancel.clone(),
        ));

        let mut seen = 0;
        for _ in 0..10_000 {
            tokio::task::yield_now().await;
            seen = count.0.load(Ordering::SeqCst);
            if seen > 0 {
                break;
            }
        }
        cancel.cancel();
        task.await.unwrap();
        assert!(seen > 0, "the listener never received");
        assert!(
            seen < QUEUED / 2,
            "the listener took {seen} of {QUEUED} queued datagrams in one poll"
        );
    }

    #[tokio::test]
    async fn every_parked_sender_is_woken_once_the_socket_is_writable() {
        let out = out().await;
        let (first, second) = (Arc::new(Counter::default()), Arc::new(Counter::default()));
        let (first_waker, second_waker) = (Waker::from(first.clone()), Waker::from(second.clone()));
        out.park(&first_waker);
        out.park(&first_waker);
        out.park(&second_waker);
        for _ in 0..100 {
            if first.0.load(Ordering::SeqCst) > 0 && second.0.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(first.0.load(Ordering::SeqCst), 1);
        assert_eq!(second.0.load(Ordering::SeqCst), 1);
        assert!(lock(&out.waiters).is_empty());
    }

    #[tokio::test]
    async fn a_sender_that_parks_again_after_a_wake_is_woken_again() {
        let out = out().await;
        let counter = Arc::new(Counter::default());
        let waker = Waker::from(counter.clone());
        for round in 1..=2 {
            out.park(&waker);
            for _ in 0..100 {
                if counter.0.load(Ordering::SeqCst) >= round {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(counter.0.load(Ordering::SeqCst), round);
        }
    }
}
