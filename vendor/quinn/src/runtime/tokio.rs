use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Instant,
};

use tokio::{
    io::Interest,
    time::{Sleep, sleep_until},
};

use super::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPollHelper};

/// A Quinn runtime for Tokio
#[derive(Debug)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn new_timer(&self, t: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(sleep_until(t.into()))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(&self, sock: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        gro_key::hold();
        Ok(Arc::new(UdpSocket {
            inner: udp::UdpSocketState::new((&sock).into())?,
            io: tokio::net::UdpSocket::from_std(sock)?,
        }))
    }

    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
}

// Concord: `UdpSocketState::new` turns on UDP_GRO, and Linux counts every such socket in its UDP
// encapsulation static keys (`udp_tunnel_encap_enable`, released in `udp(v6)_destroy_sock`). A key's
// count moving between zero and one rewrites kernel text and interrupts every CPU, so one short-lived
// socket per connection paid that twice per connection. A GRO socket held for the process keeps the
// count above zero; it is connected to itself, so nothing else can reach it.
#[cfg(any(target_os = "linux", target_os = "android"))]
mod gro_key {
    use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
    use std::sync::OnceLock;

    static HELD: OnceLock<Option<UdpSocket>> = OnceLock::new();

    pub(super) fn hold() {
        HELD.get_or_init(open);
    }

    fn open() -> Option<UdpSocket> {
        let sock = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))
            .or_else(|_| UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)))
            .ok()?;
        sock.connect(sock.local_addr().ok()?).ok()?;
        udp::UdpSocketState::new((&sock).into()).ok()?;
        Some(sock)
    }
}

impl AsyncTimer for Sleep {
    fn reset(self: Pin<&mut Self>, t: Instant) {
        Self::reset(self, t.into())
    }
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        Future::poll(self, cx)
    }
}

#[derive(Debug)]
struct UdpSocket {
    io: tokio::net::UdpSocket,
    inner: udp::UdpSocketState,
}

impl AsyncUdpSocket for UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn super::UdpPoller>> {
        Box::pin(UdpPollHelper::new(move || {
            let socket = self.clone();
            async move { socket.io.writable().await }
        }))
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.inner.send((&self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(res) = self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}
