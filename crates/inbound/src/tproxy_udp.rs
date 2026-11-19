use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{
    Address, InboundInfo, InboundKind, PacketBuf, Tasks, UdpFlow, UdpPayload, UdpReply,
};
use tokio::net::UdpSocket;
use tokio::task::coop::consume_budget;
use tokio_util::sync::CancellationToken;

use crate::accept::next_backoff;
use crate::ctx::{ListenCtx, unmap_addr};
use crate::transparent::Transparent;

const DRAIN_BATCH: usize = 64;

type Pair = (SocketAddr, SocketAddr);

/// The sockets that answer a client as the server it addressed. Each is bound to that
/// server's address and connected to the client, so the client's later datagrams for the
/// same server reach it rather than the listener.
struct Table {
    ctx: Arc<ListenCtx>,
    transparent: Arc<dyn Transparent>,
    cancel: CancellationToken,
    tasks: Tasks,
    foreign: Mutex<HashMap<Pair, Arc<Foreign>>>,
}

struct Foreign {
    socket: UdpSocket,
    closed: CancellationToken,
}

impl Table {
    fn foreign_for(
        self: &Arc<Self>,
        from: SocketAddr,
        client: SocketAddr,
    ) -> io::Result<Arc<Foreign>> {
        let key = (from, client);
        let mut foreign = lock(&self.foreign);
        if let Some(held) = foreign.get(&key) {
            return Ok(held.clone());
        }
        let socket = UdpSocket::from_std(self.transparent.reply_socket(from, client)?)?;
        let held = Arc::new(Foreign {
            socket,
            closed: self.cancel.child_token(),
        });
        foreign.insert(key, held.clone());
        drop(foreign);
        self.tasks.spawn(read_back(self.clone(), key, held.clone()));
        Ok(held)
    }

    /// mihomo closes these with the client's session too, not only once they idle.
    fn close_client(&self, client: SocketAddr) {
        let mut foreign = lock(&self.foreign);
        foreign.retain(|(_, to), held| {
            let keep = *to != client;
            if !keep {
                held.closed.cancel();
            }
            keep
        });
    }

    fn forget(&self, key: Pair, held: &Arc<Foreign>) {
        let mut foreign = lock(&self.foreign);
        if foreign
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, held))
        {
            foreign.remove(&key);
        }
    }

    fn deliver(&self, local: Option<SocketAddr>, packet: PacketBuf, reply: &Arc<Reply>, dscp: u8) {
        let inbound = InboundInfo {
            kind: InboundKind::TProxy,
            name: self.ctx.name.clone(),
            addr: local,
            user: None,
            host: false,
            user_agent: None,
        };
        let flow = UdpFlow {
            inbound: &inbound,
            src: reply.client,
            dst: Address::from(reply.dst),
            dscp,
        };
        let reply: Arc<dyn UdpReply> = reply.clone();
        self.ctx
            .shared
            .handler()
            .handle_udp(flow, UdpPayload::Owned(packet), &reply);
    }
}

struct Reply {
    table: Arc<Table>,
    client: SocketAddr,
    dst: SocketAddr,
}

impl UdpReply for Reply {
    fn poll_write_back(
        &self,
        cx: &mut Context<'_>,
        payload: &[u8],
        from: &Address,
    ) -> Poll<io::Result<()>> {
        let from = match from {
            Address::Socket(addr) => unmap_addr(*addr),
            Address::Domain(..) => self.dst,
        };
        let foreign = match self.table.foreign_for(from, self.client) {
            Ok(foreign) => foreign,
            Err(err) => return Poll::Ready(Err(err)),
        };
        foreign.socket.poll_send(cx, payload).map_ok(drop)
    }

    fn session_ended(&self) {
        self.table.close_client(self.client);
    }
}

async fn read_back(table: Arc<Table>, key: Pair, held: Arc<Foreign>) {
    let (from, client) = key;
    let reply = Arc::new(Reply {
        table: table.clone(),
        client,
        dst: from,
    });
    let local = held.socket.local_addr().ok();
    let mut delay = Duration::ZERO;
    loop {
        let mut packet = PacketBuf::take();
        let received = tokio::select! {
            () = held.closed.cancelled() => break,
            received = held.socket.recv(packet.spare_mut()) => received,
        };
        match received {
            Ok(len) => {
                delay = Duration::ZERO;
                packet.advance(len);
                table.deliver(local, packet, &reply, 0);
            }
            Err(_) => {
                delay = next_backoff(delay);
                tokio::time::sleep(delay).await;
            }
        }
    }
    table.forget(key, &held);
}

pub(crate) async fn run(
    ctx: Arc<ListenCtx>,
    socket: UdpSocket,
    transparent: Arc<dyn Transparent>,
    cancel: CancellationToken,
    tasks: Tasks,
) {
    let local = socket.local_addr().ok();
    let table = Arc::new(Table {
        ctx,
        transparent,
        cancel: cancel.clone(),
        tasks,
        foreign: Mutex::new(HashMap::new()),
    });
    let mut delay = Duration::ZERO;
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            ready = socket.readable() => {
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
            match table.transparent.recv_udp(&socket, packet.spare_mut()) {
                Ok(datagram) => {
                    packet.advance(datagram.len);
                    let (client, dst) = (unmap_addr(datagram.src), unmap_addr(datagram.dst));
                    let reply = Arc::new(Reply {
                        table: table.clone(),
                        client,
                        dst,
                    });
                    table.deliver(local, packet, &reply, datagram.dscp);
                    delay = Duration::ZERO;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == io::ErrorKind::InvalidData => {}
                Err(_) => {
                    delay = next_backoff(delay);
                    tokio::time::sleep(delay).await;
                    break;
                }
            }
        }
    }
}
