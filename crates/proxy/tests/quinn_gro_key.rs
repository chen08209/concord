//! The first QUIC socket a process wraps leaves one GRO socket held for the process, connected to itself.
#![cfg(target_os = "linux")]
#![allow(
    clippy::disallowed_methods,
    reason = "the test wraps loopback sockets it binds directly"
)]

use std::collections::HashSet;
use std::net::{Ipv4Addr, UdpSocket};

use quinn::{Runtime, TokioRuntime};

fn socket_inodes() -> HashSet<String> {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
        .filter_map(|target| {
            let inode = target
                .to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')?;
            Some(inode.to_owned())
        })
        .collect()
}

/// This process's UDP sockets whose remote address is their own local address.
fn self_connected() -> usize {
    let ours = socket_inodes();
    ["/proc/net/udp", "/proc/net/udp6"]
        .iter()
        .filter_map(|table| std::fs::read_to_string(table).ok())
        .flat_map(|table| table.lines().skip(1).map(str::to_owned).collect::<Vec<_>>())
        .filter(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            fields.len() > 9 && fields[1] == fields[2] && ours.contains(fields[9])
        })
        .count()
}

#[tokio::test]
async fn wrapping_sockets_holds_exactly_one_self_connected_socket() {
    assert_eq!(self_connected(), 0);
    for _ in 0..3 {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        drop(TokioRuntime.wrap_udp_socket(socket).unwrap());
    }
    assert_eq!(self_connected(), 1);
}
