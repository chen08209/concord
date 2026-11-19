mod body;
mod forward;
mod head;
mod target;

use std::io;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::BytesMut;
use concord_common::{InboundKind, PeekedStream, Stream};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::timeout;

use self::forward::Upstreams;
use self::head::{Headers, RequestHead, read_request_head};
use self::target::parse_authority;
use crate::ctx::{Client, HANDSHAKE_TIMEOUT, ListenCtx, Peer, dst_address};
use crate::spec::{Authenticator, HostCredential};

pub(crate) struct Session<S> {
    rd: ReadHalf<S>,
    wr: WriteHalf<S>,
    rbuf: BytesMut,
    upstreams: Upstreams,
    client: Client,
}

pub(crate) enum Next {
    Continue,
    Close,
}

pub(crate) fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        407 => "Proxy Authentication Required",
        502 => "Bad Gateway",
        _ => "Status",
    }
}

fn connection_headers(out: &mut Vec<u8>, close: bool) {
    out.extend_from_slice(if close {
        b"Connection: close\r\n"
    } else {
        b"Proxy-Connection: keep-alive\r\nConnection: keep-alive\r\nKeep-Alive: timeout=4\r\n"
    });
}

fn status_response(minor: u8, status: u16, keep_alive: bool) -> Vec<u8> {
    let mut out = format!("HTTP/1.{minor} {status} {}\r\n", status_text(status)).into_bytes();
    if status == 407 {
        out.extend_from_slice(b"Proxy-Authenticate: Basic\r\n");
    }
    out.extend_from_slice(b"Content-Length: 0\r\n");
    connection_headers(&mut out, !keep_alive);
    out.extend_from_slice(b"\r\n");
    out
}

enum Verdict {
    Granted,
    Refused(u16),
}

/// The user is the decoded Basic username even when no authenticator is
/// configured, so `in-user` is set whenever a client offers credentials.
fn authenticate(
    headers: &Headers,
    auth: Option<&Authenticator>,
    host: Option<&HostCredential>,
) -> (Verdict, Client) {
    let credential = headers
        .get("Proxy-Authorization")
        .and_then(|value| {
            let (scheme, rest) = value.split_at_checked(6)?;
            scheme.eq_ignore_ascii_case(b"Basic ").then_some(rest)
        })
        .unwrap_or_default();
    if credential.is_empty() && auth.is_some() {
        return (Verdict::Refused(407), Client::default());
    }
    let decoded = STANDARD
        .decode(credential)
        .ok()
        .map(|plain| String::from_utf8_lossy(&plain).into_owned())
        .and_then(|plain| {
            plain
                .split_once(':')
                .map(|(user, pass)| (user.to_owned(), pass.to_owned()))
        });
    let (user, pass) = decoded.clone().unwrap_or_default();
    if decoded.is_some() && host.is_some_and(|host| host.matches(&user, &pass)) {
        return (Verdict::Granted, Client::host());
    }
    let granted = match auth {
        None => true,
        Some(auth) => decoded.is_some() && auth.verify(&user, &pass),
    };
    if granted {
        (Verdict::Granted, Client::named(&user))
    } else {
        (Verdict::Refused(403), Client::named(&user))
    }
}

pub(crate) async fn serve<S: Stream>(
    ctx: Arc<ListenCtx>,
    stream: S,
    peer: Peer,
    auth: Option<&Authenticator>,
    host: Option<&HostCredential>,
) {
    let (rd, wr) = tokio::io::split(stream);
    let mut session = Session {
        rd,
        wr,
        rbuf: BytesMut::new(),
        upstreams: Upstreams::new(ctx.clone(), peer),
        client: Client::default(),
    };
    let mut trusted = auth.is_none();
    let mut served = false;
    let mut last_client = Client::default();

    loop {
        let read = read_request_head(&mut session.rd, &mut session.rbuf);
        let head = if served {
            read.await
        } else {
            timeout(HANDSHAKE_TIMEOUT, read)
                .await
                .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
        };
        let head = match head {
            Ok(Some(head)) => head,
            _ => return,
        };
        let keep_alive = head
            .headers
            .get("Proxy-Connection")
            .is_some_and(|value| value.trim_ascii().eq_ignore_ascii_case(b"keep-alive"));

        let (verdict, client) = authenticate(&head.headers, auth, host);
        let refusal = match verdict {
            Verdict::Granted => {
                trusted = true;
                None
            }
            Verdict::Refused(status) => Some(status),
        };
        session.client = client.clone();

        if !trusted {
            let status = refusal.unwrap_or(403);
            let reply = status_response(head.minor, status, keep_alive);
            if session.wr.write_all(&reply).await.is_err() || !keep_alive {
                return;
            }
            continue;
        }

        if head.method == "CONNECT" {
            connect(&ctx, session, peer, head).await;
            return;
        }
        if head.headers.has_token("Connection", "upgrade") {
            let _ = session.upgrade(head).await;
            return;
        }
        if client != last_client {
            session.upstreams.clear();
            last_client = client;
        }
        served = true;
        match session.forward(head, keep_alive).await {
            Ok(Next::Continue) => {}
            _ => return,
        }
    }
}

async fn connect<S: Stream>(
    ctx: &ListenCtx,
    mut session: Session<S>,
    peer: Peer,
    head: RequestHead,
) {
    let Some((host, port)) = parse_authority(&head.target) else {
        return;
    };
    let reply = format!("HTTP/1.{} 200 Connection established\r\n\r\n", head.minor);
    if session.wr.write_all(reply.as_bytes()).await.is_err() {
        return;
    }
    let Session {
        rd,
        wr,
        rbuf,
        client,
        ..
    } = session;
    let stream = rd.unsplit(wr);
    let mut meta = ctx.tcp_meta(
        InboundKind::Https,
        &peer,
        dst_address(&host, port.unwrap_or(80)),
        client,
    );
    meta.inbound.user_agent = head
        .headers
        .get("User-Agent")
        .and_then(|agent| std::str::from_utf8(agent).ok())
        .map(Arc::from);
    if rbuf.is_empty() {
        ctx.hand_off(meta, Box::new(stream));
    } else {
        ctx.hand_off(meta, Box::new(PeekedStream::new(rbuf.to_vec(), stream)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Headers {
        let mut headers = Headers::default();
        for (name, value) in pairs {
            headers.push(name, value.as_bytes());
        }
        headers
    }

    fn basic(user: &str, pass: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{user}:{pass}")))
    }

    #[test]
    fn credentials_are_decoded_even_without_an_authenticator() {
        let h = headers(&[("Proxy-Authorization", &basic("alice", "pw"))]);
        let (verdict, client) = authenticate(&h, None, None);
        assert!(matches!(verdict, Verdict::Granted));
        assert_eq!(client, Client::named("alice"));
        let (verdict, client) = authenticate(&headers(&[]), None, None);
        assert!(matches!(verdict, Verdict::Granted));
        assert_eq!(client, Client::default());
    }

    #[test]
    fn a_missing_credential_is_407_and_a_wrong_one_is_403() {
        let spec = crate::ListenSpec {
            authentication: vec![("alice".into(), "pw".into())],
            ..Default::default()
        };
        let policy = crate::spec::Policy::from_spec(&spec);
        let auth = policy.authenticator(std::net::Ipv4Addr::LOCALHOST.into());
        let (verdict, _) = authenticate(&headers(&[]), auth, None);
        assert!(matches!(verdict, Verdict::Refused(407)));
        let h = headers(&[("Proxy-Authorization", &basic("alice", "bad"))]);
        assert!(matches!(
            authenticate(&h, auth, None).0,
            Verdict::Refused(403)
        ));
        let h = headers(&[("Proxy-Authorization", "Basic !!!")]);
        assert!(matches!(
            authenticate(&h, auth, None).0,
            Verdict::Refused(403)
        ));
        let h = headers(&[("proxy-authorization", &basic("alice", "pw").to_lowercase())]);
        assert!(matches!(
            authenticate(&h, auth, None).0,
            Verdict::Refused(403)
        ));
        let h = headers(&[(
            "Proxy-Authorization",
            &basic("alice", "pw").replace("Basic", "bAsIc"),
        )]);
        assert!(matches!(authenticate(&h, auth, None).0, Verdict::Granted));
    }

    fn host_policy(users: &[(&str, &str)]) -> crate::spec::Policy {
        crate::spec::Policy::from_spec(&crate::ListenSpec {
            authentication: users
                .iter()
                .map(|(user, pass)| ((*user).into(), (*pass).into()))
                .collect(),
            host_credential: Some(("host".into(), "secret".into())),
            ..Default::default()
        })
    }

    #[test]
    fn the_host_credential_passes_with_or_without_authentication_and_names_no_user() {
        let loopback = std::net::Ipv4Addr::LOCALHOST.into();
        let h = headers(&[("Proxy-Authorization", &basic("host", "secret"))]);
        for policy in [host_policy(&[]), host_policy(&[("alice", "pw")])] {
            let (auth, host) = (policy.authenticator(loopback), policy.host(loopback));
            let (verdict, client) = authenticate(&h, auth, host);
            assert!(matches!(verdict, Verdict::Granted));
            assert_eq!(client, Client::host());
        }
    }

    #[test]
    fn a_wrong_or_remote_host_credential_is_an_ordinary_credential() {
        let loopback = std::net::Ipv4Addr::LOCALHOST.into();
        let lan = std::net::Ipv4Addr::new(192, 168, 1, 2).into();
        let wrong = headers(&[("Proxy-Authorization", &basic("host", "guess"))]);
        let right = headers(&[("Proxy-Authorization", &basic("host", "secret"))]);

        let open = host_policy(&[]);
        let (verdict, client) = authenticate(&wrong, None, open.host(loopback));
        assert!(matches!(verdict, Verdict::Granted));
        assert_eq!(client, Client::named("host"));
        let (verdict, client) = authenticate(&right, None, open.host(lan));
        assert!(matches!(verdict, Verdict::Granted));
        assert_eq!(client, Client::named("host"));

        let closed = host_policy(&[("alice", "pw")]);
        let auth = closed.authenticator(loopback);
        let (verdict, client) = authenticate(&wrong, auth, closed.host(loopback));
        assert!(matches!(verdict, Verdict::Refused(403)));
        assert!(!client.host);
        let (verdict, client) = authenticate(&right, closed.authenticator(lan), closed.host(lan));
        assert!(matches!(verdict, Verdict::Refused(403)));
        assert!(!client.host);
        let (verdict, _) = authenticate(&headers(&[]), auth, closed.host(loopback));
        assert!(matches!(verdict, Verdict::Refused(407)));
    }
}
