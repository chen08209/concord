//! A server that rejects the client's ECH config and sends `retry_configs`: the client
//! connects through one more dial, and keeps the list for its next connections.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use boring::hpke::HpkeKey;
use boring::pkey::PKey;
use boring::ssl::{NameType, SniError, SslAcceptor, SslContext, SslEchKeys, SslMethod, SslVersion};
use boring::x509::X509;
use concord_common::BoxStream;
use concord_common::sync::lock;
use concord_test_support::tcp_connect;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::time::timeout;

use super::support::{Ca, Leaf};
use crate::{ClientFingerprint, EchLookup, TlsConnector, TlsOptions};

const PUBLIC_NAME: &str = "ech.com";
const INNER_NAME: &str = "foobar.com";
static STALE_LIST: &[u8] = include_bytes!("../../../../vendor/boring/test/echconfiglist");
static SERVED_CONFIG: &[u8] = include_bytes!("../../../../vendor/boring/test/echconfig-2");
static SERVED_LIST: &[u8] = include_bytes!("../../../../vendor/boring/test/echconfiglist-2");
static SERVED_KEY: &[u8] = include_bytes!("../../../../vendor/boring/test/echkey-2");
static ROTATED_CONFIG: &[u8] = include_bytes!("../../../../vendor/boring/test/echconfig");
static ROTATED_KEY: &[u8] = include_bytes!("../../../../vendor/boring/test/echkey");

struct Server {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    ech_accepted: Arc<AtomicUsize>,
}

fn context(leaf: &Leaf) -> boring::ssl::SslAcceptorBuilder {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    builder
        .set_certificate(&X509::from_der(leaf.leaf_der().as_ref()).unwrap())
        .unwrap();
    builder
        .set_private_key(&PKey::private_key_from_der(&leaf.key_der).unwrap())
        .unwrap();
    builder
}

/// Presents the public name's certificate to a handshake that ECH did not open, and the inner
/// name's to one that it did. It holds only `SERVED_CONFIG`, so the client's stale list is
/// rejected and answered with it as the retry list.
async fn server(ca: &Ca) -> Server {
    server_holding(ca, SERVED_CONFIG, SERVED_KEY).await
}

async fn server_holding(ca: &Ca, config: &[u8], key: &[u8]) -> Server {
    let inner: SslContext = context(&ca.leaf(&[INNER_NAME])).build().into_context();
    let mut outer = context(&ca.leaf(&[PUBLIC_NAME]));
    let mut keys = SslEchKeys::builder().unwrap();
    keys.add_key(true, config, HpkeKey::dhkem_p256_sha256(key).unwrap())
        .unwrap();
    outer.set_ech_keys(&keys.build()).unwrap();
    outer.set_servername_callback(move |ssl, _| {
        if ssl.servername(NameType::HOST_NAME) == Some(INNER_NAME) {
            ssl.set_ssl_context(&inner)
                .map_err(|_| SniError::ALERT_FATAL)?;
        }
        Ok(())
    });
    let acceptor = outer.build();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let ech_accepted = Arc::new(AtomicUsize::new(0));
    let (seen, accepted) = (accepts.clone(), ech_accepted.clone());
    tokio::spawn(async move {
        while let Ok((io, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            let (acceptor, accepted) = (acceptor.clone(), accepted.clone());
            tokio::spawn(async move {
                let Ok(mut stream) = tokio_boring::accept(&acceptor, io).await else {
                    return;
                };
                if stream.ssl().ech_accepted() {
                    accepted.fetch_add(1, Ordering::SeqCst);
                }
                let _ = stream.read(&mut [0u8; 1]).await;
            });
        }
    });
    Server {
        addr,
        accepts,
        ech_accepted,
    }
}

#[derive(Debug)]
struct Lookup(Mutex<Vec<u8>>);

#[async_trait]
impl EchLookup for Lookup {
    async fn config_list(&self, _: &str) -> io::Result<Vec<u8>> {
        Ok(lock(&self.0).clone())
    }
}

async fn connect(connector: &TlsConnector, addr: SocketAddr) -> io::Result<()> {
    let dial = || async move { Ok(Box::new(tcp_connect(addr).await) as BoxStream) };
    timeout(
        Duration::from_secs(10),
        connector.connect_whole_dialing(dial, INNER_NAME),
    )
    .await
    .unwrap_or_else(|_| Err(io::Error::other("connect timed out")))
    .map(drop)
}

async fn settle(counter: &AtomicUsize, want: usize) {
    for _ in 0..200 {
        if counter.load(Ordering::SeqCst) >= want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The client starts from the stale list, fixed or through a lookup.
async fn retried_once_and_kept(fingerprint: Option<ClientFingerprint>, lookup: bool) {
    let ca = Ca::new();
    let server = server(&ca).await;
    let table = Arc::new(Lookup(Mutex::new(STALE_LIST.to_vec())));
    let options = TlsOptions {
        server_name: Some(INNER_NAME.into()),
        client_fingerprint: fingerprint,
        ech_config_list: (!lookup).then(|| STALE_LIST.to_vec()),
        ech_lookup: lookup.then(|| table.clone() as Arc<dyn EchLookup>),
        ..TlsOptions::default()
    };
    let connector = TlsConnector::new(options, ca.trust()).unwrap();

    let first = connect(&connector, server.addr).await;
    assert!(first.is_ok(), "first connect: {}", first.unwrap_err());
    settle(&server.ech_accepted, 1).await;
    assert_eq!(
        server.accepts.load(Ordering::SeqCst),
        2,
        "dials of the first connect"
    );
    assert_eq!(server.ech_accepted.load(Ordering::SeqCst), 1);

    let second = connect(&connector, server.addr).await;
    assert!(second.is_ok(), "second connect: {}", second.unwrap_err());
    settle(&server.ech_accepted, 2).await;
    assert_eq!(
        server.accepts.load(Ordering::SeqCst),
        3,
        "dials of the second connect"
    );
    assert_eq!(server.ech_accepted.load(Ordering::SeqCst), 2);

    if lookup {
        *lock(&table.0) = SERVED_LIST.to_vec();
        let third = connect(&connector, server.addr).await;
        assert!(third.is_ok(), "third connect: {}", third.unwrap_err());
        settle(&server.ech_accepted, 3).await;
        assert_eq!(
            server.accepts.load(Ordering::SeqCst),
            4,
            "dials after the lookup changed"
        );
        assert_eq!(server.ech_accepted.load(Ordering::SeqCst), 3);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rustls_retries_a_rejected_fixed_list_once_and_keeps_the_retry_list() {
    retried_once_and_kept(None, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rustls_keeps_the_retry_list_of_a_lookup_until_the_lookup_changes() {
    retried_once_and_kept(None, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boringssl_retries_a_rejected_fixed_list_once_and_keeps_the_retry_list() {
    retried_once_and_kept(Some(ClientFingerprint::Chrome), false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boringssl_keeps_the_retry_list_of_a_lookup_until_the_lookup_changes() {
    retried_once_and_kept(Some(ClientFingerprint::Chrome), true).await;
}

/// The server rotates its key after the client took its first retry list.
async fn a_second_rotation_is_retried_too(fingerprint: Option<ClientFingerprint>) {
    let ca = Ca::new();
    let before = server(&ca).await;
    let after = server_holding(&ca, ROTATED_CONFIG, ROTATED_KEY).await;
    let options = TlsOptions {
        server_name: Some(INNER_NAME.into()),
        client_fingerprint: fingerprint,
        ech_config_list: Some(STALE_LIST.to_vec()),
        ..TlsOptions::default()
    };
    let connector = TlsConnector::new(options, ca.trust()).unwrap();

    connect(&connector, before.addr).await.unwrap();
    let rotated = connect(&connector, after.addr).await;
    assert!(
        rotated.is_ok(),
        "after the rotation: {}",
        rotated.unwrap_err()
    );
    settle(&after.ech_accepted, 1).await;
    assert_eq!(after.accepts.load(Ordering::SeqCst), 2);
    assert_eq!(after.ech_accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rustls_retries_each_time_the_server_rotates_its_key() {
    a_second_rotation_is_retried_too(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boringssl_retries_each_time_the_server_rotates_its_key() {
    a_second_rotation_is_retried_too(Some(ClientFingerprint::Chrome)).await;
}

/// Reads the first flight and hangs up, so the handshake fails for a reason other than ECH.
async fn closing_server() -> Server {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let seen = accepts.clone();
    tokio::spawn(async move {
        while let Ok((mut io, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            let _ = io.read(&mut [0u8; 4096]).await;
        }
    });
    Server {
        addr,
        accepts,
        ech_accepted: Arc::new(AtomicUsize::new(0)),
    }
}

async fn fails_plainly_without_a_retry(ech_config_list: Option<Vec<u8>>) {
    let ca = Ca::new();
    let server = closing_server().await;
    let options = TlsOptions {
        server_name: Some(INNER_NAME.into()),
        client_fingerprint: Some(ClientFingerprint::Chrome),
        ech_config_list,
        ..TlsOptions::default()
    };
    let connector = TlsConnector::new(options, ca.trust()).unwrap();

    let err = connect(&connector, server.addr).await.unwrap_err();
    assert!(
        err.get_ref()
            .is_none_or(|source| !source.is::<crate::ech::BoringRejection>()),
        "{err}"
    );
    assert_eq!(
        server.accepts.load(Ordering::SeqCst),
        1,
        "no ECH retry dial"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boringssl_offering_a_list_fails_plainly_when_the_peer_hangs_up() {
    fails_plainly_without_a_retry(Some(STALE_LIST.to_vec())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boringssl_sending_grease_fails_plainly_when_the_peer_hangs_up() {
    fails_plainly_without_a_retry(None).await;
}
