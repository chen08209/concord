//! What MITM costs. The origin serves HTTPS and plain HTTP with a certificate from a CA the
//! core also decrypts with, so one client trusts both ends. mihomo has no MITM: these cases
//! compare Concord builds, and Concord's tiers with each other.

use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::load::{self, Ctx, Metrics, Windows};
use crate::origin::Ports;
use crate::socks;

pub const HOST: &str = "origin.bench";
static BODY: [u8; 64] = [0x42; 64];

/// The CA as the core reads it from `<home>/mitm`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Authority {
    pub cert: String,
    pub key: String,
    /// The origin's own certificate, so a client can tell a decrypted connection from a relayed one.
    pub origin_leaf: Vec<u8>,
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// A fresh CA, and the origin's TLS config with a certificate it signed.
pub fn authority() -> Result<(Authority, Arc<rustls::ServerConfig>), String> {
    let ca_key = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(DnType::CommonName, "concord-bench");
    let ca = params.self_signed(&ca_key).map_err(|e| e.to_string())?;
    let (cert, key) = (ca.pem(), ca_key.serialize_pem());
    let issuer = Issuer::new(params, ca_key);
    let leaf_key = KeyPair::generate().map_err(|e| e.to_string())?;
    let leaf = CertificateParams::new(vec![HOST.to_string()])
        .and_then(|params| params.signed_by(&leaf_key, &issuer))
        .map_err(|e| e.to_string())?;
    let authority = Authority {
        cert,
        key,
        origin_leaf: leaf.der().to_vec(),
    };
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone(), ca.der().clone()], key)
        .map_err(|e| e.to_string())?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok((authority, Arc::new(tls)))
}

/// The client's TLS configs, trusting only the bench CA.
#[derive(Clone)]
pub struct Clients {
    h1: Arc<rustls::ClientConfig>,
    h2: Arc<rustls::ClientConfig>,
    origin_leaf: Arc<[u8]>,
}

impl Clients {
    pub fn new(authority: &Authority) -> Result<Clients, String> {
        let mut roots = rustls::RootCertStore::empty();
        let ca =
            CertificateDer::from_pem_slice(authority.cert.as_bytes()).map_err(|e| e.to_string())?;
        roots.add(ca).map_err(|e| e.to_string())?;
        let config = |alpn: &[u8]| -> Result<Arc<rustls::ClientConfig>, String> {
            let mut config = rustls::ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_root_certificates(roots.clone())
                .with_no_client_auth();
            config.alpn_protocols = vec![alpn.to_vec()];
            Ok(Arc::new(config))
        };
        Ok(Clients {
            h1: config(b"http/1.1")?,
            h2: config(b"h2")?,
            origin_leaf: authority.origin_leaf.as_slice().into(),
        })
    }
}

/// Writes the CA, and the script `mitm-script` runs, where the core looks for them.
pub fn provision(home: &Path, authority: &Authority) -> io::Result<()> {
    let dir = home.join("mitm");
    std::fs::create_dir_all(dir.join("resources"))?;
    std::fs::write(dir.join("ca.crt"), &authority.cert)?;
    std::fs::write(dir.join("ca.key"), &authority.key)?;
    std::fs::write(dir.join("resources/bench.js"), "$done({});\n")
}

/// `mitm-route`'s routing rules ahead of the shared profile's. `mitm-modules` rejects all
/// but the origin, so the modules' resources fail at once rather than leave the machine.
pub fn profile(base: String, case: &str, origin: IpAddr, rules: usize) -> String {
    let mut routing = String::new();
    match case {
        "mitm-route" => {
            for i in 0..rules {
                let _ = writeln!(routing, "  - URL-REGEX,^https?://n{i}\\.bench/,REJECT");
            }
        }
        "mitm-modules" => {
            let _ = writeln!(routing, "  - IP-CIDR,{origin}/32,DIRECT,no-resolve");
            return base
                .replacen("rules:\n", &format!("rules:\n{routing}"), 1)
                .replace("  - MATCH,DIRECT\n", "  - MATCH,REJECT\n");
        }
        _ => return base,
    }
    base.replacen("rules:\n", &format!("rules:\n{routing}"), 1)
}

include!(concat!(env!("OUT_DIR"), "/corpus.rs"));

/// The case's mitm section. Concord takes it from the overlay, as the app sets it, not
/// from the profile. Hostname entries carry the origin's ports, so the echo port the
/// readiness probe uses is not intercepted.
pub fn section(case: &str, origin: IpAddr, ports: Ports, rules: usize) -> Option<Value> {
    let hostname = match case {
        "mitm-off" => return None,
        "mitm-pass" => vec!["other.bench".to_string()],
        _ => vec![
            format!("{origin}:{}", ports.https),
            format!("{origin}:{}", ports.http),
            format!("{HOST}:{}", ports.https),
        ],
    };
    let mut section = json!({
        "enable": true,
        "h2": true,
        "skip-server-cert-verify": true,
        "hostname": hostname,
    });
    match case {
        "mitm-rewrite" => {
            let lines: Vec<String> = (0..rules)
                .map(|i| format!("^https?://n{i}\\.bench/ _ reject"))
                .collect();
            section["url-rewrite"] = json!(lines);
        }
        "mitm-script" => {
            section["script"] =
                json!(["bench = type=http-request,pattern=^https?://,script-path=bench.js"]);
        }
        "mitm-modules" => {
            let modules = CORPUS
                .iter()
                .map(|(name, text)| json!({"name": name, "text": text, "enabled": true}));
            section["modules"] = Value::Array(modules.collect());
        }
        _ => {}
    }
    Some(section)
}

pub async fn serve_https(stream: TcpStream, tls: Arc<rustls::ServerConfig>) -> io::Result<()> {
    let tls = tokio_rustls::TlsAcceptor::from(tls).accept(stream).await?;
    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
    serve_http(tls, h2).await
}

pub async fn serve_http<S>(io: S, h2: bool) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    let service = hyper::service::service_fn(answer);
    let served = if h2 {
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(io, service)
            .await
    } else {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .await
    };
    served.map_err(io::Error::other)
}

async fn answer(
    request: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    request.into_body().collect().await?;
    Ok(Response::new(Full::new(Bytes::from_static(&BODY))))
}

#[derive(Clone, Copy)]
pub enum Wire {
    H1,
    H2,
    Plain,
}

enum Sender {
    H1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    H2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}

/// One client connection through the core; dropping it closes the connection.
pub struct Session {
    sender: Sender,
    path: String,
    host: String,
    /// Whether the core answered the handshake with a certificate of its own; `None` over plain HTTP.
    pub decrypted: Option<bool>,
}

pub async fn open(ctx: &Ctx, wire: Wire) -> io::Result<Session> {
    let port = match wire {
        Wire::Plain => ctx.ports.http,
        Wire::H1 | Wire::H2 => ctx.ports.https,
    };
    let stream = socks::connect(ctx.entry, SocketAddr::new(ctx.origin, port)).await?;
    let host = format!("{HOST}:{port}");
    let clients = ctx.tls.as_ref();
    let missing = || io::Error::other("the origin gave no CA");
    if let Wire::Plain = wire {
        let sender = h1(stream).await?;
        return Ok(Session {
            sender,
            path: "/rr".into(),
            // The core sends plain HTTP where its Host names, and the bench name resolves nowhere.
            host: format!("{}:{port}", ctx.origin),
            decrypted: None,
        });
    }
    let clients = clients.ok_or_else(missing)?;
    let h2 = matches!(wire, Wire::H2);
    let stream = tls(if h2 { &clients.h2 } else { &clients.h1 }, stream).await?;
    let leaf = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first());
    let decrypted = Some(leaf.is_none_or(|leaf| leaf.as_ref() != &*clients.origin_leaf));
    let (sender, path) = if h2 {
        let (sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .map_err(io::Error::other)?;
        tokio::spawn(conn);
        (Sender::H2(sender), format!("https://{host}/rr"))
    } else {
        (h1(stream).await?, "/rr".to_string())
    };
    Ok(Session {
        sender,
        path,
        host,
        decrypted,
    })
}

async fn tls(
    config: &Arc<rustls::ClientConfig>,
    stream: TcpStream,
) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let name = ServerName::try_from(HOST).map_err(io::Error::other)?;
    tokio_rustls::TlsConnector::from(config.clone())
        .connect(name, stream)
        .await
}

async fn h1<S>(io: S) -> io::Result<Sender>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(io::Error::other)?;
    tokio::spawn(conn);
    Ok(Sender::H1(sender))
}

impl Session {
    /// A 64-byte POST and its 64-byte answer.
    pub async fn exchange(&mut self) -> io::Result<()> {
        let request = Request::post(self.path.as_str())
            .header(hyper::header::HOST, self.host.as_str())
            .body(Full::new(Bytes::from_static(&BODY)))
            .map_err(io::Error::other)?;
        let response = match &mut self.sender {
            Sender::H1(sender) => {
                sender.ready().await.map_err(io::Error::other)?;
                sender.send_request(request).await
            }
            Sender::H2(sender) => {
                sender.ready().await.map_err(io::Error::other)?;
                sender.send_request(request).await
            }
        }
        .map_err(io::Error::other)?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(io::Error::other)?;
        let size = body.to_bytes().len();
        if status != StatusCode::OK || size != BODY.len() {
            return Err(io::Error::other(format!("{status} with {size} bytes")));
        }
        Ok(())
    }
}

/// One connection held after one exchange, for `idle`.
pub async fn held(ctx: Ctx) -> Result<Session, String> {
    let mut session = open(&ctx, Wire::H1).await.map_err(|e| e.to_string())?;
    session.exchange().await.map_err(|e| e.to_string())?;
    Ok(session)
}

pub async fn rr(ctx: &Ctx, wire: Wire) -> Result<Metrics, String> {
    let mut session = open(ctx, wire).await.map_err(|e| format!("connect: {e}"))?;
    let failed = |e: io::Error| format!("exchange: {e}");
    let warm_until = Instant::now() + ctx.warmup;
    while Instant::now() < warm_until {
        session.exchange().await.map_err(failed)?;
    }
    let windows = Windows::open(ctx.pids);
    let started = Instant::now();
    let mut samples = Vec::with_capacity(1 << 16);
    while started.elapsed() < ctx.duration {
        let sent = Instant::now();
        session.exchange().await.map_err(failed)?;
        samples.push(sent.elapsed().as_nanos() as u64);
    }
    let mut m = load::rr_metrics(started, windows.close(), &mut samples);
    if let Some(decrypted) = session.decrypted {
        m.insert("decrypted".into(), f64::from(u8::from(decrypted)));
    }
    Ok(m)
}

/// A new TLS connection, one exchange, close: handshake, leaf certificate and session setup.
pub async fn crr_once(ctx: Ctx) -> Result<u64, String> {
    let started = Instant::now();
    let work = async {
        let mut session = open(&ctx, Wire::H1).await?;
        session.exchange().await
    };
    match tokio::time::timeout(Duration::from_secs(5), work).await {
        Ok(Ok(())) => Ok(started.elapsed().as_nanos() as u64),
        Ok(Err(err)) => Err(err.to_string()),
        Err(_) => Err("timed out".into()),
    }
}
