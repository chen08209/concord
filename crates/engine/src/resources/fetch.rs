use std::io::Seek as _;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::SystemTime;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use concord_common::{CoreError, CoreOptions};
use concord_group::http::{HttpError, Streaming, Target, TlsSettings, connect};
use concord_group::{FetchError, FetchErrorKind, FetchHead, FetchRequest, FetchResponse, Fetcher};
use concord_platform::HomeDir;
use concord_tls::TrustStore;
use concord_tunnel::Tunnel;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::error::ResourceError;

const MAX_REDIRECTS: usize = 10;

/// Everything the core downloads goes through the tunnel as an inner flow, so a
/// provider can name the proxy it is fetched through.
pub(crate) struct TunnelFetcher {
    pub tunnel: Tunnel,
    pub trust: ArcSwap<TrustStore>,
    pub options: Arc<ArcSwap<CoreOptions>>,
    pub user_agent: ArcSwap<String>,
}

fn fetch_error(kind: FetchErrorKind, message: impl Into<String>) -> FetchError {
    FetchError {
        kind,
        message: message.into(),
    }
}

fn dial_error(err: &std::io::Error) -> FetchError {
    let kind = match (CoreError::of(err), err.kind()) {
        (Some(CoreError::IpNotFound(_)), _) => FetchErrorKind::Dns,
        (_, std::io::ErrorKind::TimedOut) => FetchErrorKind::Timeout,
        _ => FetchErrorKind::Connection,
    };
    fetch_error(kind, err.to_string())
}

fn http_error(err: HttpError) -> FetchError {
    let kind = match &err {
        HttpError::Tls(_) => FetchErrorKind::Tls,
        HttpError::Protocol(_) => FetchErrorKind::Connection,
        HttpError::Url(_) => FetchErrorKind::Other,
    };
    fetch_error(kind, err.to_string())
}

impl TunnelFetcher {
    /// Follows redirects to the response that is not one, under the request's deadline,
    /// and reads its body through `take`.
    async fn fetch<T>(
        &self,
        request: &FetchRequest,
        take: impl AsyncFnOnce(&mut Streaming) -> Result<T, FetchError>,
    ) -> Result<(FetchHead, T), FetchError> {
        let deadline = Instant::now() + request.timeout;
        let mut url = request.url.clone();
        let mut headers = request.headers.clone();
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        {
            headers.push(("User-Agent".to_string(), self.user_agent.load().to_string()));
        }
        let limit = request
            .size_limit
            .and_then(|limit| usize::try_from(limit).ok())
            .unwrap_or(usize::MAX);
        let tls = TlsSettings {
            trust: self.trust.load_full(),
            skip_cert_verify: self.options.load().skip_cert_verify,
            offer_h2: true,
        };
        let exchange = async {
            for _ in 0..MAX_REDIRECTS {
                let target = Target::parse(&url).map_err(http_error)?;
                let stream = self
                    .tunnel
                    .dial_inner(&target.address(), request.via_proxy.as_deref())
                    .await
                    .map_err(|err| dial_error(&err))?;
                let mut connection = connect(stream, &target, &tls, self.tunnel.tasks())
                    .await
                    .map_err(http_error)?;
                let mut response = connection
                    .open(http::Method::GET, &headers, Bytes::new(), limit)
                    .await
                    .map_err(http_error)?;
                if response.status / 100 == 3
                    && let Some(location) = response
                        .headers
                        .get(http::header::LOCATION)
                        .and_then(|value| value.to_str().ok())
                {
                    url = url::Url::parse(&url)
                        .and_then(|base| base.join(location))
                        .map_err(|err| fetch_error(FetchErrorKind::Other, err.to_string()))?
                        .to_string();
                    continue;
                }
                let head = FetchHead {
                    status: response.status,
                    headers: response
                        .headers
                        .iter()
                        .filter_map(|(name, value)| {
                            Some((name.to_string(), value.to_str().ok()?.to_string()))
                        })
                        .collect(),
                };
                let taken = take(&mut response).await?;
                drop(connection);
                return Ok((head, taken));
            }
            Err(fetch_error(
                FetchErrorKind::Other,
                format!("stopped after {MAX_REDIRECTS} redirects"),
            ))
        };
        tokio::time::timeout_at(deadline, exchange)
            .await
            .map_err(|_| fetch_error(FetchErrorKind::Timeout, "context deadline exceeded"))?
    }
}

#[async_trait]
impl Fetcher for TunnelFetcher {
    async fn get(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        let (head, body) = self
            .fetch(&request, async |response: &mut Streaming| {
                let mut body = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(http_error)? {
                    body.extend_from_slice(&chunk);
                }
                Ok(body)
            })
            .await?;
        Ok(FetchResponse {
            status: head.status,
            headers: head.headers,
            body,
        })
    }

    async fn get_into(
        &self,
        request: FetchRequest,
        sink: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<FetchHead, FetchError> {
        let (head, ()) = self
            .fetch(&request, async |response: &mut Streaming| {
                let written =
                    |err: std::io::Error| fetch_error(FetchErrorKind::Other, err.to_string());
                while let Some(chunk) = response.chunk().await.map_err(http_error)? {
                    sink.write_all(&chunk).await.map_err(written)?;
                }
                sink.flush().await.map_err(written)
            })
            .await?;
        Ok(head)
    }
}

/// A plain GET that treats anything but 2xx as a failure, as `HTTPVehicle.Read` does.
pub(crate) async fn download(
    fetcher: &dyn Fetcher,
    request: FetchRequest,
) -> Result<Vec<u8>, ResourceError> {
    let response = fetcher.get(request).await.map_err(ResourceError::Fetch)?;
    if !(200..=299).contains(&response.status) {
        return Err(ResourceError::Status(response.status));
    }
    Ok(response.body)
}

/// A body written to an unnamed file as it arrived, with its SHA-256, so that a large one is
/// never held whole.
pub(crate) struct Spilled {
    file: std::fs::File,
    pub(crate) digest: [u8; 32],
}

impl Spilled {
    /// Copies the body to `path` as [HomeDir::write_atomic] writes a file.
    pub(crate) fn store(mut self, home: &HomeDir, path: impl AsRef<Path>) -> std::io::Result<()> {
        home.write_atomic_with(path, |out| std::io::copy(&mut self.file, out).map(drop))
    }
}

struct Hashing {
    file: tokio::fs::File,
    hasher: Sha256,
}

impl AsyncWrite for Hashing {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let written = ready!(Pin::new(&mut this.file).poll_write(cx, buf))?;
        this.hasher.update(buf.get(..written).unwrap_or_default());
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_shutdown(cx)
    }
}

/// As [download], into an unnamed file in `dir` rather than memory.
pub(crate) async fn download_spilled(
    fetcher: &dyn Fetcher,
    request: FetchRequest,
    dir: &Path,
) -> Result<Spilled, ResourceError> {
    let local = |err: std::io::Error| ResourceError::Other(err.to_string());
    let file = tempfile::tempfile_in(dir).map_err(local)?;
    let mut sink = Hashing {
        file: tokio::fs::File::from_std(file),
        hasher: Sha256::new(),
    };
    let head = fetcher
        .get_into(request, &mut sink)
        .await
        .map_err(ResourceError::Fetch)?;
    if !(200..=299).contains(&head.status) {
        return Err(ResourceError::Status(head.status));
    }
    sink.flush().await.map_err(local)?;
    let mut file = sink.file.into_std().await;
    file.rewind().map_err(local)?;
    Ok(Spilled {
        file,
        digest: sink.hasher.finalize().into(),
    })
}

pub(super) fn touch(path: &Path) {
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.set_modified(SystemTime::now()));
}
