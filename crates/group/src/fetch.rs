use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::error::{FetchError, FetchErrorKind};

pub struct FetchRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub via_proxy: Option<String>,
    pub size_limit: Option<u64>,
    pub timeout: Duration,
}

pub struct FetchResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub struct FetchHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl FetchResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A body past `size_limit` is cut, not refused.
#[async_trait]
pub trait Fetcher: Send + Sync {
    async fn get(&self, request: FetchRequest) -> Result<FetchResponse, FetchError>;

    /// As [get](Self::get), writing the body to `sink` as it arrives, whatever the status.
    async fn get_into(
        &self,
        request: FetchRequest,
        sink: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<FetchHead, FetchError> {
        let response = self.get(request).await?;
        sink.write_all(&response.body)
            .await
            .map_err(|err| FetchError {
                kind: FetchErrorKind::Other,
                message: err.to_string(),
            })?;
        Ok(FetchHead {
            status: response.status,
            headers: response.headers,
        })
    }
}
