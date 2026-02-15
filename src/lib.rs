use std::time::Duration;

use reqwest::{RequestBuilder, StatusCode, header::HeaderMap};

pub mod error;

#[cfg(feature = "oauth1a")]
pub mod oauth1a;

#[cfg(feature = "oauth2")]
pub mod oauth2;

pub use reqwest;

use crate::error::Error;

#[allow(dead_code)]
pub(crate) async fn execute_retry<T>(
    f: impl Fn() -> RequestBuilder,
    try_count: usize,
    retry_millis: u64,
) -> Result<(T, StatusCode, HeaderMap), Error>
where
    T: serde::de::DeserializeOwned,
{
    for i in 0..try_count {
        let req = f();
        let res = req.send().await?;
        let status = res.status();
        let headers = res.headers().clone();
        if status.is_success() {
            let json: T = res.json().await?;
            return Ok((json, status, headers));
        } else if status.is_client_error() {
            let body = res.text().await.unwrap_or_default();
            return Err(Error::ClientError(body, status, headers));
        }
        if i + 1 < try_count {
            // ジッターとエクスポーネンシャルバックオフを組み合わせる
            let jitter: u64 = rand::random::<u64>() % retry_millis;
            let exp_backoff = 2u64.pow(i as u32) * retry_millis;
            let retry_duration = Duration::from_millis(exp_backoff + jitter);
            tokio::time::sleep(retry_duration).await;
        } else {
            let body = res.text().await.unwrap_or_default();
            return Err(Error::RetryOver(body, status, headers));
        }
    }
    unreachable!()
}

#[allow(dead_code)]
pub(crate) async fn execute_retry_body(
    f: impl Fn() -> RequestBuilder,
    try_count: usize,
    retry_millis: u64,
) -> Result<(String, StatusCode, HeaderMap), Error> {
    for i in 0..try_count {
        let req = f();
        let res = req.send().await?;
        let status = res.status();
        let headers = res.headers().clone();
        if status.is_success() {
            let body = res.text().await?;
            return Ok((body, status, headers));
        } else if status.is_client_error() {
            let body = res.text().await.unwrap_or_default();
            return Err(Error::ClientError(body, status, headers));
        }
        if i + 1 < try_count {
            // ジッターとエクスポーネンシャルバックオフを組み合わせる
            let jitter: u64 = rand::random::<u64>() % retry_millis;
            let exp_backoff = 2u64.pow(i as u32) * retry_millis;
            let retry_duration = Duration::from_millis(exp_backoff + jitter);
            tokio::time::sleep(retry_duration).await;
        } else {
            let body = res.text().await.unwrap_or_default();
            return Err(Error::RetryOver(body, status, headers));
        }
    }
    unreachable!()
}

pub(crate) fn make_url(base_url: &str, path: &str, prefix_url: &Option<String>) -> String {
    if let Some(prefix_url) = prefix_url {
        format!("{}{}", prefix_url, path)
    } else {
        format!("{}{}", base_url, path)
    }
}
