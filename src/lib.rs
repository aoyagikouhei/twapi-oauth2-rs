use std::time::Duration;

use base64::prelude::*;
use query_string_builder::QueryString;
use reqwest::{RequestBuilder, StatusCode, header::HeaderMap};
use serde::{Deserialize, Serialize};
use sha2::Digest;

pub mod error;
pub mod x;

pub use reqwest;

use crate::error::OAuth2Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResult {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub scope: String,
    pub token_type: String,
}

pub(crate) enum ResponseType {
    Code,
    #[allow(unused)]
    Token,
}

impl std::fmt::Display for ResponseType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Code => write!(f, "code"),
            Self::Token => write!(f, "token"),
        }
    }
}

pub(crate) enum CodeChallengeMethod {
    S256,
    #[allow(unused)]
    Plain,
}

impl std::fmt::Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::S256 => write!(f, "S256"),
            Self::Plain => write!(f, "plain"),
        }
    }
}

pub(crate) struct PkceS256 {
    pub code_challenge: String,
    pub code_verifier: String,
}

impl PkceS256 {
    pub fn new() -> Self {
        let size = 32;
        let random_bytes: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
        let code_verifier = BASE64_URL_SAFE_NO_PAD.encode(&random_bytes);
        let code_challenge = {
            let hash = sha2::Sha256::digest(code_verifier.as_bytes());
            BASE64_URL_SAFE_NO_PAD.encode(hash)
        };
        Self {
            code_challenge,
            code_verifier,
        }
    }
}

impl Default for PkceS256 {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn authorize_url(
    url: &str,
    response_type: ResponseType,
    client_id: &str,
    redirect_uri: &str,
    scopes: &str,
    state: &str,
    code_challenge: &str,
    code_challenge_method: CodeChallengeMethod,
) -> String {
    let qs = QueryString::dynamic()
        .with_value("response_type", response_type.to_string())
        .with_value("client_id", client_id)
        .with_value("redirect_uri", redirect_uri)
        .with_value("scope", scopes)
        .with_value("state", state)
        .with_value("code_challenge", code_challenge)
        .with_value("code_challenge_method", code_challenge_method.to_string());
    format!("{}{}", url, qs)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn token(
    url: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    code: &str,
    code_verifier: &str,
    grant_type: &str,
    timeout: Duration,
    try_count: usize,
    retry_millis: u64,
) -> Result<(TokenResult, StatusCode, HeaderMap), OAuth2Error> {
    let params = [
        ("grant_type", grant_type),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];

    let client = reqwest::Client::new();

    execute_retry(
        || {
            client
                .post(url)
                .form(&params)
                .basic_auth(client_id, Some(client_secret))
                .timeout(timeout)
        },
        try_count,
        retry_millis,
    )
    .await
}

pub(crate) async fn execute_retry<T>(
    f: impl Fn() -> RequestBuilder,
    try_count: usize,
    retry_millis: u64,
) -> Result<(T, StatusCode, HeaderMap), OAuth2Error>
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
            return Err(OAuth2Error::ClientError(body, status, headers));
        }
        if i + 1 < try_count {
            // ジッターとエクスポーネンシャルバックオフを組み合わせる
            let jitter: u64 = rand::random::<u64>() % retry_millis;
            let exp_backoff = 2u64.pow(i as u32) * retry_millis;
            let retry_duration = Duration::from_millis(exp_backoff + jitter);
            tokio::time::sleep(retry_duration).await;
        } else {
            let body = res.text().await.unwrap_or_default();
            return Err(OAuth2Error::RetryOver(body, status, headers));
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use crate::x::{X_AUTHORIZE_URL, XScope};

    use super::*;

    // CLIENT_ID=xxx cargo test -- --nocapture
    #[tokio::test]
    async fn test_authorize() {
        let client_id = std::env::var("CLIENT_ID").unwrap();
        let redirect_url = std::env::var("REDIRECT_URL").unwrap();
        let state = "test_state";
        let scopes = XScope::scopes_to_string(&XScope::all());
        let code_challenge = "test_code_challenge";
        let res = authorize_url(
            X_AUTHORIZE_URL,
            ResponseType::Code,
            &client_id,
            &redirect_url,
            &scopes,
            &state,
            &code_challenge,
            CodeChallengeMethod::Plain,
        );
        println!("res: {}", res);
    }
}
