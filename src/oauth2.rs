use std::time::Duration;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use query_string_builder::QueryString;
use reqwest::{StatusCode, header::HeaderMap};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::{error::Error, execute_retry};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResult {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub scope: String,
    pub token_type: String,
}

enum ResponseType {
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

enum CodeChallengeMethod {
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
fn authorize_url(
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
) -> Result<(TokenResult, StatusCode, HeaderMap), Error> {
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

pub enum XScope {
    TweetRead,
    TweetWrite,
    TweetModerateWrite,
    UsersEmail,
    UsersRead,
    FollowsRead,
    FollowsWrite,
    OfflineAccess,
    SpaceRead,
    MuteRead,
    MuteWrite,
    LikeRead,
    LikeWrite,
    ListRead,
    ListWrite,
    BlockRead,
    BlockWrite,
    BookmarkRead,
    BookmarkWrite,
    DmRead,
    DmWrite,
    MediaWrite,
}

impl XScope {
    pub fn all() -> Vec<Self> {
        vec![
            Self::TweetRead,
            Self::TweetWrite,
            Self::TweetModerateWrite,
            Self::UsersEmail,
            Self::UsersRead,
            Self::FollowsRead,
            Self::FollowsWrite,
            Self::OfflineAccess,
            Self::SpaceRead,
            Self::MuteRead,
            Self::MuteWrite,
            Self::LikeRead,
            Self::LikeWrite,
            Self::ListRead,
            Self::ListWrite,
            Self::BlockRead,
            Self::BlockWrite,
            Self::BookmarkRead,
            Self::BookmarkWrite,
            Self::DmRead,
            Self::DmWrite,
            Self::MediaWrite,
        ]
    }

    pub fn scopes_to_string(scopes: &[XScope]) -> String {
        scopes
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<String>>()
            .join(" ")
    }
}

impl std::fmt::Display for XScope {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::TweetRead => write!(f, "tweet.read"),
            Self::TweetWrite => write!(f, "tweet.write"),
            Self::TweetModerateWrite => write!(f, "tweet.moderate.write"),
            Self::UsersEmail => write!(f, "users.email"),
            Self::UsersRead => write!(f, "users.read"),
            Self::FollowsRead => write!(f, "follows.read"),
            Self::FollowsWrite => write!(f, "follows.write"),
            Self::OfflineAccess => write!(f, "offline.access"),
            Self::SpaceRead => write!(f, "space.read"),
            Self::MuteRead => write!(f, "mute.read"),
            Self::MuteWrite => write!(f, "mute.write"),
            Self::LikeRead => write!(f, "like.read"),
            Self::LikeWrite => write!(f, "like.write"),
            Self::ListRead => write!(f, "list.read"),
            Self::ListWrite => write!(f, "list.write"),
            Self::BlockRead => write!(f, "block.read"),
            Self::BlockWrite => write!(f, "block.write"),
            Self::BookmarkRead => write!(f, "bookmark.read"),
            Self::BookmarkWrite => write!(f, "bookmark.write"),
            Self::DmRead => write!(f, "dm.read"),
            Self::DmWrite => write!(f, "dm.write"),
            Self::MediaWrite => write!(f, "media.write"),
        }
    }
}

pub const X_AUTHORIZE_URL: &str = "https://x.com/i/oauth2/authorize";
pub const X_TOKEN_URL: &str = "https://api.x.com/2/oauth2/token";

pub struct XClient {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: Vec<XScope>,
    try_count: usize,
    retry_millis: u64,
    timeout: Duration,
}

impl XClient {
    pub fn new(
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        scopes: Vec<XScope>,
    ) -> Self {
        Self::new_with_token_options(
            client_id,
            client_secret,
            redirect_uri,
            scopes,
            3,
            500,
            Duration::from_secs(10),
        )
    }

    pub fn new_with_token_options(
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        scopes: Vec<XScope>,
        try_count: usize,
        retry_millis: u64,
        timeout: Duration,
    ) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scopes,
            try_count,
            retry_millis,
            timeout,
        }
    }

    pub fn authorize_url(&self, state: &str) -> (String, String) {
        let pkce = PkceS256::new();

        let scopes_str = XScope::scopes_to_string(&self.scopes);
        (
            authorize_url(
                X_AUTHORIZE_URL,
                ResponseType::Code,
                &self.client_id,
                &self.redirect_uri,
                &scopes_str,
                state,
                &pkce.code_challenge,
                CodeChallengeMethod::S256,
            ),
            pkce.code_verifier,
        )
    }

    pub async fn token(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<(TokenResult, StatusCode, HeaderMap), Error> {
        let (token_json, status_code, headers) = token(
            X_TOKEN_URL,
            &self.client_id,
            &self.client_secret,
            &self.redirect_uri,
            code,
            code_verifier,
            "authorization_code",
            self.timeout,
            self.try_count,
            self.retry_millis,
        )
        .await?;
        Ok((token_json, status_code, headers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CLIENT_ID=xxx CLIENT_SECRET=xxx REDIRECT_URL=http://localhost:8000/callback cargo test test_x_authorize -- --nocapture
    #[tokio::test]
    async fn test_x_authorize() {
        let client_id = std::env::var("CLIENT_ID").unwrap();
        let client_secret = std::env::var("CLIENT_SECRET").unwrap();
        let redirect_url = std::env::var("REDIRECT_URL").unwrap();
        let state = "test_state";
        let x_client = XClient::new(&client_id, &client_secret, &redirect_url, XScope::all());
        let (auth_url, code_verifier) = x_client.authorize_url(state);
        println!("Authorize URL: {}", auth_url);
        println!("Code Verifier: {}", code_verifier);
    }

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
