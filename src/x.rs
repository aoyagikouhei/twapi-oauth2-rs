use std::time::Duration;

use reqwest::{StatusCode, header::HeaderMap};

use crate::{
    CodeChallengeMethod, PkceS256, ResponseType, TokenResult, authorize_url, error::OAuth2Error,
};

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
    ) -> Result<(TokenResult, StatusCode, HeaderMap), OAuth2Error> {
        let (token_json, status_code, headers) = crate::token(
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
    use crate::x::XScope;

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
}
