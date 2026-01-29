use base64::prelude::*;
use query_string_builder::QueryString;
use sha2::Digest;

pub mod error;
pub mod x;

pub enum ResponseType {
    Code,
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

pub enum CodeChallengeMethod {
    S256,
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

pub struct PkceS256 {
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
            BASE64_URL_SAFE_NO_PAD.encode(&hash)
        };
        Self {
            code_challenge,
            code_verifier,
        }
    }
}

pub fn authorize_url(
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
        .with_value("response_type", &response_type.to_string())
        .with_value("client_id", client_id)
        .with_value("redirect_uri", redirect_uri)
        .with_value("scope", scopes)
        .with_value("state", state)
        .with_value("code_challenge", code_challenge)
        .with_value("code_challenge_method", &code_challenge_method.to_string());
    format!("{}{}", url, qs)
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
