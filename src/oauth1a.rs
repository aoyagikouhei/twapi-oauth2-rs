use crate::{error::Error, execute_retry_body, make_url, oauth1a::calc_oauth1a::calc_oauth_header};
use reqwest::{StatusCode, header::HeaderMap};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};

pub mod calc_oauth1a;

const BASE_URL_PREFIX: &str = "https://api.x.com";
const REQUEST_TOKEN_URL_POSTFIX: &str = "/oauth/request_token";
const ACCESS_TOKEN_URL_POSTFIX: &str = "/oauth/access_token";
const AUTHORIZE_URL: &str = "https://api.x.com/oauth/authorize?oauth_token=";

pub enum XAuthAccessType {
    Read,
    Write,
}

impl XAuthAccessType {
    pub fn as_str(&self) -> &str {
        match self {
            XAuthAccessType::Read => "read",
            XAuthAccessType::Write => "write",
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RequestToken {
    pub response: RequestTokenResponse,
    pub url: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RequestTokenResponse {
    pub oauth_token: String,
    pub oauth_token_secret: String,
    pub oauth_callback_confirmed: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AccessToken {
    pub oauth_token: String,
    pub oauth_token_secret: String,
    pub screen_name: String,
}

pub struct OAuth1aClient {
    consumer_key: String,
    consumer_secret: String,
    callback_url: String,
    try_count: usize,
    retry_duration: Duration,
    timeout: Duration,
    prefix_url: Option<String>,
}

impl OAuth1aClient {
    pub fn new(consumer_key: &str, consumer_secret: &str, callback_url: &str) -> Self {
        Self::new_with_options(
            consumer_key,
            consumer_secret,
            callback_url,
            3,
            Duration::from_millis(100),
            Duration::from_secs(10),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_options(
        consumer_key: &str,
        consumer_secret: &str,
        callback_url: &str,
        try_count: usize,
        retry_duration: Duration,
        timeout: Duration,
        prefix_url: Option<String>,
    ) -> Self {
        OAuth1aClient {
            consumer_key: consumer_key.to_string(),
            consumer_secret: consumer_secret.to_string(),
            callback_url: callback_url.to_string(),
            try_count,
            retry_duration,
            timeout,
            prefix_url,
        }
    }

    pub async fn request_token(
        &self,
        x_auth_access_type: Option<XAuthAccessType>,
    ) -> Result<RequestToken, Error> {
        let mut header_options = vec![("oauth_callback", self.callback_url.as_str())];
        if let Some(x_auth_access_type) = x_auth_access_type.as_ref() {
            header_options.push(("x_auth_access_type", x_auth_access_type.as_str()));
        }
        let url = make_url(BASE_URL_PREFIX, REQUEST_TOKEN_URL_POSTFIX, &self.prefix_url);
        let signed = calc_oauth_header(
            &format!("{}&", self.consumer_secret),
            &self.consumer_key,
            &header_options,
            "POST",
            &url,
            &vec![],
        );
        let signed = format!("OAuth {}", signed);
        println!("signed: {}", signed);
        let client = reqwest::Client::new();
        let (res, _, _): (String, StatusCode, HeaderMap) = execute_retry_body(
            || {
                client
                    .post(&url)
                    .header("Authorization", &signed)
                    .timeout(self.timeout)
            },
            self.try_count,
            self.retry_duration,
        )
        .await?;
        let map = parse_oauth_body(res);
        let oauth_token = map.get("oauth_token").unwrap().to_string();
        let oauth_token_secret = map.get("oauth_token_secret").unwrap().to_string();
        let oauth_callback_confirmed = map.get("oauth_callback_confirmed").unwrap().to_string();
        let url = format!("{}{}", AUTHORIZE_URL, oauth_token);
        Ok(RequestToken {
            response: RequestTokenResponse {
                oauth_token,
                oauth_token_secret,
                oauth_callback_confirmed,
            },
            url,
        })
    }

    pub async fn access_token(
        &self,
        oauth_token: &str,
        oauth_token_secret: &str,
        oauth_verifier: &str,
    ) -> Result<AccessToken, Error> {
        let url = make_url(BASE_URL_PREFIX, ACCESS_TOKEN_URL_POSTFIX, &self.prefix_url);
        let signed = calc_oauth_header(
            &format!("{}&{}", self.consumer_secret, oauth_token_secret),
            &self.consumer_key,
            &vec![
                ("oauth_token", oauth_token),
                ("oauth_verifier", oauth_verifier),
            ],
            "POST",
            &url,
            &vec![],
        );
        let signed = format!("OAuth {}", signed);
        let client = reqwest::Client::new();
        let (res, _, _): (String, StatusCode, HeaderMap) = execute_retry_body(
            || {
                client
                    .post(&url)
                    .header("Authorization", &signed)
                    .timeout(self.timeout)
            },
            self.try_count,
            self.retry_duration,
        )
        .await?;
        let map = parse_oauth_body(res);
        let oauth_token = map.get("oauth_token").unwrap().to_string();
        let oauth_token_secret = map.get("oauth_token_secret").unwrap().to_string();
        let screen_name = map.get("screen_name").unwrap().to_string();
        Ok(AccessToken {
            oauth_token,
            oauth_token_secret,
            screen_name,
        })
    }
}

pub fn parse_oauth_body(body: String) -> HashMap<String, String> {
    let mut result = HashMap::new();
    result.insert("twapi_request_body".to_owned(), body.clone());
    for item in body.split('&') {
        let mut pair = item.split('=');
        if let Some(key) = pair.next() {
            result.insert(key.to_owned(), pair.next().unwrap_or("").to_owned());
        }
    }
    result
}
