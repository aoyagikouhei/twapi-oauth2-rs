use axum::{
    Json, Router,
    extract::Query,
    response::{Html, IntoResponse},
    routing::get,
};
use std::collections::HashMap;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use twapi_oauth2::oauth1a::OAuth1aClient;

// CONSUMER_KEY=xxx CONSUMER_SECRET=xxx CALLBACK_URL=http://localhost:3000/oauth?state=xyz cargo run

pub const OAUTH_TOKEN_SECRET: &str = "oauth_token_secret";

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/oauth", get(oauth))
        .route("/", get(root))
        .layer(CookieManagerLayer::new());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn oauth_client() -> OAuth1aClient {
    OAuth1aClient::new(
        &std::env::var("CONSUMER_KEY").unwrap(),
        &std::env::var("CONSUMER_SECRET").unwrap(),
        &std::env::var("CALLBACK_URL").unwrap(),
    )
}

async fn root(cookies: Cookies) -> impl IntoResponse {
    let oauth = oauth_client();
    let request_token = oauth.request_token(None).await.unwrap();
    cookies.add(Cookie::new(OAUTH_TOKEN_SECRET, request_token.response.oauth_token_secret.clone()));
    Html(format!("<a href='{}'>oauth<a>", request_token.url)).into_response()
}

async fn oauth(
    Query(params): Query<HashMap<String, String>>,
    cookies: Cookies,
) -> impl IntoResponse {
    let oauth_token_secret = cookies.get(OAUTH_TOKEN_SECRET).unwrap();
    let oauth = oauth_client();
    let res = oauth
        .access_token(
            params.get("oauth_token").unwrap(),
            oauth_token_secret.value(),
            params.get("oauth_verifier").unwrap(),
        )
        .await
        .unwrap();
    println!("{:?}", res);
    Json(res).into_response()
}
