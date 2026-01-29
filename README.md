# twapi-oauth2-rs

Twitter(X) OAuth2 library.

[Documentation](https://docs.rs/twapi-oauth2)

- OAuth 2.0 Authorization Code Flow with PKCE
- Token exchange
- Configurable retry with exponential backoff and jitter
- Configurable timeout
- Comprehensive X API scope support

## Changes
[CHANGELOG.md](https://github.com/aoyagikouhei/twapi-oauth2-rs/blob/main/CHANGELOG.md)

## Examples

### OAuth Web
```
cd examples/oauth-web
API_KEY_CODE=xxx API_SECRET_CODE=xxx CALLBACK_URL=http://localhost:3000/oauth cargo run
```
http://localhost:3000/

### Code
```rust
use twapi_oauth2::x::{XClient, XScope};

#[tokio::main]
async fn main() {
    let client = XClient::new(
        &std::env::var("API_KEY_CODE").unwrap(),
        &std::env::var("API_SECRET_CODE").unwrap(),
        &std::env::var("CALLBACK_URL").unwrap(),
        XScope::all(),
    );

    // Generate authorization URL with PKCE
    let (oauth_url, pkce_verifier) = client.authorize_url("state");
    println!("Open this URL: {}", oauth_url);

    // Exchange authorization code for token
    let code = "authorization_code_from_callback";
    let res = client.token(code, &pkce_verifier).await.unwrap();
    println!("{:?}", res);
}
```
