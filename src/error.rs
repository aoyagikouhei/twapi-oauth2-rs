use thiserror::Error;

#[derive(Error, Debug)]
pub enum OAuth2Error {
    #[error("Reqwest {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Url {0}")]
    Url(#[from] url::ParseError),

    #[error("Invalid {0}")]
    Invalid(String),
}
