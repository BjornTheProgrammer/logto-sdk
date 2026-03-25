use reqwest::{Client, Response, StatusCode};
use thiserror::Error;

use crate::{
    auth_client::{CachedToken, LogtoAuthClient, LogtoAuthError, TokenResponse},
    management_api::{account_center::AccountCenter, organizations::Organizations},
};

pub mod account_center;
pub mod organizations;

#[derive(Error, Debug)]
pub enum ManagementApiError {
    #[error("Resource not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Forbidden")]
    Forbidden,
    #[error("API error: {0}")]
    ApiError(String),
    #[error("Request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
}

impl From<LogtoAuthError> for ManagementApiError {
    fn from(e: LogtoAuthError) -> Self {
        match e {
            LogtoAuthError::Http(e) => match e.status() {
                Some(s) if s == StatusCode::UNAUTHORIZED => ManagementApiError::Unauthorized,
                Some(s) if s == StatusCode::FORBIDDEN => ManagementApiError::Forbidden,
                _ => ManagementApiError::RequestFailed(e),
            },
            LogtoAuthError::Json(e) => ManagementApiError::ApiError(e.to_string()),
        }
    }
}

pub trait ResponseExt {
    fn check_status(self) -> Result<Response, ManagementApiError>;
}

impl ResponseExt for Result<Response, reqwest::Error> {
    fn check_status(self) -> Result<Response, ManagementApiError> {
        let response = self.map_err(ManagementApiError::RequestFailed)?;
        match response.status() {
            StatusCode::OK => Ok(response),
            StatusCode::UNAUTHORIZED => Err(ManagementApiError::Unauthorized),
            StatusCode::FORBIDDEN => Err(ManagementApiError::Forbidden),
            StatusCode::NOT_FOUND => Err(ManagementApiError::NotFound),
            status => Err(ManagementApiError::ApiError(format!(
                "Unexpected status: {}",
                status
            ))),
        }
    }
}

pub struct LogtoClient {
    pub http: Client,
    pub cached_token: CachedToken,
}

impl LogtoClient {
    pub fn new(auth_client: LogtoAuthClient) -> Self {
        Self {
            http: Client::new(),
            cached_token: CachedToken::new(auth_client),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.cached_token.auth_client.resource
    }

    pub async fn get_valid_token(&self) -> Result<TokenResponse, LogtoAuthError> {
        self.cached_token.get_valid_token().await
    }

    pub fn account_center<'a>(&'a self) -> AccountCenter<'a> {
        AccountCenter { client: &self }
    }

    pub fn organizations<'a>(&'a self) -> Organizations<'a> {
        Organizations { client: &self }
    }
}
