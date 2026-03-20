use reqwest::Client;

use crate::{
    auth_client::{CachedToken, LogtoAuthClient, LogtoAuthError, TokenResponse},
    management_api::account_center::AccountCenter,
};

pub mod account_center;

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
}
