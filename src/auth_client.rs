use std::time::{Duration, Instant};

use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct M2MCredentials {
    pub client_id: String,
    pub client_secret: String,
}

pub struct LogtoAuthClient {
    pub http: Client,
    pub base_url: String,
    pub resource: String,
    pub credentials: M2MCredentials,
    pub scopes: Vec<String>,
}

#[derive(Error, Debug)]
pub enum LogtoAuthError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON serialization/deserialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    /// Use this value for accessing the Logto Management API
    pub access_token: String,
    /// Token expiration in seconds
    pub expires_in: u64,
    /// Token type for your request when using the access token
    pub token_type: String,
    /// Scope for Logto Management API
    pub scope: String,
}

impl LogtoAuthClient {
    pub fn new(
        tenant_id: impl AsRef<str>,
        credentials: M2MCredentials,
        scopes: Vec<String>,
    ) -> Self {
        let tenant_id = tenant_id.as_ref().to_owned();
        let base_url = format!("https://{}.logto.app", tenant_id);
        let resource = format!("{}/api", base_url);

        Self {
            http: Client::new(),
            base_url,
            resource,
            credentials,
            scopes,
        }
    }

    pub async fn get_access_token(&self) -> Result<TokenResponse, LogtoAuthError> {
        Ok(self
            .http
            .post(format!("{}/oidc/token", self.base_url))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &self.credentials.client_id),
                ("client_secret", &self.credentials.client_secret),
                ("resource", &self.resource),
                ("scope", &self.scopes.join(" ")),
            ])
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await?
            .error_for_status()?
            .json::<TokenResponse>()
            .await?)
    }
}

pub struct TokenWithExpiry {
    pub token: TokenResponse,
    pub expires_at: Instant,
}

impl TokenWithExpiry {
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// Caches the auth token and gives a new one if there is no valid token
pub struct CachedToken {
    pub auth_client: LogtoAuthClient,
    pub token: Option<TokenWithExpiry>,
    pub token_recieved: Instant,
    pub safety_buffer: Duration,
}

impl CachedToken {
    pub fn new(auth_client: LogtoAuthClient) -> Self {
        Self {
            auth_client,
            token: None,
            token_recieved: Instant::now(),
            safety_buffer: Duration::from_secs(1),
        }
    }

    /// Token is garunteed to be valid for at least 1 second
    pub async fn get_valid_token(&mut self) -> Result<&TokenResponse, LogtoAuthError> {
        let needs_refresh = self.token.as_ref().map_or(true, |t| t.is_expired());

        if needs_refresh {
            let start = Instant::now();
            let token_response = self.auth_client.get_access_token().await?;
            let elapsed = start.elapsed();

            let expires_at = Instant::now() + Duration::from_secs(token_response.expires_in)
                - elapsed
                - self.safety_buffer;

            self.token = Some(TokenWithExpiry {
                token: token_response,
                expires_at,
            });
        }

        Ok(&self.token.as_ref().unwrap().token)
    }
}
