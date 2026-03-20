use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct M2mCredentials {
    pub client_id: String,
    pub client_secret: String,
}

impl M2mCredentials {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        }
    }
}

pub struct LogtoAuthClient {
    pub http: Client,
    pub token_endpoint: String,
    pub resource: String,
    pub credentials: M2mCredentials,
    pub scopes: Vec<String>,
}

#[derive(Error, Debug)]
pub enum LogtoAuthError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON serialization/deserialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize, Clone)]
pub struct TokenResponse {
    /// Use this value for accessing the Logto Management API
    pub access_token: String,
    /// Token expiration in seconds
    pub expires_in: u64,
    /// Token type for your request when using the access token
    pub token_type: String,
    /// Scope for Logto Management API
    pub scope: Option<String>,
}

impl LogtoAuthClient {
    pub fn new(
        tenant_id: impl AsRef<str>,
        credentials: M2mCredentials,
        scopes: Vec<impl Into<String>>,
    ) -> Self {
        let tenant_id = tenant_id.as_ref();
        let base_url = format!("https://{}.logto.app", tenant_id);
        let token_endpoint = format!("{}/oidc/token", base_url);
        let resource = format!("{}/api", base_url);

        Self {
            http: Client::new(),
            token_endpoint,
            resource,
            credentials,
            scopes: scopes.into_iter().map(|scope| scope.into()).collect(),
        }
    }

    pub async fn get_access_token(&self) -> Result<TokenResponse, LogtoAuthError> {
        let response = self
            .http
            .post(&self.token_endpoint)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &self.credentials.client_id),
                ("client_secret", &self.credentials.client_secret),
                ("resource", &self.resource),
                ("scope", &self.scopes.join(" ")),
            ])
            .send()
            .await?
            .error_for_status()?;

        Ok(response.json::<TokenResponse>().await?)
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
    pub token: Mutex<Option<TokenWithExpiry>>,
    pub token_recieved: Instant,
    pub safety_buffer: Duration,
}

impl CachedToken {
    pub fn new(auth_client: LogtoAuthClient) -> Self {
        Self {
            auth_client,
            token: Mutex::new(None),
            token_recieved: Instant::now(),
            safety_buffer: Duration::from_secs(1),
        }
    }

    /// Token is garunteed to be valid for at least 1 second
    pub async fn get_valid_token(&self) -> Result<TokenResponse, LogtoAuthError> {
        let mut guard = self.token.lock().unwrap();

        let needs_refresh = self
            .token
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|t| t.is_expired());

        if needs_refresh {
            let start = Instant::now();
            let token_response = self.auth_client.get_access_token().await?;
            let elapsed = start.elapsed();

            let expires_at = Instant::now() + Duration::from_secs(token_response.expires_in)
                - elapsed
                - self.safety_buffer;

            *guard = Some(TokenWithExpiry {
                token: token_response,
                expires_at,
            });
        }

        Ok(guard.as_ref().unwrap().token.clone())
    }
}
