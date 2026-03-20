use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;

use crate::auth_client::{CachedToken, LogtoAuthClient};

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
}
