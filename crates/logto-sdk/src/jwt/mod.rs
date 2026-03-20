use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::Value;
use std::collections::HashMap;

use crate::jwt::auth::{AuthInfo, AuthorizationError, ISSUER, JWKS_URI};

pub mod auth;

pub trait PayloadVerifier: Send + Sync {
    fn verify_payload(&self, claims: &Value) -> Result<(), AuthorizationError>;
}

pub struct JwtValidator {
    pub jwks: HashMap<String, DecodingKey>,
    verifier: Box<dyn PayloadVerifier>,
}

impl JwtValidator {
    pub async fn new(verifier: Box<dyn PayloadVerifier>) -> Result<Self, AuthorizationError> {
        let jwks = Self::fetch_jwks().await?;
        Ok(Self { jwks, verifier })
    }

    async fn fetch_jwks() -> Result<HashMap<String, DecodingKey>, AuthorizationError> {
        let response = reqwest::get(JWKS_URI).await.map_err(|e| {
            AuthorizationError::with_status(format!("Failed to fetch JWKS: {}", e), 401)
        })?;

        let jwks: Value = response.json().await.map_err(|e| {
            AuthorizationError::with_status(format!("Failed to parse JWKS: {}", e), 401)
        })?;

        let mut keys = HashMap::new();

        if let Some(keys_array) = jwks["keys"].as_array() {
            for key in keys_array {
                if let (Some(kid), Some(kty), Some(n), Some(e)) = (
                    key["kid"].as_str(),
                    key["kty"].as_str(),
                    key["n"].as_str(),
                    key["e"].as_str(),
                ) {
                    if kty == "RSA" {
                        if let Ok(decoding_key) = DecodingKey::from_rsa_components(n, e) {
                            keys.insert(kid.to_string(), decoding_key);
                        }
                    }
                }
            }
        }

        if keys.is_empty() {
            return Err(AuthorizationError::with_status(
                "No valid keys found in JWKS",
                401,
            ));
        }

        Ok(keys)
    }

    pub fn validate_jwt(&self, token: &str) -> Result<AuthInfo, AuthorizationError> {
        let header = decode_header(token).map_err(|e| {
            AuthorizationError::with_status(format!("Invalid token header: {}", e), 401)
        })?;

        let kid = header
            .kid
            .ok_or_else(|| AuthorizationError::with_status("Token missing kid claim", 401))?;

        let key = self
            .jwks
            .get(&kid)
            .ok_or_else(|| AuthorizationError::with_status("Unknown key ID", 401))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[ISSUER]);
        validation.validate_aud = false; // We'll verify audience manually

        let token_data = decode::<Value>(token, key, &validation)
            .map_err(|e| AuthorizationError::with_status(format!("Invalid token: {}", e), 401))?;

        let claims = token_data.claims;
        self.verifier.verify_payload(&claims)?;

        Ok(self.create_auth_info(claims))
    }

    fn create_auth_info(&self, claims: Value) -> AuthInfo {
        let scopes = claims["scope"]
            .as_str()
            .map(|s| s.split(' ').map(|s| s.to_string()).collect())
            .unwrap_or_default();

        let audience = match &claims["aud"] {
            Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
            Value::String(s) => vec![s.clone()],
            _ => vec![],
        };

        AuthInfo::new(
            claims["sub"].as_str().unwrap_or_default().to_string(),
            claims["client_id"].as_str().map(|s| s.to_string()),
            claims["organization_id"].as_str().map(|s| s.to_string()),
            scopes,
            audience,
        )
    }
}

pub struct GlobalApiResourceVerifier {
    pub audience: String,
    pub required_scopes: Vec<String>,
}

impl PayloadVerifier for GlobalApiResourceVerifier {
    fn verify_payload(&self, claims: &Value) -> Result<(), AuthorizationError> {
        // Check audience claim matches your API resource indicator
        let audiences = match &claims["aud"] {
            Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>(),
            Value::String(s) => vec![s.as_str()],
            _ => vec![],
        };

        if !audiences.contains(&self.audience.as_str()) {
            return Err(AuthorizationError::new("Invalid audience"));
        }

        // Check required scopes for global API resources
        let scopes = claims["scope"]
            .as_str()
            .map(|s| s.split(' ').collect::<Vec<_>>())
            .unwrap_or_default();

        for required_scope in &self.required_scopes {
            if !scopes.contains(&required_scope.as_str()) {
                return Err(AuthorizationError::new("Insufficient scope"));
            }
        }

        Ok(())
    }
}
