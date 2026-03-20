use jsonwebtoken::{DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde_json::Value;
use std::collections::HashMap;

use crate::jwt::auth::{AuthInfo, AuthorizationError};

pub mod auth;

pub trait PayloadVerifier: Send + Sync {
    fn verify_payload(&self, claims: &Value) -> Result<(), AuthorizationError>;
}

#[derive(Debug, Clone)]
pub struct JwtValidatorConfig {
    pub jwks_uri: String,
    pub issuer: String,
}

impl JwtValidatorConfig {
    pub fn new(jwks_uri: impl Into<String>, issuer: impl Into<String>) -> Self {
        Self {
            jwks_uri: jwks_uri.into(),
            issuer: issuer.into(),
        }
    }

    pub fn with_tenant_id(tenant_id: impl AsRef<str>) -> Self {
        let tenant_id = tenant_id.as_ref();
        Self {
            jwks_uri: format!("https://{tenant_id}.logto.app/oidc/jwks"),
            issuer: format!("https://{tenant_id}.logto.app/oidc"),
        }
    }
}

pub struct JwtValidator {
    pub jwks: HashMap<String, DecodingKey>,
    verifier: Box<dyn PayloadVerifier>,
    pub config: JwtValidatorConfig,
}

impl JwtValidator {
    pub async fn new(
        config: JwtValidatorConfig,
        verifier: Box<dyn PayloadVerifier>,
    ) -> Result<Self, AuthorizationError> {
        let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();

        let jwks = Self::fetch_jwks(&config.jwks_uri).await?;
        Ok(Self {
            config,
            jwks,
            verifier,
        })
    }

    async fn fetch_jwks(
        jwks_uri: impl AsRef<str>,
    ) -> Result<HashMap<String, DecodingKey>, AuthorizationError> {
        let response = reqwest::get(jwks_uri.as_ref()).await.map_err(|e| {
            AuthorizationError::with_status(format!("Failed to fetch JWKS: {}", e), 401)
        })?;

        let jwk_set: JwkSet = response.json().await.map_err(|e| {
            AuthorizationError::with_status(format!("Failed to parse JWKS: {}", e), 401)
        })?;

        let mut keys = HashMap::new();
        for jwk in &jwk_set.keys {
            if let Some(kid) = &jwk.common.key_id
                && let Ok(dk) = DecodingKey::from_jwk(jwk)
            {
                keys.insert(kid.clone(), dk);
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

        let mut validation = Validation::new(header.alg);

        validation.set_issuer(&[&self.config.issuer]);
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

impl GlobalApiResourceVerifier {
    pub fn new(audience: impl Into<String>, required_scopes: Vec<impl Into<String>>) -> Self {
        Self {
            audience: audience.into(),
            required_scopes: required_scopes
                .into_iter()
                .map(|scope| scope.into())
                .collect(),
        }
    }
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
