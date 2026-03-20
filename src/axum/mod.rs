use crate::jwt::{
    JwtValidator, PayloadVerifier,
    auth::{AuthorizationError, extract_bearer_token},
};
use axum::{
    Extension, Json,
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::sync::Arc;

pub async fn jwt_middleware<V: PayloadVerifier>(
    Extension(validator): Extension<Arc<JwtValidator>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthorizationError> {
    let authorization = headers.get("authorization").and_then(|h| h.to_str().ok());

    let token = extract_bearer_token(authorization)?;
    let auth_info = validator.validate_jwt(token)?;

    // Store auth info in request extensions for generic use
    request.extensions_mut().insert(auth_info);

    Ok(next.run(request).await)
}

impl IntoResponse for AuthorizationError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status_code).unwrap_or(StatusCode::FORBIDDEN);
        (status, Json(json!({ "error": self.message }))).into_response()
    }
}
