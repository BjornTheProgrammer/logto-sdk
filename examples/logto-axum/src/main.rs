use axum::{Router, extract::Extension, middleware, response::Json, routing::get};
use logto_sdk::{
    axum::jwt_middleware,
    jwt::{GlobalApiResourceVerifier, JwtValidator, JwtValidatorConfig, auth::AuthInfo},
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    let validator = Arc::new(
        JwtValidator::new(
            JwtValidatorConfig::with_tenant_id("xxxxx"), // Set the tenant id here or there will be a panic
            Box::new(GlobalApiResourceVerifier {
                audience: "https://your-api-resource-indicator".to_string(),
                required_scopes: vec!["api:read".to_string(), "api:write".to_string()],
            }),
        )
        .await
        .expect("Failed to initialize JWT validator"),
    );

    let app = Router::new()
        .route("/api/protected", get(protected_handler))
        .layer(middleware::from_fn(
            jwt_middleware::<GlobalApiResourceVerifier>,
        ))
        .layer(Extension(validator))
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn protected_handler(Extension(auth): Extension<AuthInfo>) -> Json<Value> {
    // Access auth information directly from Extension
    Json(json!({ "auth": auth }))
}
