use actix_web::{App, HttpMessage, HttpRequest, HttpServer, Result, middleware::Logger, web};
use logto_sdk::{
    actix_web::JwtMiddleware,
    jwt::{GlobalApiResourceVerifier, JwtValidator, JwtValidatorConfig, auth::AuthInfo},
};
use serde_json::{Value, json};
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let validator = Arc::new(
        JwtValidator::new(
            JwtValidatorConfig::with_tenant_id("t980oe"), // Set the tenant id here or there will be a panic
            Box::new(GlobalApiResourceVerifier::new(
                "https://t980oe.logto.app/api",
                vec!["all"],
            )),
        )
        .await
        .expect("Failed to initialize JWT validator"),
    );

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(validator.clone()))
            .wrap(Logger::default())
            .service(
                web::scope("/api/protected")
                    .wrap(JwtMiddleware::new(validator.clone()))
                    .route("", web::get().to(protected_handler)),
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

async fn protected_handler(req: HttpRequest) -> Result<web::Json<Value>> {
    // Access auth information from request extensions
    let extensions = req.extensions();
    let auth = extensions.get::<AuthInfo>().unwrap();
    Ok(web::Json(json!({ "auth": auth })))
}
