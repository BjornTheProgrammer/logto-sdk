use logto_sdk::jwt::{GlobalApiResourceVerifier, JwtValidator, JwtValidatorConfig, auth::AuthInfo};
use rocket::{get, launch, routes, serde::json::Json};
use serde_json::{Value, json};

#[get("/api/protected")]
fn protected_handler(auth: AuthInfo) -> Json<Value> {
    // Access auth information directly from request guard
    Json(json!({ "auth": auth }))
}

#[launch]
async fn rocket() -> _ {
    let validator = JwtValidator::new(
        JwtValidatorConfig::with_tenant_id("XXXXXX"), // Set the tenant id here or there will be a panic
        Box::new(GlobalApiResourceVerifier::new(
            "https://XXXXXX.logto.app/api",
            vec!["all"],
        )),
    )
    .await
    .expect("Failed to initialize JWT validator");

    rocket::build()
        .manage(validator)
        .mount("/", routes![protected_handler])
}
