use rocket::{
    State,
    http::Status,
    outcome::Outcome,
    request::{self, FromRequest, Request},
};

use crate::jwt::{
    JwtValidator,
    auth::{AuthInfo, AuthorizationError, extract_bearer_token},
};

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthInfo {
    type Error = AuthorizationError;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let validator = match req.guard::<&State<JwtValidator>>().await {
            Outcome::Success(validator) => validator,
            Outcome::Error((status, _)) => {
                return Outcome::Error((
                    status,
                    AuthorizationError::with_status("JWT validator not found", 500),
                ));
            }
            Outcome::Forward(val) => return Outcome::Forward(val),
        };

        let authorization = req.headers().get_one("authorization");

        match extract_bearer_token(authorization).and_then(|token| validator.validate_jwt(token)) {
            Ok(auth_info) => Outcome::Success(auth_info),
            Err(e) => {
                let status = Status::from_code(e.status_code).unwrap_or(Status::Forbidden);
                Outcome::Error((status, e))
            }
        }
    }
}
