#[cfg(feature = "management-api")]
pub mod management_api;

#[cfg(feature = "auth-client")]
pub mod auth_client;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "actix-web")]
pub mod actix_web;

#[cfg(feature = "rocket")]
pub mod rocket;

#[cfg(feature = "jwt")]
pub mod jwt;
