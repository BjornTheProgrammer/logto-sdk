# Logto SDK

Unofficial Logto SDK for Rust with support for [axum](https://github.com/tokio-rs/axum),
[actix](https://actix.rs/), and [rocket](https://github.com/rwf2/Rocket).

## Installation

To add to your project just run

```toml
logto-sdk = { version = "0.1", features = ["axum"] } # do "actix-web" or "rocket" instead if not using axum
```

## Using the Logto API

You can use the `logto-sdk` to get access tokens as well as use the management api functionality.

```rust
use logto_sdk::auth_client::{LogtoAuthClient, M2mCredentials};

#[tokio::main]
async fn main() {
    let client = LogtoAuthClient::new(
        "XXXXXX", // Tenant id
        M2mCredentials::new("XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXX"), // Client id and secret
        vec!["all"], // scope
    );

    let access_token_response = client.get_access_token().await.unwrap();
    println!(
        "Recieved access token with response: {:?}",
        access_token_response
    );
}
```

## Usage as Middleware

Now that you have `logto-sdk` added as a dependency, you can very easily add a middleware
your framework. There are examples for each web framework in the [examples directory](https://github.com/BjornTheProgrammer/logto-sdk/tree/main/examples).
