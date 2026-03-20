# Logto SDK

Unofficial Logto SDK for Rust with support for [axum](https://github.com/tokio-rs/axum),
[actix](https://actix.rs/), and [rocket](https://github.com/rwf2/Rocket).

## Installation

To add to your project just run

```toml
logto-sdk = { version = "0.1", features = ["axum"] } # do "actix-web" or "rocket" instead if not using axum
```

## Using the Logto API

You can use the `logto-sdk` to get access tokens as well as use the management api.

## Usage as Middleware

Now that you have `logto-sdk` added as a dependency, you can very easily add a middleware
your framework.
