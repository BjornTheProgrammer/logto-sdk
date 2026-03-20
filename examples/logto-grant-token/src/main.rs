use logto_sdk::auth_client::{LogtoAuthClient, M2mCredentials};

#[tokio::main]
async fn main() {
    let client = LogtoAuthClient::new(
        "XXXXXX", // Tenant id
        M2mCredentials::new("XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXX"),
        vec!["all"],
    );

    let access_token_response = client.get_access_token().await.unwrap();
    println!(
        "Recieved access token with response: {:?}",
        access_token_response
    );
}
