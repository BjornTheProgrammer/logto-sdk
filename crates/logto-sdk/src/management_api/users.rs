use serde::Deserialize;

use crate::management_api::{LogtoClient, ManagementApiError, ResponseExt};

/// A global (tenant-wide) role, as opposed to the per-organization roles
/// in [`crate::management_api::organizations`].
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

pub struct Users<'a> {
    pub client: &'a LogtoClient,
}

impl<'a> Users<'a> {
    /// The user's global roles (GET /users/{id}/roles).
    pub async fn get_roles(&self, user_id: &str) -> Result<Vec<Role>, ManagementApiError> {
        let token = self.client.get_valid_token().await?;
        self.client
            .http
            .get(format!("{}/users/{}/roles", self.client.base_url(), user_id))
            .bearer_auth(token.access_token)
            .query(&[("page", "1"), ("page_size", "100")])
            .send()
            .await
            .check_status()?
            .json()
            .await
            .map_err(ManagementApiError::RequestFailed)
    }
}
