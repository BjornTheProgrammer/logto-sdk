use serde::Deserialize;

use crate::{auth_client::LogtoAuthError, management_api::LogtoClient};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountCenterSettings {
    pub tenant_id: String,
    pub id: String,
    pub enabled: bool,
    pub fields: AccountCenterFields,
    pub webauthn_related_origins: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountCenterFields {
    pub name: Option<FieldMode>,
    pub avatar: Option<FieldMode>,
    pub profile: Option<FieldMode>,
    pub email: Option<FieldMode>,
    pub phone: Option<FieldMode>,
    pub password: Option<FieldMode>,
    pub username: Option<FieldMode>,
    pub social: Option<FieldMode>,
    pub custom_data: Option<FieldMode>,
    pub mfa: Option<FieldMode>,
    pub session: Option<FieldMode>,
}

#[derive(Debug, Deserialize)]
pub enum FieldMode {
    Off,
    ReadOnly,
    Edit,
}

pub struct AccountCenter<'a> {
    pub client: &'a LogtoClient,
}

impl<'a> AccountCenter<'a> {
    pub async fn get(&self) -> Result<AccountCenterSettings, LogtoAuthError> {
        Ok(self
            .client
            .http
            .get(format!("{}/account-center", self.client.base_url()))
            .bearer_auth(self.client.get_valid_token().await?.access_token)
            .send()
            .await?
            .error_for_status()?
            .json::<AccountCenterSettings>()
            .await?)
    }
}
