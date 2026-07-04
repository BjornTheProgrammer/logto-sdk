use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::management_api::{LogtoClient, ManagementApiError, ResponseExt};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationColor {
    pub primary_color: Option<String>,
    pub is_dark_mode_enabled: Option<bool>,
    pub dark_primary_color: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationBranding {
    pub logo_url: Option<String>,
    pub dark_logo_url: Option<String>,
    pub favicon: Option<String>,
    pub dark_favicon: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    pub tenant_id: String,
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub custom_data: Value,
    pub is_mfa_required: bool,
    pub color: OrganizationColor,
    pub branding: OrganizationBranding,
    pub custom_css: Option<String>,
    pub created_at: i64,
    pub organization_roles: Vec<OrganizationRole>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationRole {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationUser {
    pub id: String,
    pub username: Option<String>,
    pub primary_email: Option<String>,
    pub primary_phone: Option<String>,
    pub name: Option<String>,
    pub avatar: Option<String>,
    pub created_at: i64,
    pub last_sign_in_at: Option<i64>,
    pub is_suspended: bool,
    pub organization_roles: Vec<OrganizationRole>,
}

#[derive(Debug)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchUser {
    pub id: String,
    pub primary_email: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Invitation {
    pub id: String,
    pub invitee: String,
    pub status: String,
    pub expires_at: i64,
}

pub struct Organizations<'a> {
    pub client: &'a LogtoClient,
}

impl<'a> Organizations<'a> {
    pub async fn get_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<Organization>, ManagementApiError> {
        let token = self.client.get_valid_token().await?;
        self.client
            .http
            .get(format!(
                "{}/users/{}/organizations",
                self.client.base_url(),
                user_id
            ))
            .bearer_auth(token.access_token)
            .send()
            .await
            .check_status()?
            .json::<Vec<Organization>>()
            .await
            .map_err(ManagementApiError::RequestFailed)
    }

    pub async fn get(&self, org_id: &str) -> Result<Organization, ManagementApiError> {
        let token = self.client.get_valid_token().await?;
        self.client
            .http
            .get(format!(
                "{}/organizations/{}",
                self.client.base_url(),
                org_id
            ))
            .bearer_auth(token.access_token)
            .send()
            .await
            .check_status()?
            .json::<Organization>()
            .await
            .map_err(ManagementApiError::RequestFailed)
    }

    pub async fn get_users(
        &self,
        org_id: &str,
        page: Option<u32>,
        page_size: Option<u32>,
    ) -> Result<PaginatedResponse<OrganizationUser>, ManagementApiError> {
        let token = self.client.get_valid_token().await?;

        let mut url = format!(
            "{}/organizations/{}/users",
            self.client.base_url(),
            org_id
        );
        let mut query_parts: Vec<String> = Vec::new();
        if let Some(p) = page {
            query_parts.push(format!("page={}", p));
        }
        if let Some(ps) = page_size {
            query_parts.push(format!("page_size={}", ps));
        }
        if !query_parts.is_empty() {
            url = format!("{}?{}", url, query_parts.join("&"));
        }

        let response = self
            .client
            .http
            .get(url)
            .bearer_auth(token.access_token)
            .send()
            .await
            .check_status()?;

        let total = response
            .headers()
            .get("Total-Number")
            .and_then(|v: &reqwest::header::HeaderValue| v.to_str().ok())
            .and_then(|v: &str| v.parse::<u32>().ok())
            .unwrap_or(0);

        let data = response
            .json::<Vec<OrganizationUser>>()
            .await
            .map_err(ManagementApiError::RequestFailed)?;

        Ok(PaginatedResponse { data, total })
    }

    pub async fn add_user(&self, org_id: &str, user_id: &str) -> Result<(), ManagementApiError> {
        let token = self.client.get_valid_token().await?;
        self.client
            .http
            .post(format!(
                "{}/organizations/{}/users",
                self.client.base_url(),
                org_id
            ))
            .bearer_auth(token.access_token)
            .json(&serde_json::json!({ "userIds": [user_id] }))
            .send()
            .await
            .check_status()?;
        Ok(())
    }

    pub async fn remove_user(
        &self,
        org_id: &str,
        user_id: &str,
    ) -> Result<(), ManagementApiError> {
        let token = self.client.get_valid_token().await?;
        self.client
            .http
            .delete(format!(
                "{}/organizations/{}/users/{}",
                self.client.base_url(),
                org_id,
                user_id
            ))
            .bearer_auth(token.access_token)
            .send()
            .await
            .check_status()?;
        Ok(())
    }

    /// Searches for users by email prefix (up to 20 results).
    pub async fn search_users(
        &self,
        email: &str,
    ) -> Result<Vec<SearchUser>, ManagementApiError> {
        let token = self.client.get_valid_token().await?;
        self.client
            .http
            .get(format!("{}/users", self.client.base_url()))
            .bearer_auth(token.access_token)
            .query(&[("search", email), ("pageSize", "20")])
            .send()
            .await
            .check_status()?
            .json()
            .await
            .map_err(ManagementApiError::RequestFailed)
    }

    pub async fn invite_user(
        &self,
        org_id: &str,
        invitee: &str,
        inviter_id: &str,
        expires_at: u64,
    ) -> Result<(), ManagementApiError> {
        let token = self.client.get_valid_token().await?;
        self.client
            .http
            .post(format!("{}/organization-invitations", self.client.base_url()))
            .bearer_auth(token.access_token)
            .json(&serde_json::json!({
                "invitee": invitee,
                "organizationId": org_id,
                "inviterId": inviter_id,
                "expiresAt": expires_at,
            }))
            .send()
            .await
            .check_status()?;
        Ok(())
    }

    /// Lists all pending invitations for the given organization.
    pub async fn list_invitations(
        &self,
        org_id: &str,
    ) -> Result<Vec<Invitation>, ManagementApiError> {
        let token = self.client.get_valid_token().await?;
        self.client
            .http
            .get(format!("{}/organization-invitations", self.client.base_url()))
            .bearer_auth(token.access_token)
            .query(&[("organizationId", org_id), ("pageSize", "100")])
            .send()
            .await
            .check_status()?
            .json()
            .await
            .map_err(ManagementApiError::RequestFailed)
    }

    pub async fn cancel_invitation(
        &self,
        invitation_id: &str,
    ) -> Result<(), ManagementApiError> {
        let token = self.client.get_valid_token().await?;
        self.client
            .http
            .delete(format!(
                "{}/organization-invitations/{}",
                self.client.base_url(),
                invitation_id
            ))
            .bearer_auth(token.access_token)
            .send()
            .await
            .check_status()?;
        Ok(())
    }
}
