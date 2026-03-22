use async_trait::async_trait;
use axum::extract::*;
use axum_extra::extract::CookieJar;
use bytes::Bytes;
use headers::Host;
use http::Method;
use serde::{Deserialize, Serialize};

use crate::{models, types::*};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum CreateMldsaVaultResponse {
    /// ML-DSA key creation task enqueued
    Status200_ML
    ,
    /// Validation error or malformed request
    Status400_ValidationErrorOrMalformedRequest
    (models::Error)
    ,
    /// Rate limit exceeded (10 req/s, 100 burst)
    Status429_RateLimitExceeded
    (models::Error)
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum CreateVaultResponse {
    /// Vault creation initiated
    Status200_VaultCreationInitiated
    (models::VaultCreateResponse)
    ,
    /// Validation error or malformed request
    Status400_ValidationErrorOrMalformedRequest
    (models::Error)
    ,
    /// Rate limit exceeded (10 req/s, 100 burst)
    Status429_RateLimitExceeded
    (models::Error)
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum ExistVaultResponse {
    /// Vault exists
    Status200_VaultExists
    ,
    /// Validation error or malformed request
    Status400_ValidationErrorOrMalformedRequest
    (models::Error)
    ,
    /// Vault not found
    Status404_VaultNotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum GetVaultResponse {
    /// Vault metadata
    Status200_VaultMetadata
    (models::VaultGetResponse)
    ,
    /// Validation error or malformed request
    Status400_ValidationErrorOrMalformedRequest
    (models::Error)
    ,
    /// Vault not found
    Status404_VaultNotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum ImportVaultResponse {
    /// Import task enqueued
    Status204_ImportTaskEnqueued
    ,
    /// Validation error or malformed request
    Status400_ValidationErrorOrMalformedRequest
    (models::Error)
    ,
    /// Rate limit exceeded (10 req/s, 100 burst)
    Status429_RateLimitExceeded
    (models::Error)
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum MigrateVaultResponse {
    /// Migration task enqueued
    Status204_MigrationTaskEnqueued
    ,
    /// Validation error or malformed request
    Status400_ValidationErrorOrMalformedRequest
    (models::Error)
    ,
    /// Rate limit exceeded (10 req/s, 100 burst)
    Status429_RateLimitExceeded
    (models::Error)
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum ReshareVaultResponse {
    /// Reshare task enqueued
    Status204_ReshareTaskEnqueued
    ,
    /// Validation error or malformed request
    Status400_ValidationErrorOrMalformedRequest
    (models::Error)
    ,
    /// Rate limit exceeded (10 req/s, 100 burst)
    Status429_RateLimitExceeded
    (models::Error)
}




/// Vault
#[async_trait]
#[allow(clippy::ptr_arg)]
pub trait Vault<E: std::fmt::Debug + Send + Sync + 'static = ()>: super::ErrorHandler<E> {
    /// Add ML-DSA key to existing vault.
    ///
    /// CreateMldsaVault - POST /vault/mldsa
    async fn create_mldsa_vault(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
            body: &models::CreateMldsaRequest,
    ) -> Result<CreateMldsaVaultResponse, E>;

    /// Create a new vault (keygen).
    ///
    /// CreateVault - POST /vault/create
    async fn create_vault(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
            body: &models::VaultCreateRequest,
    ) -> Result<CreateVaultResponse, E>;

    /// Check if a vault exists.
    ///
    /// ExistVault - GET /vault/exist/{publicKeyECDSA}
    async fn exist_vault(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
      path_params: &models::ExistVaultPathParams,
    ) -> Result<ExistVaultResponse, E>;

    /// Retrieve vault metadata.
    ///
    /// GetVault - GET /vault/get/{publicKeyECDSA}
    async fn get_vault(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
      header_params: &models::GetVaultHeaderParams,
      path_params: &models::GetVaultPathParams,
    ) -> Result<GetVaultResponse, E>;

    /// Import an existing vault.
    ///
    /// ImportVault - POST /vault/import
    async fn import_vault(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
            body: &models::KeyImportRequest,
    ) -> Result<ImportVaultResponse, E>;

    /// Migrate vault from GG20 to DKLS.
    ///
    /// MigrateVault - POST /vault/migrate
    async fn migrate_vault(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
            body: &models::MigrationRequest,
    ) -> Result<MigrateVaultResponse, E>;

    /// Reshare vault key shares.
    ///
    /// ReshareVault - POST /vault/reshare
    async fn reshare_vault(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
            body: &models::ReshareRequest,
    ) -> Result<ReshareVaultResponse, E>;
}
