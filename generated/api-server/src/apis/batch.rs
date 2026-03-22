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
pub enum CreateVaultBatchResponse {
    /// Batch keygen task enqueued
    Status204_BatchKeygenTaskEnqueued
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
pub enum ImportVaultBatchResponse {
    /// Batch import task enqueued
    Status204_BatchImportTaskEnqueued
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
pub enum ReshareVaultBatchResponse {
    /// Batch reshare task enqueued
    Status204_BatchReshareTaskEnqueued
    ,
    /// Validation error or malformed request
    Status400_ValidationErrorOrMalformedRequest
    (models::Error)
    ,
    /// Rate limit exceeded (10 req/s, 100 burst)
    Status429_RateLimitExceeded
    (models::Error)
}




/// Batch
#[async_trait]
#[allow(clippy::ptr_arg)]
pub trait Batch<E: std::fmt::Debug + Send + Sync + 'static = ()>: super::ErrorHandler<E> {
    /// Batch vault creation.
    ///
    /// CreateVaultBatch - POST /vault/batch/keygen
    async fn create_vault_batch(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
            body: &models::BatchVaultRequest,
    ) -> Result<CreateVaultBatchResponse, E>;

    /// Batch vault import.
    ///
    /// ImportVaultBatch - POST /vault/batch/import
    async fn import_vault_batch(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
            body: &models::BatchImportRequest,
    ) -> Result<ImportVaultBatchResponse, E>;

    /// Batch vault reshare.
    ///
    /// ReshareVaultBatch - POST /vault/batch/reshare
    async fn reshare_vault_batch(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
            body: &models::BatchReshareRequest,
    ) -> Result<ReshareVaultBatchResponse, E>;
}
