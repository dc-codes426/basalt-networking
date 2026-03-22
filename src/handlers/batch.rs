use axum_extra::extract::CookieJar;
use headers::Host;
use http::Method;

use basalt_networking_api_server::apis;
use basalt_networking_api_server::models;

use basalt_vultiserver_client::apis::batch_api;
use basalt_vultiserver_client::models as vs_models;

use crate::error::{convert, map_upstream_error};
use crate::ApiImpl;

#[async_trait::async_trait]
impl apis::batch::Batch for ApiImpl {
    async fn create_vault_batch(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::BatchVaultRequest,
    ) -> Result<apis::batch::CreateVaultBatchResponse, ()> {
        let req: vs_models::BatchVaultRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match batch_api::create_vault_batch(&self.vultiserver_client, req).await {
            Ok(()) => Ok(apis::batch::CreateVaultBatchResponse::Status204_BatchKeygenTaskEnqueued),
            Err(err) => {
                let (status, error) = map_upstream_error(err);
                match status {
                    400 => Ok(apis::batch::CreateVaultBatchResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::batch::CreateVaultBatchResponse::Status429_RateLimitExceeded(error)),
                    _ => Err(()),
                }
            }
        }
    }

    async fn import_vault_batch(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::BatchImportRequest,
    ) -> Result<apis::batch::ImportVaultBatchResponse, ()> {
        let req: vs_models::BatchImportRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match batch_api::import_vault_batch(&self.vultiserver_client, req).await {
            Ok(()) => Ok(apis::batch::ImportVaultBatchResponse::Status204_BatchImportTaskEnqueued),
            Err(err) => {
                let (status, error) = map_upstream_error(err);
                match status {
                    400 => Ok(apis::batch::ImportVaultBatchResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::batch::ImportVaultBatchResponse::Status429_RateLimitExceeded(error)),
                    _ => Err(()),
                }
            }
        }
    }

    async fn reshare_vault_batch(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::BatchReshareRequest,
    ) -> Result<apis::batch::ReshareVaultBatchResponse, ()> {
        let req: vs_models::BatchReshareRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match batch_api::reshare_vault_batch(&self.vultiserver_client, req).await {
            Ok(()) => {
                Ok(apis::batch::ReshareVaultBatchResponse::Status204_BatchReshareTaskEnqueued)
            }
            Err(err) => {
                let (status, error) = map_upstream_error(err);
                match status {
                    400 => Ok(apis::batch::ReshareVaultBatchResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::batch::ReshareVaultBatchResponse::Status429_RateLimitExceeded(error)),
                    _ => Err(()),
                }
            }
        }
    }
}
