use axum_extra::extract::CookieJar;
use headers::Host;
use http::Method;

use basalt_networking_api_server::apis;
use basalt_networking_api_server::models;

use basalt_vultiserver_client::apis::vault_api;
use basalt_vultiserver_client::models as vs_models;

use crate::error::{convert, map_upstream_error};
use crate::ApiImpl;

#[async_trait::async_trait]
impl apis::vault::Vault for ApiImpl {
    async fn create_mldsa_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::CreateMldsaRequest,
    ) -> Result<apis::vault::CreateMldsaVaultResponse, ()> {
        let req: vs_models::CreateMldsaRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match vault_api::create_mldsa_vault(&self.vultiserver_client, req).await {
            Ok(()) => Ok(apis::vault::CreateMldsaVaultResponse::Status200_ML),
            Err(err) => {
                let (status, error) = map_upstream_error(err);
                match status {
                    400 => Ok(apis::vault::CreateMldsaVaultResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::vault::CreateMldsaVaultResponse::Status429_RateLimitExceeded(error)),
                    _ => {
                        tracing::error!("create_mldsa_vault unexpected upstream status {status}: {error:?}");
                        Err(())
                    }
                }
            }
        }
    }

    async fn create_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::VaultCreateRequest,
    ) -> Result<apis::vault::CreateVaultResponse, ()> {
        let req: vs_models::VaultCreateRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match vault_api::create_vault(&self.vultiserver_client, req).await {
            Ok(()) => {
                Ok(apis::vault::CreateVaultResponse::Status200_VaultCreationInitiated)
            }
            Err(err) => {
                let (status, error) = map_upstream_error(err);
                match status {
                    400 => Ok(apis::vault::CreateVaultResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::vault::CreateVaultResponse::Status429_RateLimitExceeded(error)),
                    _ => {
                        tracing::error!("create_vault unexpected upstream status {status}: {error:?}");
                        Err(())
                    }
                }
            }
        }
    }

    async fn exist_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        path_params: &models::ExistVaultPathParams,
    ) -> Result<apis::vault::ExistVaultResponse, ()> {
        match vault_api::exist_vault(&self.vultiserver_client, &path_params.public_key_ecdsa).await
        {
            Ok(()) => Ok(apis::vault::ExistVaultResponse::Status200_VaultExists),
            Err(err) => {
                let (status, error) = map_upstream_error(err);
                match status {
                    400 => Ok(apis::vault::ExistVaultResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    404 => Ok(apis::vault::ExistVaultResponse::Status404_VaultNotFound),
                    _ => {
                        tracing::error!("exist_vault unexpected upstream status {status}: {error:?}");
                        Err(())
                    }
                }
            }
        }
    }

    async fn get_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        header_params: &models::GetVaultHeaderParams,
        path_params: &models::GetVaultPathParams,
    ) -> Result<apis::vault::GetVaultResponse, ()> {
        match vault_api::get_vault(
            &self.vultiserver_client,
            &path_params.public_key_ecdsa,
            &header_params.x_password,
        )
        .await
        {
            Ok(resp) => {
                let resp: models::VaultGetResponse = convert(&resp).map_err(|e| {
                    tracing::error!("response conversion error: {e}");
                })?;
                Ok(apis::vault::GetVaultResponse::Status200_VaultMetadata(resp))
            }
            Err(err) => {
                let (status, error) = map_upstream_error(err);
                match status {
                    400 => Ok(apis::vault::GetVaultResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    404 => Ok(apis::vault::GetVaultResponse::Status404_VaultNotFound),
                    _ => {
                        tracing::error!("get_vault unexpected upstream status {status}: {error:?}");
                        Err(())
                    }
                }
            }
        }
    }

    async fn import_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::KeyImportRequest,
    ) -> Result<apis::vault::ImportVaultResponse, ()> {
        let req: vs_models::KeyImportRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match vault_api::import_vault(&self.vultiserver_client, req).await {
            Ok(()) => Ok(apis::vault::ImportVaultResponse::Status204_ImportTaskEnqueued),
            Err(err) => {
                let (status, error) = map_upstream_error(err);
                match status {
                    400 => Ok(apis::vault::ImportVaultResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::vault::ImportVaultResponse::Status429_RateLimitExceeded(error)),
                    _ => {
                        tracing::error!("import_vault unexpected upstream status {status}: {error:?}");
                        Err(())
                    }
                }
            }
        }
    }

    async fn migrate_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::MigrationRequest,
    ) -> Result<apis::vault::MigrateVaultResponse, ()> {
        let req: vs_models::MigrationRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match vault_api::migrate_vault(&self.vultiserver_client, req).await {
            Ok(()) => Ok(apis::vault::MigrateVaultResponse::Status204_MigrationTaskEnqueued),
            Err(err) => {
                let (status, error) = map_upstream_error(err);
                match status {
                    400 => Ok(apis::vault::MigrateVaultResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::vault::MigrateVaultResponse::Status429_RateLimitExceeded(error)),
                    _ => {
                        tracing::error!("migrate_vault unexpected upstream status {status}: {error:?}");
                        Err(())
                    }
                }
            }
        }
    }

    async fn reshare_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::ReshareRequest,
    ) -> Result<apis::vault::ReshareVaultResponse, ()> {
        let req: vs_models::ReshareRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match vault_api::reshare_vault(&self.vultiserver_client, req).await {
            Ok(()) => Ok(apis::vault::ReshareVaultResponse::Status204_ReshareTaskEnqueued),
            Err(err) => {
                let (status, error) = map_upstream_error(err);
                match status {
                    400 => Ok(apis::vault::ReshareVaultResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::vault::ReshareVaultResponse::Status429_RateLimitExceeded(error)),
                    _ => {
                        tracing::error!("reshare_vault unexpected upstream status {status}: {error:?}");
                        Err(())
                    }
                }
            }
        }
    }
}
