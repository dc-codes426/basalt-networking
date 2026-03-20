#![allow(unused_qualifications)]

use http::HeaderValue;
use validator::Validate;

#[cfg(feature = "server")]
use crate::header;
use crate::{models, types::*};

#[allow(dead_code)]
fn from_validation_error(e: validator::ValidationError) -> validator::ValidationErrors {
  let mut errs = validator::ValidationErrors::new();
  errs.add("na", e);
  errs
}

#[allow(dead_code)]
pub fn check_xss_string(v: &str) -> std::result::Result<(), validator::ValidationError> {
    if ammonia::is_html(v) {
        std::result::Result::Err(validator::ValidationError::new("xss detected"))
    } else {
        std::result::Result::Ok(())
    }
}

#[allow(dead_code)]
pub fn check_xss_vec_string(v: &[String]) -> std::result::Result<(), validator::ValidationError> {
    if v.iter().any(|i| ammonia::is_html(i)) {
        std::result::Result::Err(validator::ValidationError::new("xss detected"))
    } else {
        std::result::Result::Ok(())
    }
}

#[allow(dead_code)]
pub fn check_xss_map_string(
    v: &std::collections::HashMap<String, String>,
) -> std::result::Result<(), validator::ValidationError> {
    if v.keys().any(|k| ammonia::is_html(k)) || v.values().any(|v| ammonia::is_html(v)) {
        std::result::Result::Err(validator::ValidationError::new("xss detected"))
    } else {
        std::result::Result::Ok(())
    }
}

#[allow(dead_code)]
pub fn check_xss_map_nested<T>(
    v: &std::collections::HashMap<String, T>,
) -> std::result::Result<(), validator::ValidationError>
where
    T: validator::Validate,
{
    if v.keys().any(|k| ammonia::is_html(k)) || v.values().any(|v| v.validate().is_err()) {
        std::result::Result::Err(validator::ValidationError::new("xss detected"))
    } else {
        std::result::Result::Ok(())
    }
}

#[allow(dead_code)]
pub fn check_xss_map<T>(v: &std::collections::HashMap<String, T>) -> std::result::Result<(), validator::ValidationError> {
    if v.keys().any(|k| ammonia::is_html(k)) {
        std::result::Result::Err(validator::ValidationError::new("xss detected"))
    } else {
        std::result::Result::Ok(())
    }
}







    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
    #[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
    pub struct GetDerivedPublicKeyQueryParams {
            /// Base public key (hex-encoded)
                #[serde(rename = "publicKey")]
                    pub public_key: String,
            /// Chain code in hexadecimal format
                #[serde(rename = "hexChainCode")]
                    pub hex_chain_code: String,
            /// BIP-32 style derivation path (e.g. `m/44'/60'/0'/0/0`)
                #[serde(rename = "derivePath")]
                    pub derive_path: String,
            /// Use EdDSA curve instead of ECDSA. Defaults to false.
                #[serde(rename = "isEdDSA")]
                    #[serde(skip_serializing_if="Option::is_none")]
                    pub is_ed_dsa: Option<bool>,
    }




    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
    #[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
    pub struct ExistVaultPathParams {
            /// 66-character hex-encoded ECDSA public key identifying the vault
                #[validate(
                        length(min = 66, max = 66),
                          regex(path = *RE_EXISTVAULTPATHPARAMS_PUBLIC_KEY_ECDSA),
            )]
                pub public_key_ecdsa: String,
    }

    lazy_static::lazy_static! {
        static ref RE_EXISTVAULTPATHPARAMS_PUBLIC_KEY_ECDSA: regex::Regex = regex::Regex::new("^[0-9a-fA-F]{66}$").unwrap();
    }


    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
    #[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
    pub struct GetVaultHeaderParams {
        pub x_password: String,
    }


    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
    #[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
    pub struct GetVaultPathParams {
            /// 66-character hex-encoded ECDSA public key identifying the vault
                #[validate(
                        length(min = 66, max = 66),
                          regex(path = *RE_GETVAULTPATHPARAMS_PUBLIC_KEY_ECDSA),
            )]
                pub public_key_ecdsa: String,
    }

    lazy_static::lazy_static! {
        static ref RE_GETVAULTPATHPARAMS_PUBLIC_KEY_ECDSA: regex::Regex = regex::Regex::new("^[0-9a-fA-F]{66}$").unwrap();
    }






#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct BatchImportRequest {
    /// Unique session identifier (UUID)
    #[serde(rename = "session_id")]
    pub session_id: uuid::Uuid,

    /// 32-byte hex-encoded encryption key
    #[serde(rename = "hex_encryption_key")]
    #[validate(
            regex(path = *RE_BATCHIMPORTREQUEST_HEX_ENCRYPTION_KEY),
          custom(function = "check_xss_string"),
    )]
    pub hex_encryption_key: String,

    /// Local TSS party identifier
    #[serde(rename = "local_party_id")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub local_party_id: Option<String>,

    /// Encryption password for the vault
    #[serde(rename = "encryption_password")]
          #[validate(custom(function = "check_xss_string"))]
    pub encryption_password: String,

    /// List of protocols to import across (must not contain duplicates)
    #[serde(rename = "protocols")]
    #[validate(
          custom(function = "check_xss_vec_string"),
    )]
    pub protocols: Vec<String>,

    /// List of blockchain chains to import
    #[serde(rename = "chains")]
          #[validate(custom(function = "check_xss_vec_string"))]
    pub chains: Vec<String>,

}


lazy_static::lazy_static! {
    static ref RE_BATCHIMPORTREQUEST_HEX_ENCRYPTION_KEY: regex::Regex = regex::Regex::new("^[0-9a-fA-F]{64}$").unwrap();
}

impl BatchImportRequest {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(session_id: uuid::Uuid, hex_encryption_key: String, encryption_password: String, protocols: Vec<String>, chains: Vec<String>, ) -> BatchImportRequest {
        BatchImportRequest {
 session_id,
 hex_encryption_key,
 local_party_id: None,
 encryption_password,
 protocols,
 chains,
        }
    }
}

/// Converts the BatchImportRequest value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for BatchImportRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![
            // Skipping session_id in query parameter serialization


            Some("hex_encryption_key".to_string()),
            Some(self.hex_encryption_key.to_string()),


            self.local_party_id.as_ref().map(|local_party_id| {
                [
                    "local_party_id".to_string(),
                    local_party_id.to_string(),
                ].join(",")
            }),


            Some("encryption_password".to_string()),
            Some(self.encryption_password.to_string()),


            Some("protocols".to_string()),
            Some(self.protocols.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")),


            Some("chains".to_string()),
            Some(self.chains.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")),

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a BatchImportRequest value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for BatchImportRequest {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub session_id: Vec<uuid::Uuid>,
            pub hex_encryption_key: Vec<String>,
            pub local_party_id: Vec<String>,
            pub encryption_password: Vec<String>,
            pub protocols: Vec<Vec<String>>,
            pub chains: Vec<Vec<String>>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing BatchImportRequest".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "session_id" => intermediate_rep.session_id.push(<uuid::Uuid as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_encryption_key" => intermediate_rep.hex_encryption_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "local_party_id" => intermediate_rep.local_party_id.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "encryption_password" => intermediate_rep.encryption_password.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    "protocols" => return std::result::Result::Err("Parsing a container in this style is not supported in BatchImportRequest".to_string()),
                    "chains" => return std::result::Result::Err("Parsing a container in this style is not supported in BatchImportRequest".to_string()),
                    _ => return std::result::Result::Err("Unexpected key while parsing BatchImportRequest".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(BatchImportRequest {
            session_id: intermediate_rep.session_id.into_iter().next().ok_or_else(|| "session_id missing in BatchImportRequest".to_string())?,
            hex_encryption_key: intermediate_rep.hex_encryption_key.into_iter().next().ok_or_else(|| "hex_encryption_key missing in BatchImportRequest".to_string())?,
            local_party_id: intermediate_rep.local_party_id.into_iter().next(),
            encryption_password: intermediate_rep.encryption_password.into_iter().next().ok_or_else(|| "encryption_password missing in BatchImportRequest".to_string())?,
            protocols: intermediate_rep.protocols.into_iter().next().ok_or_else(|| "protocols missing in BatchImportRequest".to_string())?,
            chains: intermediate_rep.chains.into_iter().next().ok_or_else(|| "chains missing in BatchImportRequest".to_string())?,
        })
    }
}

// Methods for converting between header::IntoHeaderValue<BatchImportRequest> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<BatchImportRequest>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<BatchImportRequest>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for BatchImportRequest - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<BatchImportRequest> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <BatchImportRequest as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into BatchImportRequest - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct BatchReshareRequest {
    /// Existing vault public key
    #[serde(rename = "public_key")]
          #[validate(custom(function = "check_xss_string"))]
    pub public_key: String,

    /// Unique session identifier (UUID)
    #[serde(rename = "session_id")]
    pub session_id: uuid::Uuid,

    /// 32-byte hex-encoded encryption key
    #[serde(rename = "hex_encryption_key")]
    #[validate(
            regex(path = *RE_BATCHRESHAREREQUEST_HEX_ENCRYPTION_KEY),
          custom(function = "check_xss_string"),
    )]
    pub hex_encryption_key: String,

    /// Local TSS party identifier
    #[serde(rename = "local_party_id")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub local_party_id: Option<String>,

    /// Encryption password for the vault
    #[serde(rename = "encryption_password")]
          #[validate(custom(function = "check_xss_string"))]
    pub encryption_password: String,

    /// List of party IDs from the previous share set
    #[serde(rename = "old_parties")]
          #[validate(custom(function = "check_xss_vec_string"))]
    pub old_parties: Vec<String>,

    /// List of protocols to reshare across
    #[serde(rename = "protocols")]
          #[validate(custom(function = "check_xss_vec_string"))]
    pub protocols: Vec<String>,

}


lazy_static::lazy_static! {
    static ref RE_BATCHRESHAREREQUEST_HEX_ENCRYPTION_KEY: regex::Regex = regex::Regex::new("^[0-9a-fA-F]{64}$").unwrap();
}

impl BatchReshareRequest {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(public_key: String, session_id: uuid::Uuid, hex_encryption_key: String, encryption_password: String, old_parties: Vec<String>, protocols: Vec<String>, ) -> BatchReshareRequest {
        BatchReshareRequest {
 public_key,
 session_id,
 hex_encryption_key,
 local_party_id: None,
 encryption_password,
 old_parties,
 protocols,
        }
    }
}

/// Converts the BatchReshareRequest value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for BatchReshareRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![

            Some("public_key".to_string()),
            Some(self.public_key.to_string()),

            // Skipping session_id in query parameter serialization


            Some("hex_encryption_key".to_string()),
            Some(self.hex_encryption_key.to_string()),


            self.local_party_id.as_ref().map(|local_party_id| {
                [
                    "local_party_id".to_string(),
                    local_party_id.to_string(),
                ].join(",")
            }),


            Some("encryption_password".to_string()),
            Some(self.encryption_password.to_string()),


            Some("old_parties".to_string()),
            Some(self.old_parties.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")),


            Some("protocols".to_string()),
            Some(self.protocols.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")),

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a BatchReshareRequest value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for BatchReshareRequest {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub public_key: Vec<String>,
            pub session_id: Vec<uuid::Uuid>,
            pub hex_encryption_key: Vec<String>,
            pub local_party_id: Vec<String>,
            pub encryption_password: Vec<String>,
            pub old_parties: Vec<Vec<String>>,
            pub protocols: Vec<Vec<String>>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing BatchReshareRequest".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "public_key" => intermediate_rep.public_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "session_id" => intermediate_rep.session_id.push(<uuid::Uuid as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_encryption_key" => intermediate_rep.hex_encryption_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "local_party_id" => intermediate_rep.local_party_id.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "encryption_password" => intermediate_rep.encryption_password.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    "old_parties" => return std::result::Result::Err("Parsing a container in this style is not supported in BatchReshareRequest".to_string()),
                    "protocols" => return std::result::Result::Err("Parsing a container in this style is not supported in BatchReshareRequest".to_string()),
                    _ => return std::result::Result::Err("Unexpected key while parsing BatchReshareRequest".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(BatchReshareRequest {
            public_key: intermediate_rep.public_key.into_iter().next().ok_or_else(|| "public_key missing in BatchReshareRequest".to_string())?,
            session_id: intermediate_rep.session_id.into_iter().next().ok_or_else(|| "session_id missing in BatchReshareRequest".to_string())?,
            hex_encryption_key: intermediate_rep.hex_encryption_key.into_iter().next().ok_or_else(|| "hex_encryption_key missing in BatchReshareRequest".to_string())?,
            local_party_id: intermediate_rep.local_party_id.into_iter().next(),
            encryption_password: intermediate_rep.encryption_password.into_iter().next().ok_or_else(|| "encryption_password missing in BatchReshareRequest".to_string())?,
            old_parties: intermediate_rep.old_parties.into_iter().next().ok_or_else(|| "old_parties missing in BatchReshareRequest".to_string())?,
            protocols: intermediate_rep.protocols.into_iter().next().ok_or_else(|| "protocols missing in BatchReshareRequest".to_string())?,
        })
    }
}

// Methods for converting between header::IntoHeaderValue<BatchReshareRequest> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<BatchReshareRequest>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<BatchReshareRequest>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for BatchReshareRequest - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<BatchReshareRequest> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <BatchReshareRequest as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into BatchReshareRequest - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct BatchVaultRequest {
    /// Unique session identifier (UUID)
    #[serde(rename = "session_id")]
    pub session_id: uuid::Uuid,

    /// 32-byte hex-encoded encryption key
    #[serde(rename = "hex_encryption_key")]
    #[validate(
            regex(path = *RE_BATCHVAULTREQUEST_HEX_ENCRYPTION_KEY),
          custom(function = "check_xss_string"),
    )]
    pub hex_encryption_key: String,

    /// Hex-encoded chain code
    #[serde(rename = "hex_chain_code")]
          #[validate(custom(function = "check_xss_string"))]
    pub hex_chain_code: String,

    /// Local TSS party identifier
    #[serde(rename = "local_party_id")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub local_party_id: Option<String>,

    /// Encryption password for the vault
    #[serde(rename = "encryption_password")]
          #[validate(custom(function = "check_xss_string"))]
    pub encryption_password: String,

    #[serde(rename = "lib_type")]
          #[validate(nested)]
    #[serde(skip_serializing_if="Option::is_none")]
    pub lib_type: Option<models::LibType>,

    /// List of protocols to run keygen across
    #[serde(rename = "protocols")]
          #[validate(custom(function = "check_xss_vec_string"))]
    pub protocols: Vec<String>,

    /// Existing public key (optional, for adding protocols to existing vault)
    #[serde(rename = "public_key")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub public_key: Option<String>,

}


lazy_static::lazy_static! {
    static ref RE_BATCHVAULTREQUEST_HEX_ENCRYPTION_KEY: regex::Regex = regex::Regex::new("^[0-9a-fA-F]{64}$").unwrap();
}

impl BatchVaultRequest {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(session_id: uuid::Uuid, hex_encryption_key: String, hex_chain_code: String, encryption_password: String, protocols: Vec<String>, ) -> BatchVaultRequest {
        BatchVaultRequest {
 session_id,
 hex_encryption_key,
 hex_chain_code,
 local_party_id: None,
 encryption_password,
 lib_type: None,
 protocols,
 public_key: None,
        }
    }
}

/// Converts the BatchVaultRequest value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for BatchVaultRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![
            // Skipping session_id in query parameter serialization


            Some("hex_encryption_key".to_string()),
            Some(self.hex_encryption_key.to_string()),


            Some("hex_chain_code".to_string()),
            Some(self.hex_chain_code.to_string()),


            self.local_party_id.as_ref().map(|local_party_id| {
                [
                    "local_party_id".to_string(),
                    local_party_id.to_string(),
                ].join(",")
            }),


            Some("encryption_password".to_string()),
            Some(self.encryption_password.to_string()),

            // Skipping lib_type in query parameter serialization


            Some("protocols".to_string()),
            Some(self.protocols.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")),


            self.public_key.as_ref().map(|public_key| {
                [
                    "public_key".to_string(),
                    public_key.to_string(),
                ].join(",")
            }),

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a BatchVaultRequest value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for BatchVaultRequest {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub session_id: Vec<uuid::Uuid>,
            pub hex_encryption_key: Vec<String>,
            pub hex_chain_code: Vec<String>,
            pub local_party_id: Vec<String>,
            pub encryption_password: Vec<String>,
            pub lib_type: Vec<models::LibType>,
            pub protocols: Vec<Vec<String>>,
            pub public_key: Vec<String>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing BatchVaultRequest".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "session_id" => intermediate_rep.session_id.push(<uuid::Uuid as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_encryption_key" => intermediate_rep.hex_encryption_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_chain_code" => intermediate_rep.hex_chain_code.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "local_party_id" => intermediate_rep.local_party_id.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "encryption_password" => intermediate_rep.encryption_password.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "lib_type" => intermediate_rep.lib_type.push(<models::LibType as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    "protocols" => return std::result::Result::Err("Parsing a container in this style is not supported in BatchVaultRequest".to_string()),
                    #[allow(clippy::redundant_clone)]
                    "public_key" => intermediate_rep.public_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    _ => return std::result::Result::Err("Unexpected key while parsing BatchVaultRequest".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(BatchVaultRequest {
            session_id: intermediate_rep.session_id.into_iter().next().ok_or_else(|| "session_id missing in BatchVaultRequest".to_string())?,
            hex_encryption_key: intermediate_rep.hex_encryption_key.into_iter().next().ok_or_else(|| "hex_encryption_key missing in BatchVaultRequest".to_string())?,
            hex_chain_code: intermediate_rep.hex_chain_code.into_iter().next().ok_or_else(|| "hex_chain_code missing in BatchVaultRequest".to_string())?,
            local_party_id: intermediate_rep.local_party_id.into_iter().next(),
            encryption_password: intermediate_rep.encryption_password.into_iter().next().ok_or_else(|| "encryption_password missing in BatchVaultRequest".to_string())?,
            lib_type: intermediate_rep.lib_type.into_iter().next(),
            protocols: intermediate_rep.protocols.into_iter().next().ok_or_else(|| "protocols missing in BatchVaultRequest".to_string())?,
            public_key: intermediate_rep.public_key.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<BatchVaultRequest> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<BatchVaultRequest>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<BatchVaultRequest>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for BatchVaultRequest - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<BatchVaultRequest> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <BatchVaultRequest as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into BatchVaultRequest - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct CreateMldsaRequest {
    /// 66-character hex-encoded ECDSA public key of the existing vault
    #[serde(rename = "public_key")]
    #[validate(
            regex(path = *RE_CREATEMLDSAREQUEST_PUBLIC_KEY),
          custom(function = "check_xss_string"),
    )]
    pub public_key: String,

    /// Unique session identifier (UUID)
    #[serde(rename = "session_id")]
    pub session_id: uuid::Uuid,

    /// 32-byte hex-encoded encryption key
    #[serde(rename = "hex_encryption_key")]
    #[validate(
            regex(path = *RE_CREATEMLDSAREQUEST_HEX_ENCRYPTION_KEY),
          custom(function = "check_xss_string"),
    )]
    pub hex_encryption_key: String,

    /// Encryption password for the vault
    #[serde(rename = "encryption_password")]
          #[validate(custom(function = "check_xss_string"))]
    pub encryption_password: String,

}


lazy_static::lazy_static! {
    static ref RE_CREATEMLDSAREQUEST_PUBLIC_KEY: regex::Regex = regex::Regex::new("^[0-9a-fA-F]{66}$").unwrap();
}
lazy_static::lazy_static! {
    static ref RE_CREATEMLDSAREQUEST_HEX_ENCRYPTION_KEY: regex::Regex = regex::Regex::new("^[0-9a-fA-F]{64}$").unwrap();
}

impl CreateMldsaRequest {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(public_key: String, session_id: uuid::Uuid, hex_encryption_key: String, encryption_password: String, ) -> CreateMldsaRequest {
        CreateMldsaRequest {
 public_key,
 session_id,
 hex_encryption_key,
 encryption_password,
        }
    }
}

/// Converts the CreateMldsaRequest value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for CreateMldsaRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![

            Some("public_key".to_string()),
            Some(self.public_key.to_string()),

            // Skipping session_id in query parameter serialization


            Some("hex_encryption_key".to_string()),
            Some(self.hex_encryption_key.to_string()),


            Some("encryption_password".to_string()),
            Some(self.encryption_password.to_string()),

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a CreateMldsaRequest value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for CreateMldsaRequest {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub public_key: Vec<String>,
            pub session_id: Vec<uuid::Uuid>,
            pub hex_encryption_key: Vec<String>,
            pub encryption_password: Vec<String>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing CreateMldsaRequest".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "public_key" => intermediate_rep.public_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "session_id" => intermediate_rep.session_id.push(<uuid::Uuid as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_encryption_key" => intermediate_rep.hex_encryption_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "encryption_password" => intermediate_rep.encryption_password.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    _ => return std::result::Result::Err("Unexpected key while parsing CreateMldsaRequest".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(CreateMldsaRequest {
            public_key: intermediate_rep.public_key.into_iter().next().ok_or_else(|| "public_key missing in CreateMldsaRequest".to_string())?,
            session_id: intermediate_rep.session_id.into_iter().next().ok_or_else(|| "session_id missing in CreateMldsaRequest".to_string())?,
            hex_encryption_key: intermediate_rep.hex_encryption_key.into_iter().next().ok_or_else(|| "hex_encryption_key missing in CreateMldsaRequest".to_string())?,
            encryption_password: intermediate_rep.encryption_password.into_iter().next().ok_or_else(|| "encryption_password missing in CreateMldsaRequest".to_string())?,
        })
    }
}

// Methods for converting between header::IntoHeaderValue<CreateMldsaRequest> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<CreateMldsaRequest>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<CreateMldsaRequest>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for CreateMldsaRequest - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<CreateMldsaRequest> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <CreateMldsaRequest as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into CreateMldsaRequest - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct Error {
    /// Human-readable error message
    #[serde(rename = "message")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub message: Option<String>,

}



impl Error {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new() -> Error {
        Error {
 message: None,
        }
    }
}

/// Converts the Error value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![

            self.message.as_ref().map(|message| {
                [
                    "message".to_string(),
                    message.to_string(),
                ].join(",")
            }),

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a Error value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for Error {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub message: Vec<String>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing Error".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "message" => intermediate_rep.message.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    _ => return std::result::Result::Err("Unexpected key while parsing Error".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(Error {
            message: intermediate_rep.message.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<Error> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<Error>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<Error>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for Error - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<Error> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <Error as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into Error - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct KeyImportRequest {
    /// Unique session identifier (UUID)
    #[serde(rename = "session_id")]
    pub session_id: uuid::Uuid,

    /// 32-byte hex-encoded encryption key
    #[serde(rename = "hex_encryption_key")]
    #[validate(
            regex(path = *RE_KEYIMPORTREQUEST_HEX_ENCRYPTION_KEY),
          custom(function = "check_xss_string"),
    )]
    pub hex_encryption_key: String,

    /// Hex-encoded chain code
    #[serde(rename = "hex_chain_code")]
          #[validate(custom(function = "check_xss_string"))]
    pub hex_chain_code: String,

    /// Local TSS party identifier
    #[serde(rename = "local_party_id")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub local_party_id: Option<String>,

    /// Encryption password for the vault
    #[serde(rename = "encryption_password")]
          #[validate(custom(function = "check_xss_string"))]
    pub encryption_password: String,

    /// List of blockchain chains to import (e.g. BTC, ETH)
    #[serde(rename = "chains")]
          #[validate(custom(function = "check_xss_vec_string"))]
    pub chains: Vec<String>,

}


lazy_static::lazy_static! {
    static ref RE_KEYIMPORTREQUEST_HEX_ENCRYPTION_KEY: regex::Regex = regex::Regex::new("^[0-9a-fA-F]{64}$").unwrap();
}

impl KeyImportRequest {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(session_id: uuid::Uuid, hex_encryption_key: String, hex_chain_code: String, encryption_password: String, chains: Vec<String>, ) -> KeyImportRequest {
        KeyImportRequest {
 session_id,
 hex_encryption_key,
 hex_chain_code,
 local_party_id: None,
 encryption_password,
 chains,
        }
    }
}

/// Converts the KeyImportRequest value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for KeyImportRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![
            // Skipping session_id in query parameter serialization


            Some("hex_encryption_key".to_string()),
            Some(self.hex_encryption_key.to_string()),


            Some("hex_chain_code".to_string()),
            Some(self.hex_chain_code.to_string()),


            self.local_party_id.as_ref().map(|local_party_id| {
                [
                    "local_party_id".to_string(),
                    local_party_id.to_string(),
                ].join(",")
            }),


            Some("encryption_password".to_string()),
            Some(self.encryption_password.to_string()),


            Some("chains".to_string()),
            Some(self.chains.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")),

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a KeyImportRequest value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for KeyImportRequest {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub session_id: Vec<uuid::Uuid>,
            pub hex_encryption_key: Vec<String>,
            pub hex_chain_code: Vec<String>,
            pub local_party_id: Vec<String>,
            pub encryption_password: Vec<String>,
            pub chains: Vec<Vec<String>>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing KeyImportRequest".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "session_id" => intermediate_rep.session_id.push(<uuid::Uuid as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_encryption_key" => intermediate_rep.hex_encryption_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_chain_code" => intermediate_rep.hex_chain_code.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "local_party_id" => intermediate_rep.local_party_id.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "encryption_password" => intermediate_rep.encryption_password.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    "chains" => return std::result::Result::Err("Parsing a container in this style is not supported in KeyImportRequest".to_string()),
                    _ => return std::result::Result::Err("Unexpected key while parsing KeyImportRequest".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(KeyImportRequest {
            session_id: intermediate_rep.session_id.into_iter().next().ok_or_else(|| "session_id missing in KeyImportRequest".to_string())?,
            hex_encryption_key: intermediate_rep.hex_encryption_key.into_iter().next().ok_or_else(|| "hex_encryption_key missing in KeyImportRequest".to_string())?,
            hex_chain_code: intermediate_rep.hex_chain_code.into_iter().next().ok_or_else(|| "hex_chain_code missing in KeyImportRequest".to_string())?,
            local_party_id: intermediate_rep.local_party_id.into_iter().next(),
            encryption_password: intermediate_rep.encryption_password.into_iter().next().ok_or_else(|| "encryption_password missing in KeyImportRequest".to_string())?,
            chains: intermediate_rep.chains.into_iter().next().ok_or_else(|| "chains missing in KeyImportRequest".to_string())?,
        })
    }
}

// Methods for converting between header::IntoHeaderValue<KeyImportRequest> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<KeyImportRequest>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<KeyImportRequest>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for KeyImportRequest - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<KeyImportRequest> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <KeyImportRequest as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into KeyImportRequest - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct KeysignRequest {
    /// Public key identifying the vault backup file
    #[serde(rename = "public_key")]
          #[validate(custom(function = "check_xss_string"))]
    pub public_key: String,

    /// Hex-encoded messages to sign
    #[serde(rename = "messages")]
    #[validate(
            length(min = 1),
          custom(function = "check_xss_vec_string"),
    )]
    pub messages: Vec<String>,

    /// Unique session identifier (UUID)
    #[serde(rename = "session")]
    pub session: uuid::Uuid,

    /// 32-byte hex-encoded encryption key
    #[serde(rename = "hex_encryption_key")]
    #[validate(
            regex(path = *RE_KEYSIGNREQUEST_HEX_ENCRYPTION_KEY),
          custom(function = "check_xss_string"),
    )]
    pub hex_encryption_key: String,

    /// BIP-32 derivation path for the signing key
    #[serde(rename = "derive_path")]
          #[validate(custom(function = "check_xss_string"))]
    pub derive_path: String,

    /// Use ECDSA signing (true) or EdDSA (false)
    #[serde(rename = "is_ecdsa")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub is_ecdsa: Option<bool>,

    /// Password to decrypt the vault backup
    #[serde(rename = "vault_password")]
          #[validate(custom(function = "check_xss_string"))]
    pub vault_password: String,

    /// Target blockchain (e.g. BTC, ETH)
    #[serde(rename = "chain")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub chain: Option<String>,

    /// Use ML-DSA (post-quantum Dilithium) signing
    #[serde(rename = "mldsa")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub mldsa: Option<bool>,

}


lazy_static::lazy_static! {
    static ref RE_KEYSIGNREQUEST_HEX_ENCRYPTION_KEY: regex::Regex = regex::Regex::new("^[0-9a-fA-F]{64}$").unwrap();
}

impl KeysignRequest {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(public_key: String, messages: Vec<String>, session: uuid::Uuid, hex_encryption_key: String, derive_path: String, vault_password: String, ) -> KeysignRequest {
        KeysignRequest {
 public_key,
 messages,
 session,
 hex_encryption_key,
 derive_path,
 is_ecdsa: Some(false),
 vault_password,
 chain: None,
 mldsa: Some(false),
        }
    }
}

/// Converts the KeysignRequest value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for KeysignRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![

            Some("public_key".to_string()),
            Some(self.public_key.to_string()),


            Some("messages".to_string()),
            Some(self.messages.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")),

            // Skipping session in query parameter serialization


            Some("hex_encryption_key".to_string()),
            Some(self.hex_encryption_key.to_string()),


            Some("derive_path".to_string()),
            Some(self.derive_path.to_string()),


            self.is_ecdsa.as_ref().map(|is_ecdsa| {
                [
                    "is_ecdsa".to_string(),
                    is_ecdsa.to_string(),
                ].join(",")
            }),


            Some("vault_password".to_string()),
            Some(self.vault_password.to_string()),


            self.chain.as_ref().map(|chain| {
                [
                    "chain".to_string(),
                    chain.to_string(),
                ].join(",")
            }),


            self.mldsa.as_ref().map(|mldsa| {
                [
                    "mldsa".to_string(),
                    mldsa.to_string(),
                ].join(",")
            }),

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a KeysignRequest value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for KeysignRequest {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub public_key: Vec<String>,
            pub messages: Vec<Vec<String>>,
            pub session: Vec<uuid::Uuid>,
            pub hex_encryption_key: Vec<String>,
            pub derive_path: Vec<String>,
            pub is_ecdsa: Vec<bool>,
            pub vault_password: Vec<String>,
            pub chain: Vec<String>,
            pub mldsa: Vec<bool>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing KeysignRequest".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "public_key" => intermediate_rep.public_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    "messages" => return std::result::Result::Err("Parsing a container in this style is not supported in KeysignRequest".to_string()),
                    #[allow(clippy::redundant_clone)]
                    "session" => intermediate_rep.session.push(<uuid::Uuid as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_encryption_key" => intermediate_rep.hex_encryption_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "derive_path" => intermediate_rep.derive_path.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "is_ecdsa" => intermediate_rep.is_ecdsa.push(<bool as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "vault_password" => intermediate_rep.vault_password.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "chain" => intermediate_rep.chain.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "mldsa" => intermediate_rep.mldsa.push(<bool as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    _ => return std::result::Result::Err("Unexpected key while parsing KeysignRequest".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(KeysignRequest {
            public_key: intermediate_rep.public_key.into_iter().next().ok_or_else(|| "public_key missing in KeysignRequest".to_string())?,
            messages: intermediate_rep.messages.into_iter().next().ok_or_else(|| "messages missing in KeysignRequest".to_string())?,
            session: intermediate_rep.session.into_iter().next().ok_or_else(|| "session missing in KeysignRequest".to_string())?,
            hex_encryption_key: intermediate_rep.hex_encryption_key.into_iter().next().ok_or_else(|| "hex_encryption_key missing in KeysignRequest".to_string())?,
            derive_path: intermediate_rep.derive_path.into_iter().next().ok_or_else(|| "derive_path missing in KeysignRequest".to_string())?,
            is_ecdsa: intermediate_rep.is_ecdsa.into_iter().next(),
            vault_password: intermediate_rep.vault_password.into_iter().next().ok_or_else(|| "vault_password missing in KeysignRequest".to_string())?,
            chain: intermediate_rep.chain.into_iter().next(),
            mldsa: intermediate_rep.mldsa.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<KeysignRequest> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<KeysignRequest>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<KeysignRequest>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for KeysignRequest - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<KeysignRequest> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <KeysignRequest as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into KeysignRequest - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



/// TSS library/protocol type
/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them as `#[repr(C)]`
/// which helps with FFI.
#[allow(non_camel_case_types, clippy::large_enum_variant)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "conversion", derive(frunk_enum_derive::LabelledGenericEnum))]
pub enum LibType {
    #[serde(rename = "0")]
    GG20,
    #[serde(rename = "1")]
    DKLS,
    #[serde(rename = "2")]
    KeyImport,
}

impl validator::Validate for LibType
{
    fn validate(&self) -> std::result::Result<(), validator::ValidationErrors> {
        std::result::Result::Ok(())
    }
}

impl std::fmt::Display for LibType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            LibType::GG20 => write!(f, "0"),
            LibType::DKLS => write!(f, "1"),
            LibType::KeyImport => write!(f, "2"),
        }
    }
}

impl std::str::FromStr for LibType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "0" => std::result::Result::Ok(LibType::GG20),
            "1" => std::result::Result::Ok(LibType::DKLS),
            "2" => std::result::Result::Ok(LibType::KeyImport),
            _ => std::result::Result::Err(format!(r#"Value not valid: {s}"#)),
        }
    }
}


#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct MigrationRequest {
    /// 66-character hex-encoded ECDSA public key of the vault to migrate
    #[serde(rename = "public_key")]
    #[validate(
            regex(path = *RE_MIGRATIONREQUEST_PUBLIC_KEY),
          custom(function = "check_xss_string"),
    )]
    pub public_key: String,

    /// Unique session identifier (UUID)
    #[serde(rename = "session_id")]
    pub session_id: uuid::Uuid,

    /// 32-byte hex-encoded encryption key
    #[serde(rename = "hex_encryption_key")]
    #[validate(
            regex(path = *RE_MIGRATIONREQUEST_HEX_ENCRYPTION_KEY),
          custom(function = "check_xss_string"),
    )]
    pub hex_encryption_key: String,

    /// Encryption password for the vault
    #[serde(rename = "encryption_password")]
          #[validate(custom(function = "check_xss_string"))]
    pub encryption_password: String,

}


lazy_static::lazy_static! {
    static ref RE_MIGRATIONREQUEST_PUBLIC_KEY: regex::Regex = regex::Regex::new("^[0-9a-fA-F]{66}$").unwrap();
}
lazy_static::lazy_static! {
    static ref RE_MIGRATIONREQUEST_HEX_ENCRYPTION_KEY: regex::Regex = regex::Regex::new("^[0-9a-fA-F]{64}$").unwrap();
}

impl MigrationRequest {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(public_key: String, session_id: uuid::Uuid, hex_encryption_key: String, encryption_password: String, ) -> MigrationRequest {
        MigrationRequest {
 public_key,
 session_id,
 hex_encryption_key,
 encryption_password,
        }
    }
}

/// Converts the MigrationRequest value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for MigrationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![

            Some("public_key".to_string()),
            Some(self.public_key.to_string()),

            // Skipping session_id in query parameter serialization


            Some("hex_encryption_key".to_string()),
            Some(self.hex_encryption_key.to_string()),


            Some("encryption_password".to_string()),
            Some(self.encryption_password.to_string()),

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a MigrationRequest value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for MigrationRequest {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub public_key: Vec<String>,
            pub session_id: Vec<uuid::Uuid>,
            pub hex_encryption_key: Vec<String>,
            pub encryption_password: Vec<String>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing MigrationRequest".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "public_key" => intermediate_rep.public_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "session_id" => intermediate_rep.session_id.push(<uuid::Uuid as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_encryption_key" => intermediate_rep.hex_encryption_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "encryption_password" => intermediate_rep.encryption_password.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    _ => return std::result::Result::Err("Unexpected key while parsing MigrationRequest".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(MigrationRequest {
            public_key: intermediate_rep.public_key.into_iter().next().ok_or_else(|| "public_key missing in MigrationRequest".to_string())?,
            session_id: intermediate_rep.session_id.into_iter().next().ok_or_else(|| "session_id missing in MigrationRequest".to_string())?,
            hex_encryption_key: intermediate_rep.hex_encryption_key.into_iter().next().ok_or_else(|| "hex_encryption_key missing in MigrationRequest".to_string())?,
            encryption_password: intermediate_rep.encryption_password.into_iter().next().ok_or_else(|| "encryption_password missing in MigrationRequest".to_string())?,
        })
    }
}

// Methods for converting between header::IntoHeaderValue<MigrationRequest> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<MigrationRequest>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<MigrationRequest>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for MigrationRequest - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<MigrationRequest> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <MigrationRequest as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into MigrationRequest - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct ReshareRequest {
    /// Existing vault public key
    #[serde(rename = "public_key")]
          #[validate(custom(function = "check_xss_string"))]
    pub public_key: String,

    /// Unique session identifier (UUID)
    #[serde(rename = "session_id")]
    pub session_id: uuid::Uuid,

    /// 32-byte hex-encoded encryption key
    #[serde(rename = "hex_encryption_key")]
    #[validate(
            regex(path = *RE_RESHAREREQUEST_HEX_ENCRYPTION_KEY),
          custom(function = "check_xss_string"),
    )]
    pub hex_encryption_key: String,

    /// Hex-encoded chain code
    #[serde(rename = "hex_chain_code")]
          #[validate(custom(function = "check_xss_string"))]
    pub hex_chain_code: String,

    /// Local TSS party identifier
    #[serde(rename = "local_party_id")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub local_party_id: Option<String>,

    /// List of party IDs from the previous share set
    #[serde(rename = "old_parties")]
          #[validate(custom(function = "check_xss_vec_string"))]
    pub old_parties: Vec<String>,

    /// Encryption password (minimum 6 characters)
    #[serde(rename = "encryption_password")]
    #[validate(
            length(min = 6),
          custom(function = "check_xss_string"),
    )]
    pub encryption_password: String,

    /// Prefix from previous reshare operation (if any)
    #[serde(rename = "old_reshare_prefix")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub old_reshare_prefix: Option<String>,

    #[serde(rename = "lib_type")]
          #[validate(nested)]
    #[serde(skip_serializing_if="Option::is_none")]
    pub lib_type: Option<models::LibType>,

    #[serde(rename = "reshare_type")]
          #[validate(nested)]
    #[serde(skip_serializing_if="Option::is_none")]
    pub reshare_type: Option<models::ReshareType>,

}


lazy_static::lazy_static! {
    static ref RE_RESHAREREQUEST_HEX_ENCRYPTION_KEY: regex::Regex = regex::Regex::new("^[0-9a-fA-F]{64}$").unwrap();
}

impl ReshareRequest {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(public_key: String, session_id: uuid::Uuid, hex_encryption_key: String, hex_chain_code: String, old_parties: Vec<String>, encryption_password: String, ) -> ReshareRequest {
        ReshareRequest {
 public_key,
 session_id,
 hex_encryption_key,
 hex_chain_code,
 local_party_id: None,
 old_parties,
 encryption_password,
 old_reshare_prefix: None,
 lib_type: None,
 reshare_type: None,
        }
    }
}

/// Converts the ReshareRequest value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for ReshareRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![

            Some("public_key".to_string()),
            Some(self.public_key.to_string()),

            // Skipping session_id in query parameter serialization


            Some("hex_encryption_key".to_string()),
            Some(self.hex_encryption_key.to_string()),


            Some("hex_chain_code".to_string()),
            Some(self.hex_chain_code.to_string()),


            self.local_party_id.as_ref().map(|local_party_id| {
                [
                    "local_party_id".to_string(),
                    local_party_id.to_string(),
                ].join(",")
            }),


            Some("old_parties".to_string()),
            Some(self.old_parties.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")),


            Some("encryption_password".to_string()),
            Some(self.encryption_password.to_string()),


            self.old_reshare_prefix.as_ref().map(|old_reshare_prefix| {
                [
                    "old_reshare_prefix".to_string(),
                    old_reshare_prefix.to_string(),
                ].join(",")
            }),

            // Skipping lib_type in query parameter serialization

            // Skipping reshare_type in query parameter serialization

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a ReshareRequest value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for ReshareRequest {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub public_key: Vec<String>,
            pub session_id: Vec<uuid::Uuid>,
            pub hex_encryption_key: Vec<String>,
            pub hex_chain_code: Vec<String>,
            pub local_party_id: Vec<String>,
            pub old_parties: Vec<Vec<String>>,
            pub encryption_password: Vec<String>,
            pub old_reshare_prefix: Vec<String>,
            pub lib_type: Vec<models::LibType>,
            pub reshare_type: Vec<models::ReshareType>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing ReshareRequest".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "public_key" => intermediate_rep.public_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "session_id" => intermediate_rep.session_id.push(<uuid::Uuid as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_encryption_key" => intermediate_rep.hex_encryption_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_chain_code" => intermediate_rep.hex_chain_code.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "local_party_id" => intermediate_rep.local_party_id.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    "old_parties" => return std::result::Result::Err("Parsing a container in this style is not supported in ReshareRequest".to_string()),
                    #[allow(clippy::redundant_clone)]
                    "encryption_password" => intermediate_rep.encryption_password.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "old_reshare_prefix" => intermediate_rep.old_reshare_prefix.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "lib_type" => intermediate_rep.lib_type.push(<models::LibType as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "reshare_type" => intermediate_rep.reshare_type.push(<models::ReshareType as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    _ => return std::result::Result::Err("Unexpected key while parsing ReshareRequest".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(ReshareRequest {
            public_key: intermediate_rep.public_key.into_iter().next().ok_or_else(|| "public_key missing in ReshareRequest".to_string())?,
            session_id: intermediate_rep.session_id.into_iter().next().ok_or_else(|| "session_id missing in ReshareRequest".to_string())?,
            hex_encryption_key: intermediate_rep.hex_encryption_key.into_iter().next().ok_or_else(|| "hex_encryption_key missing in ReshareRequest".to_string())?,
            hex_chain_code: intermediate_rep.hex_chain_code.into_iter().next().ok_or_else(|| "hex_chain_code missing in ReshareRequest".to_string())?,
            local_party_id: intermediate_rep.local_party_id.into_iter().next(),
            old_parties: intermediate_rep.old_parties.into_iter().next().ok_or_else(|| "old_parties missing in ReshareRequest".to_string())?,
            encryption_password: intermediate_rep.encryption_password.into_iter().next().ok_or_else(|| "encryption_password missing in ReshareRequest".to_string())?,
            old_reshare_prefix: intermediate_rep.old_reshare_prefix.into_iter().next(),
            lib_type: intermediate_rep.lib_type.into_iter().next(),
            reshare_type: intermediate_rep.reshare_type.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<ReshareRequest> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<ReshareRequest>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<ReshareRequest>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for ReshareRequest - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<ReshareRequest> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <ReshareRequest as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into ReshareRequest - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



/// Reshare operation type
/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them as `#[repr(C)]`
/// which helps with FFI.
#[allow(non_camel_case_types, clippy::large_enum_variant)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "conversion", derive(frunk_enum_derive::LabelledGenericEnum))]
pub enum ReshareType {
    #[serde(rename = "0")]
    Normal,
    #[serde(rename = "1")]
    Plugin,
}

impl validator::Validate for ReshareType
{
    fn validate(&self) -> std::result::Result<(), validator::ValidationErrors> {
        std::result::Result::Ok(())
    }
}

impl std::fmt::Display for ReshareType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ReshareType::Normal => write!(f, "0"),
            ReshareType::Plugin => write!(f, "1"),
        }
    }
}

impl std::str::FromStr for ReshareType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "0" => std::result::Result::Ok(ReshareType::Normal),
            "1" => std::result::Result::Ok(ReshareType::Plugin),
            _ => std::result::Result::Err(format!(r#"Value not valid: {s}"#)),
        }
    }
}


#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct VaultCreateRequest {
    /// Unique session identifier (UUID)
    #[serde(rename = "session_id")]
    pub session_id: uuid::Uuid,

    /// 32-byte hex-encoded encryption key
    #[serde(rename = "hex_encryption_key")]
    #[validate(
            regex(path = *RE_VAULTCREATEREQUEST_HEX_ENCRYPTION_KEY),
          custom(function = "check_xss_string"),
    )]
    pub hex_encryption_key: String,

    /// Hex-encoded chain code for key derivation
    #[serde(rename = "hex_chain_code")]
          #[validate(custom(function = "check_xss_string"))]
    pub hex_chain_code: String,

    /// Identifier for the local TSS party (optional; server assigns one if omitted)
    #[serde(rename = "local_party_id")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub local_party_id: Option<String>,

    /// Password used to encrypt the vault backup
    #[serde(rename = "encryption_password")]
          #[validate(custom(function = "check_xss_string"))]
    pub encryption_password: String,

    #[serde(rename = "lib_type")]
          #[validate(nested)]
    #[serde(skip_serializing_if="Option::is_none")]
    pub lib_type: Option<models::LibType>,

}


lazy_static::lazy_static! {
    static ref RE_VAULTCREATEREQUEST_HEX_ENCRYPTION_KEY: regex::Regex = regex::Regex::new("^[0-9a-fA-F]{64}$").unwrap();
}

impl VaultCreateRequest {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(session_id: uuid::Uuid, hex_encryption_key: String, hex_chain_code: String, encryption_password: String, ) -> VaultCreateRequest {
        VaultCreateRequest {
 session_id,
 hex_encryption_key,
 hex_chain_code,
 local_party_id: None,
 encryption_password,
 lib_type: None,
        }
    }
}

/// Converts the VaultCreateRequest value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for VaultCreateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![
            // Skipping session_id in query parameter serialization


            Some("hex_encryption_key".to_string()),
            Some(self.hex_encryption_key.to_string()),


            Some("hex_chain_code".to_string()),
            Some(self.hex_chain_code.to_string()),


            self.local_party_id.as_ref().map(|local_party_id| {
                [
                    "local_party_id".to_string(),
                    local_party_id.to_string(),
                ].join(",")
            }),


            Some("encryption_password".to_string()),
            Some(self.encryption_password.to_string()),

            // Skipping lib_type in query parameter serialization

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a VaultCreateRequest value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for VaultCreateRequest {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub session_id: Vec<uuid::Uuid>,
            pub hex_encryption_key: Vec<String>,
            pub hex_chain_code: Vec<String>,
            pub local_party_id: Vec<String>,
            pub encryption_password: Vec<String>,
            pub lib_type: Vec<models::LibType>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing VaultCreateRequest".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "session_id" => intermediate_rep.session_id.push(<uuid::Uuid as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_encryption_key" => intermediate_rep.hex_encryption_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_chain_code" => intermediate_rep.hex_chain_code.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "local_party_id" => intermediate_rep.local_party_id.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "encryption_password" => intermediate_rep.encryption_password.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "lib_type" => intermediate_rep.lib_type.push(<models::LibType as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    _ => return std::result::Result::Err("Unexpected key while parsing VaultCreateRequest".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(VaultCreateRequest {
            session_id: intermediate_rep.session_id.into_iter().next().ok_or_else(|| "session_id missing in VaultCreateRequest".to_string())?,
            hex_encryption_key: intermediate_rep.hex_encryption_key.into_iter().next().ok_or_else(|| "hex_encryption_key missing in VaultCreateRequest".to_string())?,
            hex_chain_code: intermediate_rep.hex_chain_code.into_iter().next().ok_or_else(|| "hex_chain_code missing in VaultCreateRequest".to_string())?,
            local_party_id: intermediate_rep.local_party_id.into_iter().next(),
            encryption_password: intermediate_rep.encryption_password.into_iter().next().ok_or_else(|| "encryption_password missing in VaultCreateRequest".to_string())?,
            lib_type: intermediate_rep.lib_type.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<VaultCreateRequest> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<VaultCreateRequest>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<VaultCreateRequest>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for VaultCreateRequest - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<VaultCreateRequest> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <VaultCreateRequest as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into VaultCreateRequest - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct VaultCreateResponse {
    /// Session identifier
    #[serde(rename = "session_id")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub session_id: Option<uuid::Uuid>,

    /// Hex-encoded encryption key
    #[serde(rename = "hex_encryption_key")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub hex_encryption_key: Option<String>,

    /// Hex-encoded chain code
    #[serde(rename = "hex_chain_code")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub hex_chain_code: Option<String>,

    /// Encoded message for QR code display during keygen ceremony
    #[serde(rename = "keygen_msg")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub keygen_msg: Option<String>,

}



impl VaultCreateResponse {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new() -> VaultCreateResponse {
        VaultCreateResponse {
 session_id: None,
 hex_encryption_key: None,
 hex_chain_code: None,
 keygen_msg: None,
        }
    }
}

/// Converts the VaultCreateResponse value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for VaultCreateResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![
            // Skipping session_id in query parameter serialization


            self.hex_encryption_key.as_ref().map(|hex_encryption_key| {
                [
                    "hex_encryption_key".to_string(),
                    hex_encryption_key.to_string(),
                ].join(",")
            }),


            self.hex_chain_code.as_ref().map(|hex_chain_code| {
                [
                    "hex_chain_code".to_string(),
                    hex_chain_code.to_string(),
                ].join(",")
            }),


            self.keygen_msg.as_ref().map(|keygen_msg| {
                [
                    "keygen_msg".to_string(),
                    keygen_msg.to_string(),
                ].join(",")
            }),

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a VaultCreateResponse value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for VaultCreateResponse {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub session_id: Vec<uuid::Uuid>,
            pub hex_encryption_key: Vec<String>,
            pub hex_chain_code: Vec<String>,
            pub keygen_msg: Vec<String>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing VaultCreateResponse".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "session_id" => intermediate_rep.session_id.push(<uuid::Uuid as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_encryption_key" => intermediate_rep.hex_encryption_key.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_chain_code" => intermediate_rep.hex_chain_code.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "keygen_msg" => intermediate_rep.keygen_msg.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    _ => return std::result::Result::Err("Unexpected key while parsing VaultCreateResponse".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(VaultCreateResponse {
            session_id: intermediate_rep.session_id.into_iter().next(),
            hex_encryption_key: intermediate_rep.hex_encryption_key.into_iter().next(),
            hex_chain_code: intermediate_rep.hex_chain_code.into_iter().next(),
            keygen_msg: intermediate_rep.keygen_msg.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<VaultCreateResponse> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<VaultCreateResponse>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<VaultCreateResponse>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for VaultCreateResponse - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<VaultCreateResponse> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <VaultCreateResponse as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into VaultCreateResponse - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct VaultGetResponse {
    /// Hex-encoded ECDSA public key
    #[serde(rename = "public_key_ecdsa")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub public_key_ecdsa: Option<String>,

    /// Hex-encoded EdDSA public key
    #[serde(rename = "public_key_eddsa")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub public_key_eddsa: Option<String>,

    /// Hex-encoded chain code
    #[serde(rename = "hex_chain_code")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub hex_chain_code: Option<String>,

    /// Local TSS party identifier
    #[serde(rename = "local_party_id")]
          #[validate(custom(function = "check_xss_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub local_party_id: Option<String>,

}



impl VaultGetResponse {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new() -> VaultGetResponse {
        VaultGetResponse {
 public_key_ecdsa: None,
 public_key_eddsa: None,
 hex_chain_code: None,
 local_party_id: None,
        }
    }
}

/// Converts the VaultGetResponse value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for VaultGetResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![

            self.public_key_ecdsa.as_ref().map(|public_key_ecdsa| {
                [
                    "public_key_ecdsa".to_string(),
                    public_key_ecdsa.to_string(),
                ].join(",")
            }),


            self.public_key_eddsa.as_ref().map(|public_key_eddsa| {
                [
                    "public_key_eddsa".to_string(),
                    public_key_eddsa.to_string(),
                ].join(",")
            }),


            self.hex_chain_code.as_ref().map(|hex_chain_code| {
                [
                    "hex_chain_code".to_string(),
                    hex_chain_code.to_string(),
                ].join(",")
            }),


            self.local_party_id.as_ref().map(|local_party_id| {
                [
                    "local_party_id".to_string(),
                    local_party_id.to_string(),
                ].join(",")
            }),

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a VaultGetResponse value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for VaultGetResponse {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub public_key_ecdsa: Vec<String>,
            pub public_key_eddsa: Vec<String>,
            pub hex_chain_code: Vec<String>,
            pub local_party_id: Vec<String>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing VaultGetResponse".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "public_key_ecdsa" => intermediate_rep.public_key_ecdsa.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "public_key_eddsa" => intermediate_rep.public_key_eddsa.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "hex_chain_code" => intermediate_rep.hex_chain_code.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "local_party_id" => intermediate_rep.local_party_id.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    _ => return std::result::Result::Err("Unexpected key while parsing VaultGetResponse".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(VaultGetResponse {
            public_key_ecdsa: intermediate_rep.public_key_ecdsa.into_iter().next(),
            public_key_eddsa: intermediate_rep.public_key_eddsa.into_iter().next(),
            hex_chain_code: intermediate_rep.hex_chain_code.into_iter().next(),
            local_party_id: intermediate_rep.local_party_id.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<VaultGetResponse> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<VaultGetResponse>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<VaultGetResponse>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for VaultGetResponse - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<VaultGetResponse> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <VaultGetResponse as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into VaultGetResponse - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}


