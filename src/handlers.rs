//! HTTP endpoints implemented by the x402 **facilitator**.
//!
//! These are the server-side handlers for processing client-submitted x402 payments.
//! They include both protocol-critical endpoints (`/verify`, `/settle`) and discovery endpoints (`/supported`, etc).
//!
//! All payloads follow the types defined in the `x402-rs` crate, and are compatible
//! with the TypeScript and Go client SDKs.
//!
//! Each endpoint consumes or produces structured JSON payloads defined in `x402-rs`,
//! and is compatible with official x402 client SDKs.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router, response::IntoResponse};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::instrument;

use crate::chain::FacilitatorLocalError;
use crate::chain::NetworkProvider;
use crate::facilitator::Facilitator;
use crate::facilitator_local::FacilitatorLocal;
use crate::network::Network;
use crate::provider_cache::ProviderCache;
use crate::types::{
    ErrorResponse, FacilitatorErrorReason, MixedAddress, PaymentPayload, SettleContractRequest,
    SettleContractRequestConversionError, SettleContractResponse, SettleRequest, SettleResponse,
    VerifyRequest, VerifyResponse,
};
use alloy::hex;
use alloy::primitives::{Address, Bytes};

/// `GET /verify`: Returns a machine-readable description of the `/verify` endpoint.
///
/// This is served by the facilitator to help clients understand how to construct
/// a valid [`VerifyRequest`] for payment verification.
///
/// This is optional metadata and primarily useful for discoverability and debugging tools.
#[instrument(skip_all)]
pub async fn get_verify_info() -> impl IntoResponse {
    Json(json!({
        "endpoint": "/verify",
        "description": "POST to verify x402 payments",
        "body": {
            "paymentPayload": "PaymentPayload",
            "paymentRequirements": "PaymentRequirements",
        }
    }))
}

/// Header name for settle contract requests
const X_SETTLE_CONTRACT_HEADER: &str = "x-settle-contract";
/// Header name for receiver override in settle contract requests
const X_SETTLE_RECEIVER_HEADER: &str = "x-settle-receiver";

/// `GET /settle`: Returns a machine-readable description of the `/settle` endpoint.
///
/// This is served by the facilitator to describe the structure of a valid
/// [`SettleRequest`] used to initiate on-chain payment settlement.
///
/// Use header `X-Settle-Contract: <contract_address>` to use the settle contract function instead.
/// If `X-Settle-Contract` is present, you can optionally use `X-Settle-Receiver: <receiver_address>`
/// to override the receiver address from the request body.
#[instrument(skip_all)]
pub async fn get_settle_info() -> impl IntoResponse {
    Json(json!({
        "endpoint": "/settle",
        "description": "POST to settle x402 payments. Include header 'X-Settle-Contract: <contract_address>' to use settle contract function. Optionally include 'X-Settle-Receiver: <receiver_address>' to override receiver.",
        "body": {
            "paymentPayload": "PaymentPayload (for regular settle)",
            "paymentRequirements": "PaymentRequirements (for regular settle)",
            "OR": {
                "network": "Network (for contract settle)",
                "from": "EvmAddress",
                "receiver": "EvmAddress (can be overridden by X-Settle-Receiver header)",
                "amount": "TokenAmount",
                "validAfter": "UnixTimestamp",
                "validBefore": "UnixTimestamp",
                "nonce": "hex-encoded bytes32",
                "signature": "hex-encoded bytes",
                "confirmations": "u64 (optional, default: 0)",
            }
        }
    }))
}

/// `GET /call`: Returns a machine-readable description of the `/call` endpoint.
///
/// This is served by the facilitator to help clients understand how to construct
/// a valid [`ContractCallRequest`] for universal EVM contract call submission.
#[instrument(skip_all)]
pub async fn get_call_info() -> impl IntoResponse {
    Json(json!({
        "endpoint": "/call",
        "description": "POST to submit universal EVM contract calls",
        "body": {
            "network": "Network",
            "to": "EvmAddress (target contract address)",
            "data": "hex-encoded calldata (with or without 0x prefix)",
            "confirmations": "u64 (optional, default: 1)",
        }
    }))
}

pub fn routes<A>() -> Router<A>
where
    A: Facilitator + Clone + Send + Sync + 'static + AsRef<FacilitatorLocal<ProviderCache>>,
    A::Error: IntoResponse,
{
    Router::new()
        .route("/", get(get_root))
        .route("/verify", get(get_verify_info))
        .route("/verify", post(post_verify::<A>))
        .route("/settle", get(get_settle_info))
        .route("/settle", post(post_settle::<A>))
        .route("/call", get(get_call_info))
        .route("/call", post(post_contract_call::<A>))
        .route("/health", get(get_health::<A>))
        .route("/supported", get(get_supported::<A>))
}

/// `GET /`: Returns a simple greeting message from the facilitator.
#[instrument(skip_all)]
pub async fn get_root() -> impl IntoResponse {
    let pkg_name = env!("CARGO_PKG_NAME");
    (StatusCode::OK, format!("Hello from {pkg_name}!"))
}

/// `GET /supported`: Lists the x402 payment schemes and networks supported by this facilitator.
///
/// Facilitators may expose this to help clients dynamically configure their payment requests
/// based on available network and scheme support.
#[instrument(skip_all)]
pub async fn get_supported<A>(State(facilitator): State<A>) -> impl IntoResponse
where
    A: Facilitator,
    A::Error: IntoResponse,
{
    match facilitator.supported().await {
        Ok(supported) => (StatusCode::OK, Json(json!(supported))).into_response(),
        Err(error) => error.into_response(),
    }
}

#[instrument(skip_all)]
pub async fn get_health<A>(State(facilitator): State<A>) -> impl IntoResponse
where
    A: Facilitator,
    A::Error: IntoResponse,
{
    get_supported(State(facilitator)).await
}

/// `POST /verify`: Facilitator-side verification of a proposed x402 payment.
///
/// This endpoint checks whether a given payment payload satisfies the declared
/// [`PaymentRequirements`], including signature validity, scheme match, and fund sufficiency.
///
/// Responds with a [`VerifyResponse`] indicating whether the payment can be accepted.
#[instrument(skip_all)]
pub async fn post_verify<A>(
    State(facilitator): State<A>,
    Json(body): Json<VerifyRequest>,
) -> impl IntoResponse
where
    A: Facilitator,
    A::Error: IntoResponse,
{
    match facilitator.verify(&body).await {
        Ok(valid_response) => (StatusCode::OK, Json(valid_response)).into_response(),
        Err(error) => {
            tracing::warn!(
                error = ?error,
                body = %serde_json::to_string(&body).unwrap_or_else(|_| "<can-not-serialize>".to_string()),
                "Verification failed"
            );
            error.into_response()
        }
    }
}

/// `POST /settle`: Facilitator-side execution of a valid x402 payment on-chain.
///
/// Given a valid [`SettleRequest`], this endpoint attempts to execute the payment
/// via ERC-3009 `transferWithAuthorization`, and returns a [`SettleResponse`] with transaction details.
///
/// This endpoint is typically called after a successful `/verify` step.
///
/// If header `X-Settle-Contract: <contract_address>` is provided, the endpoint expects a [`SettleContractRequest`]
/// body and calls the settle contract function directly instead.
/// If `X-Settle-Receiver: <receiver_address>` is also provided, it will override the receiver field from the request body.
#[instrument(skip_all)]
pub async fn post_settle<A>(
    headers: HeaderMap,
    State(facilitator): State<A>,
    body: axum::body::Body,
) -> impl IntoResponse
where
    A: Facilitator + 'static,
    A::Error: IntoResponse,
{
    // Check if X-Settle-Contract header is present
    let use_contract = headers.contains_key(X_SETTLE_CONTRACT_HEADER);
    let has_receiver_header = headers.contains_key(X_SETTLE_RECEIVER_HEADER);

    tracing::debug!(
        use_contract = use_contract,
        has_receiver_header = has_receiver_header,
        x_settle_contract = ?headers.get(X_SETTLE_CONTRACT_HEADER).and_then(|h| h.to_str().ok()),
        x_settle_receiver = ?headers.get(X_SETTLE_RECEIVER_HEADER).and_then(|h| h.to_str().ok()),
        "Processing /settle request"
    );

    if use_contract {
        // Handle settle contract request
        let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(
                    error = ?e,
                    "Failed to read request body for settle contract request"
                );
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Failed to read body: {}", e),
                    }),
                )
                    .into_response();
            }
        };

        // Try to parse as SettleContractRequest or convert legacy bodies
        let mut contract_request =
            match serde_json::from_slice::<SettleContractRequest>(&body_bytes) {
                Ok(request) => request,
                Err(contract_err) => {
                    let value: Value = match serde_json::from_slice(&body_bytes) {
                        Ok(v) => v,
                        Err(_) => {
                            let body_preview =
                                String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(500)]);
                            tracing::error!(
                                error = ?contract_err,
                                body_preview = %body_preview,
                                body_length = body_bytes.len(),
                                "Failed to parse SettleContractRequest"
                            );
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(ErrorResponse {
                                    error: format!(
                                        "Failed to parse SettleContractRequest: {}",
                                        contract_err
                                    ),
                                }),
                            )
                                .into_response();
                        }
                    };

                    let payload_value = match value.get("paymentPayload") {
                        Some(v) => v.clone(),
                        None => {
                            tracing::error!(
                                "Request body for contract settle missing paymentPayload field"
                            );
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(ErrorResponse {
                                    error: "Request body missing paymentPayload field".to_string(),
                                }),
                            )
                                .into_response();
                        }
                    };

                    let payment_payload: PaymentPayload =
                        match serde_json::from_value(payload_value) {
                            Ok(payload) => payload,
                            Err(payload_err) => {
                                tracing::error!(
                                    error = ?payload_err,
                                    "Failed to parse paymentPayload when converting settle body"
                                );
                                return (
                                    StatusCode::BAD_REQUEST,
                                    Json(ErrorResponse {
                                        error: format!(
                                            "Failed to parse paymentPayload: {}",
                                            payload_err
                                        ),
                                    }),
                                )
                                    .into_response();
                            }
                        };

                    match SettleContractRequest::try_from(&payment_payload) {
                        Ok(request) => {
                            tracing::debug!("Converted paymentPayload into SettleContractRequest");
                            request
                        }
                        Err(convert_err) => {
                            let error_message = match convert_err {
                                SettleContractRequestConversionError::UnsupportedScheme(scheme) => {
                                    format!("Unsupported settle scheme for contract call: {scheme}")
                                }
                                SettleContractRequestConversionError::UnsupportedNetwork(
                                    network,
                                ) => format!(
                                    "Unsupported settle network for contract call: {network}"
                                ),
                                SettleContractRequestConversionError::UnsupportedPayload => {
                                    "Contract settle expects an EVM payment payload".to_string()
                                }
                            };

                            tracing::error!(
                                error = %convert_err,
                                message = %error_message,
                                "Failed to convert legacy settle request"
                            );
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(ErrorResponse {
                                    error: error_message,
                                }),
                            )
                                .into_response();
                        }
                    }
                }
            };

        // If X-Settle-Receiver header is present, replace the receiver in the request
        if let Some(receiver_header) = headers.get(X_SETTLE_RECEIVER_HEADER) {
            if let Ok(receiver_str) = receiver_header.to_str() {
                match receiver_str.parse::<crate::types::EvmAddress>() {
                    Ok(receiver_addr) => {
                        tracing::debug!(
                            original_receiver = %contract_request.receiver,
                            new_receiver = %receiver_addr,
                            "Overriding receiver from X-Settle-Receiver header"
                        );
                        contract_request.receiver = receiver_addr;
                    }
                    Err(e) => {
                        tracing::error!(
                            error = ?e,
                            receiver_header_value = %receiver_str,
                            "Invalid X-Settle-Receiver header value"
                        );
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(ErrorResponse {
                                error: format!("Invalid X-Settle-Receiver header value: {}", e),
                            }),
                        )
                            .into_response();
                    }
                }
            } else {
                tracing::error!("X-Settle-Receiver header contains invalid UTF-8");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "X-Settle-Receiver header contains invalid UTF-8".to_string(),
                    }),
                )
                    .into_response();
            }
        }

        // Get the contract address from header (for validation if needed)
        let header_contract_address = headers
            .get(X_SETTLE_CONTRACT_HEADER)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        tracing::debug!(
            contract_address = ?header_contract_address,
            from = %contract_request.from,
            receiver = %contract_request.receiver,
            amount = %contract_request.amount,
            network = ?contract_request.network,
            "Processing settle contract request"
        );

        match try_settle_contract(&facilitator, &contract_request).await {
            Ok(response) => {
                let settle_response = SettleResponse {
                    success: response.success,
                    error_reason: response.error_reason,
                    payer: contract_request.from.into(),
                    transaction: response.transaction,
                    network: contract_request.network,
                };
                (StatusCode::OK, Json(settle_response)).into_response()
            }
            Err(error) => {
                tracing::warn!(
                    error = ?error,
                    contract_address = ?header_contract_address,
                    "Settle contract call failed"
                );
                error.into_response()
            }
        }
    } else {
        // Handle regular settle request
        let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(
                    error = ?e,
                    "Failed to read request body for regular settle request"
                );
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Failed to read body: {}", e),
                    }),
                )
                    .into_response();
            }
        };

        match serde_json::from_slice::<SettleRequest>(&body_bytes) {
            Ok(settle_request) => match facilitator.settle(&settle_request).await {
                Ok(valid_response) => (StatusCode::OK, Json(valid_response)).into_response(),
                Err(error) => {
                    tracing::warn!(
                        error = ?error,
                        body = %String::from_utf8_lossy(&body_bytes),
                        "Settlement failed"
                    );
                    error.into_response()
                }
            },
            Err(e) => {
                let body_preview =
                    String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(500)]);
                tracing::error!(
                    error = ?e,
                    body_preview = %body_preview,
                    body_length = body_bytes.len(),
                    "Failed to parse SettleRequest"
                );
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Failed to parse SettleRequest: {}", e),
                    }),
                )
                    .into_response()
            }
        }
    }
}

/// `POST /call`: Universal EVM contract call submission.
///
/// Accepts raw calldata and target address, sends a transaction using the facilitator's signer set
/// with round-robin selection and nonce management. Returns a receipt summary.
#[instrument(skip_all)]
pub async fn post_contract_call<A>(
    State(facilitator): State<A>,
    Json(body): Json<ContractCallRequest>,
) -> impl IntoResponse
where
    A: Facilitator + AsRef<FacilitatorLocal<ProviderCache>>,
    A::Error: IntoResponse,
{
    let facilitator_ref: &FacilitatorLocal<ProviderCache> = facilitator.as_ref();
    let provider = match facilitator_ref.provider_by_network(body.network) {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Unsupported or unconfigured network".to_string(),
                }),
            )
                .into_response();
        }
    };

    let confirmations = 0;
    let to: Address = match body.to.parse() {
        Ok(addr) => addr,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid 'to' address".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Accept both 0x-prefixed and non-prefixed hex
    let hex_data = body.data.trim_start_matches("0x");
    let calldata: Bytes = match hex::decode(hex_data) {
        Ok(b) => b.into(),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid hex in 'data'".to_string(),
                }),
            )
                .into_response();
        }
    };

    match provider {
        NetworkProvider::Evm(evm) => {
            use crate::chain::evm::{
                MetaTransaction, load_gas_overrides_from_redis,
            };

            let gas_overrides = match load_gas_overrides_from_redis().await {
                Ok(overrides) => overrides,
                Err(err) => return err.into_response(),
            };

            let mut max_fee_per_gas = gas_overrides.max_fee_per_gas;
            let min_priority_fee = gas_overrides.max_priority_fee_per_gas;
            if max_fee_per_gas < min_priority_fee {
                max_fee_per_gas = min_priority_fee;
            }

            let meta = MetaTransaction {
                to,
                calldata,
                confirmations,
                max_fee_per_gas: Some(max_fee_per_gas),
                max_priority_fee_per_gas: Some(min_priority_fee),
            };

            let pending = match evm.broadcast_transaction(meta).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = ?e, "contract call broadcast failed");
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: format!("Broadcast failed: {e}"),
                        }),
                    )
                        .into_response();
                }
            };

            let tx_hash_bytes: [u8; 32] = (*pending.tx_hash()).into();
            let response = json!({
                "success": true,
                "pending": true,
                "txHash": format!("0x{}", hex::encode(tx_hash_bytes)),
                "network": body.network.to_string(),
                "to": format!("{to}"),
                "confirmations": confirmations,
            });

            return (StatusCode::ACCEPTED, Json(response)).into_response();
        }
        NetworkProvider::Solana(_) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "/call supports only EVM networks".to_string(),
            }),
        )
            .into_response(),
    }
}

/// Helper function to try calling settle_contract if the facilitator is FacilitatorLocal wrapped in Arc
async fn try_settle_contract<A>(
    facilitator: &A,
    request: &SettleContractRequest,
) -> Result<SettleContractResponse, FacilitatorLocalError>
where
    A: Facilitator + 'static,
{
    // The state is wrapped in Arc<FacilitatorLocal> in main.rs
    // Use std::any to check if we can downcast
    use std::any::Any;
    use std::sync::Arc;

    // Try to downcast as Arc<FacilitatorLocal> first (since that's what's passed in main.rs)
    if let Some(arc_facilitator_local) = (facilitator as &dyn Any)
        .downcast_ref::<Arc<FacilitatorLocal<crate::provider_cache::ProviderCache>>>()
    {
        arc_facilitator_local.settle_contract(request).await
    } else {
        Err(FacilitatorLocalError::ContractCall(
            "Settle contract requires FacilitatorLocal (wrapped in Arc)".to_string(),
        ))
    }
}

#[derive(Debug, Deserialize)]
struct ContractCallRequest {
    network: Network,
    to: String,
    data: String,
}

fn invalid_schema(payer: Option<MixedAddress>) -> VerifyResponse {
    VerifyResponse::invalid(payer, FacilitatorErrorReason::InvalidScheme)
}

impl IntoResponse for FacilitatorLocalError {
    fn into_response(self) -> Response {
        let error = self;

        let bad_request = (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid request".to_string(),
            }),
        )
            .into_response();

        match error {
            FacilitatorLocalError::SchemeMismatch(payer, ..) => {
                (StatusCode::OK, Json(invalid_schema(payer))).into_response()
            }
            FacilitatorLocalError::ReceiverMismatch(payer, ..)
            | FacilitatorLocalError::InvalidSignature(payer, ..)
            | FacilitatorLocalError::InvalidTiming(payer, ..)
            | FacilitatorLocalError::InsufficientValue(payer) => {
                (StatusCode::OK, Json(invalid_schema(Some(payer)))).into_response()
            }
            FacilitatorLocalError::NetworkMismatch(payer, ..)
            | FacilitatorLocalError::UnsupportedNetwork(payer) => (
                StatusCode::OK,
                Json(VerifyResponse::invalid(
                    payer,
                    FacilitatorErrorReason::InvalidNetwork,
                )),
            )
                .into_response(),
            FacilitatorLocalError::ContractCall(msg) => {
                tracing::error!(
                    error = %msg,
                    "Contract call error"
                );
                bad_request
            }
            FacilitatorLocalError::InvalidAddress(msg) => {
                tracing::error!(
                    error = %msg,
                    "Invalid address error"
                );
                bad_request
            }
            FacilitatorLocalError::ClockError(e) => {
                tracing::error!(
                    error = ?e,
                    "Clock error"
                );
                bad_request
            }
            FacilitatorLocalError::DecodingError(reason) => (
                StatusCode::OK,
                Json(VerifyResponse::invalid(
                    None,
                    FacilitatorErrorReason::FreeForm(reason),
                )),
            )
                .into_response(),
            FacilitatorLocalError::InsufficientFunds(payer) => (
                StatusCode::OK,
                Json(VerifyResponse::invalid(
                    Some(payer),
                    FacilitatorErrorReason::InsufficientFunds,
                )),
            )
                .into_response(),
        }
    }
}
