//! Facilitator implementation for x402 payments using on-chain verification and settlement.
//!
//! This module provides a [`Facilitator`] implementation that validates x402 payment payloads
//! and performs on-chain settlements using ERC-3009 `transferWithAuthorization`.
//!
//! Features include:
//! - EIP-712 signature recovery
//! - ERC-20 balance checks
//! - Contract interaction using Alloy
//! - Network-specific configuration via [`ProviderCache`] and [`USDCDeployment`]

use tracing::instrument;

use crate::chain::FacilitatorLocalError;
use crate::chain::NetworkProvider;
use crate::facilitator::Facilitator;
use crate::provider_cache::ProviderMap;
use crate::types::{
    SettleContractRequest, SettleContractResponse, SettleRequest, SettleResponse,
    SupportedPaymentKindsResponse, VerifyRequest, VerifyResponse,
};

/// A concrete [`Facilitator`] implementation that verifies and settles x402 payments
/// using a network-aware provider cache.
///
/// This type is generic over the [`ProviderMap`] implementation used to access EVM providers,
/// which enables testing or customization beyond the default [`ProviderCache`].
pub struct FacilitatorLocal<A> {
    provider_map: A,
    gas_overrides: crate::chain::evm::GasOverrides,
}

impl<A> FacilitatorLocal<A> {
    /// Creates a new [`FacilitatorLocal`] with the given provider cache.
    ///
    /// The provider cache is used to resolve the appropriate EVM provider for each payment's target network.
    pub fn new(provider_map: A, gas_overrides: crate::chain::evm::GasOverrides) -> Self {
        FacilitatorLocal {
            provider_map,
            gas_overrides,
        }
    }

    /// Call the settle contract function with the provided parameters.
    ///
    /// # Errors
    /// Returns [`FacilitatorLocalError`] if:
    /// - The network is not supported
    /// - The provider is not an EVM provider
    /// - The contract call fails
    #[instrument(skip_all, err)]
    pub async fn settle_contract(
        &self,
        request: &SettleContractRequest,
    ) -> Result<SettleContractResponse, FacilitatorLocalError>
    where
        A: ProviderMap<Value = NetworkProvider> + Sync,
    {
        let provider = self
            .provider_map
            .by_network(request.network)
            .ok_or(FacilitatorLocalError::UnsupportedNetwork(None))?;

        // We need to extract EvmProvider from NetworkProvider, but provider is a reference
        // So we pattern match and borrow the inner value
        let evm_provider = match provider {
            NetworkProvider::Evm(evm) => evm,
            NetworkProvider::Solana(_) => {
                return Err(FacilitatorLocalError::UnsupportedNetwork(None));
            }
        };

        use alloy::primitives::{Address, Bytes, FixedBytes, U256};

        let from: Address = request.from.into();
        let receiver: Address = request.receiver.into();
        let amount: U256 = request.amount.into();
        let valid_after: U256 = request.valid_after.into();
        let valid_before: U256 = request.valid_before.into();
        let nonce = FixedBytes(request.nonce);
        let signature = Bytes::from(request.signature.clone());

        let mut max_fee_per_gas = self.gas_overrides.max_fee_per_gas;
        let min_priority_fee = self.gas_overrides.max_priority_fee_per_gas;
        if max_fee_per_gas < min_priority_fee {
            max_fee_per_gas = min_priority_fee;
        }

        if request.confirmations == 0 {
            let tx_hash = evm_provider
                .settle_contract_pending(
                    from,
                    receiver,
                    amount,
                    valid_after,
                    valid_before,
                    nonce,
                    signature,
                    request.confirmations,
                    max_fee_per_gas,
                    min_priority_fee,
                )
                .await?;

            Ok(SettleContractResponse {
                success: true,
                error_reason: None,
                transaction: Some(crate::types::TransactionHash::Evm(tx_hash)),
            })
        } else {
            let receipt = evm_provider
                .settle_contract(
                    from,
                    receiver,
                    amount,
                    valid_after,
                    valid_before,
                    nonce,
                    signature,
                    request.confirmations,
                    max_fee_per_gas,
                    min_priority_fee,
                )
                .await?;

            let success = receipt.status();
            Ok(SettleContractResponse {
                success,
                error_reason: if success {
                    None
                } else {
                    Some(crate::types::FacilitatorErrorReason::InvalidScheme)
                },
                transaction: Some(crate::types::TransactionHash::Evm(
                    receipt.transaction_hash.0,
                )),
            })
        }
    }
}

impl<A, E> Facilitator for FacilitatorLocal<A>
where
    A: ProviderMap + Sync,
    A::Value: Facilitator<Error = E>,
    E: Send,
    FacilitatorLocalError: From<E>,
{
    type Error = FacilitatorLocalError;

    /// Verifies a proposed x402 payment payload against a passed [`PaymentRequirements`].
    ///
    /// This function validates the signature, timing, receiver match, network, scheme, and on-chain
    /// balance sufficiency for the token. If all checks pass, return a [`VerifyResponse::Valid`].
    ///
    /// Called from the `/verify` HTTP endpoint on the facilitator.
    ///
    /// # Errors
    ///
    /// Returns [`FacilitatorLocalError`] if any check fails, including:
    /// - scheme/network mismatch,
    /// - receiver mismatch,
    /// - invalid signature,
    /// - expired or future-dated timing,
    /// - insufficient funds,
    /// - unsupported network.
    #[instrument(skip_all, err, fields(network = %request.payment_payload.network))]
    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
        let network = request.network();
        let provider = self
            .provider_map
            .by_network(network)
            .ok_or(FacilitatorLocalError::UnsupportedNetwork(None))?;
        let verify_response = provider.verify(request).await?;
        Ok(verify_response)
    }

    /// Executes an x402 payment on-chain using ERC-3009 `transferWithAuthorization`.
    ///
    /// This function performs the same validations as `verify`, then sends the authorized transfer
    /// via a smart contract and waits for transaction receipt.
    ///
    /// Called from the `/settle` HTTP endpoint on the facilitator.
    ///
    /// # Errors
    ///
    /// Returns [`FacilitatorLocalError`] if validation or contract call fails. Transaction receipt is included
    /// in the response on success or failure.
    #[instrument(skip_all, err, fields(network = %request.payment_payload.network))]
    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
        let network = request.network();
        let provider = self
            .provider_map
            .by_network(network)
            .ok_or(FacilitatorLocalError::UnsupportedNetwork(None))?;
        let settle_response = provider.settle(request).await?;
        Ok(settle_response)
    }

    async fn supported(&self) -> Result<SupportedPaymentKindsResponse, Self::Error> {
        let mut kinds = vec![];
        for provider in self.provider_map.values() {
            let supported = provider.supported().await.ok();
            let mut supported_kinds = supported.map(|k| k.kinds).unwrap_or_default();
            kinds.append(&mut supported_kinds);
        }
        Ok(SupportedPaymentKindsResponse { kinds })
    }
}
