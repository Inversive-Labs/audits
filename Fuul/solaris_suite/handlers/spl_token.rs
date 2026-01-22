use crate::core::harness::HarnessBase;
use super::super::state::FullSvmState;
use super::super::proto::SplTokenFreezeAuthorityCheck;
use super::super::invariants::{
    state_consistency::check_freeze_authority_on_currency_token,
    InvariantViolation,
};
use crate::{debug_log, debug_err};
use solana_sdk::pubkey::Pubkey;
use litesvm::LiteSVM;

/// INV-N1: Check freeze authority after adding a currency token
pub fn check_freeze_authority_after_add_currency(
    svm: &LiteSVM,
    token_mint: &Pubkey,
    is_native: bool,
) -> Result<(), InvariantViolation> {
    check_freeze_authority_on_currency_token(
        svm,
        token_mint,
        is_native,
        "add_currency_token",
    )
}

/// This function verifies INV-N1: Freeze Authority DoS Protection
pub fn execute_spl_token_freeze_authority_check(
    harness: &mut HarnessBase,
    msg: &SplTokenFreezeAuthorityCheck,
) -> Result<(), Box<dyn std::error::Error>> {
    debug_err!("[HARNESS] spl_token_freeze_authority_check(currency_index={})", msg.currency_index);

    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Get the currency token by index
    let currency_tokens: Vec<_> = state.currency_tokens.iter().collect();
    if currency_tokens.is_empty() {
        debug_log!("INV-N1: No currency tokens registered, skipping check");
        return Ok(());
    }

    let index = msg.currency_index as usize % currency_tokens.len();
    let (token_mint, currency) = currency_tokens[index];
    let token_mint = *token_mint;

    // Check if this is a native currency type
    let is_native = matches!(currency.currency_type, crate::targets::full_svm::state::CurrencyType::Native);

    // Skip check for native tokens (SOL doesn't have freeze authority)
    if is_native || token_mint == Pubkey::default() {
        debug_log!("INV-N1: Skipping freeze authority check for native token");
        return Ok(());
    }

    // INV-N1: Check freeze authority on non-native currency tokens
    if let Err(mut violation) = check_freeze_authority_on_currency_token(
        &harness.svm,
        &token_mint,
        is_native,
        "spl_freeze_authority_check",
    ) {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        if let Some(ref pb_data) = state.current_protobuf {
            violation = violation.with_protobuf(pb_data.clone());
        }
        if let Some(seed) = state.current_seed {
            violation = violation.with_seed(seed);
        }
        violation.dump_and_abort();
    }

    Ok(())
}

/// Check all registered currency tokens for freeze authority vulnerabilities
pub fn execute_spl_token_freeze_authority_batch_check(
    harness: &mut HarnessBase,
) -> Result<(), Box<dyn std::error::Error>> {
    debug_err!("[HARNESS] spl_token_freeze_authority_batch_check()");

    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Check all currency tokens
    for (token_mint, currency) in &state.currency_tokens.clone() {
        // Skip native tokens
        if *token_mint == Pubkey::default() {
            continue;
        }

        let is_native = matches!(currency.currency_type, crate::targets::full_svm::state::CurrencyType::Native);
        if is_native {
            continue;
        }

        // INV-N1: Check freeze authority
        if let Err(mut violation) = check_freeze_authority_on_currency_token(
            &harness.svm,
            token_mint,
            is_native,
            "batch_freeze_authority_check",
        ) {
            let state = harness.state.get_or_insert_extension::<FullSvmState>();
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }
    }

    debug_log!("INV-N1 All currency tokens verified: no freeze_authority");
    Ok(())
}
