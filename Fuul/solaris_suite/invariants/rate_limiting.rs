use crate::targets::full_svm::state::FullSvmState;
use crate::targets::full_svm::PROGRAM_ID;
use super::types::InvariantViolation;
use solana_sdk::pubkey::Pubkey;
use litesvm::LiteSVM;

/// Helper: Read CurrencyToken Rate Limiting Fields
/// Account Structure
/// The CurrencyToken account has this structure:
/// ```
/// Offset | Size | Field
/// -------|------|------------------
/// 0      | 8    | discriminator (Anchor)
/// 8      | 1    | is_initialized (bool)
/// 9      | 32   | token_mint (Pubkey)
/// 41     | 1    | token_type (enum - 1 byte)
/// 42     | 1    | is_active (bool)
/// 43     | 8    | claim_limit_per_cooldown (u64)  ← We read this
/// 51     | 8    | cumulative_claim_per_cooldown (u64)  ← We read this
/// 59     | 8    | claim_cooldown_period_started (i64)  ← We read this
/// ```
pub fn read_on_chain_rate_limits(
    svm: &LiteSVM,
    currency_mint: &Pubkey,
) -> Result<(u64, u64, i64), String> {
    // Derive the CurrencyToken PDA
    let (currency_token_pda, _bump) = Pubkey::find_program_address(
        &[b"currency-token", currency_mint.as_ref()],
        &PROGRAM_ID,
    );

    // Read the account from LiteSVM
    let account = svm.get_account(&currency_token_pda)
        .ok_or_else(|| {
            format!(
                "CurrencyToken account not found at PDA: {} (mint: {})",
                currency_token_pda, currency_mint
            )
        })?;

    // Verify the account has the expected minimum size
    // 8 (discriminator) + 1 (is_initialized) + 32 (token_mint) + 1 (token_type) + 1 (is_active) +
    // 8 (claim_limit_per_cooldown) + 8 (cumulative_claim_per_cooldown) + 8 (claim_cooldown_period_started) = 67 bytes
    if account.data.len() < 67 {
        return Err(format!(
            "CurrencyToken account data too short: {} bytes (expected at least 67)",
            account.data.len()
        ));
    }

    // Read claim_limit_per_cooldown at offset 43
    // Offset calculation: 8 (discriminator) + 1 (is_initialized) + 32 (token_mint) + 1 (token_type) + 1 (is_active) = 43
    let claim_limit = u64::from_le_bytes(
        account.data[43..51]
            .try_into()
            .map_err(|_| "Failed to read claim_limit_per_cooldown from bytes 43-51".to_string())?
    );

    // Read cumulative_claim_per_cooldown at offset 51
    let cumulative = u64::from_le_bytes(
        account.data[51..59]
            .try_into()
            .map_err(|_| "Failed to read cumulative_claim_per_cooldown from bytes 51-59".to_string())?
    );

    // Read claim_cooldown_period_started at offset 59
    let period_started = i64::from_le_bytes(
        account.data[59..67]
            .try_into()
            .map_err(|_| "Failed to read claim_cooldown_period_started from bytes 59-67".to_string())?
    );

    Ok((claim_limit, cumulative, period_started))
}

/// Helper: Read GlobalConfig Cooldown Duration
/// ## Account Structure
/// ```
/// Offset | Size | Field
/// -------|------|------------------
/// 0      | 8    | discriminator
/// 8      | 1    | is_initialized
/// 9      | 1    | paused
/// 10     | 8    | project_nonce
/// 18     | 8    | claim_cool_down (u64) ← We read this
/// ```
/// 
pub fn read_on_chain_cooldown_duration(svm: &LiteSVM) -> Result<u64, String> {
    // Derive the GlobalConfig PDA
    let (global_config_pda, _bump) = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    );

    // Read the account from LiteSVM
    let account = svm.get_account(&global_config_pda)
        .ok_or_else(|| {
            format!("GlobalConfig account not found at PDA: {}", global_config_pda)
        })?;

    // Verify minimum size
    if account.data.len() < 26 {
        return Err(format!(
            "GlobalConfig account data too short: {} bytes (expected at least 26)",
            account.data.len()
        ));
    }

    // Read claim_cool_down at offset 18
    let cooldown_duration = u64::from_le_bytes(
        account.data[18..26]
            .try_into()
            .map_err(|_| "Failed to read claim_cool_down from bytes 18-26".to_string())?
    );

    Ok(cooldown_duration)
}

// ============================================================================
// INV-R1: Cumulative Claim Within Limit
// ============================================================================

/// INV-R1: Cumulative Claim Within Limit
pub fn check_cumulative_within_limit(
    state: &FullSvmState,
    svm: &LiteSVM,
    currency_mint: &Pubkey,
    operation: &str,
) -> Result<(), InvariantViolation> {
    // STEP 1: Read on-chain state
    let (onchain_limit, onchain_cumulative, _period_started) =
        read_on_chain_rate_limits(svm, currency_mint)
            .map_err(|e| InvariantViolation::new(
                operation,
                "INV-R1-ONCHAIN",
                &format!("Failed to read CurrencyToken rate limits: {}", e)
            ))?;

    // STEP 2: Verify cumulative never exceeds limit
    if onchain_cumulative > onchain_limit {
        return Err(InvariantViolation::new(
            operation,
            "INV-R1",
            &format!(
                "CRITICAL: Cumulative claims exceed limit!\n\
                \n\
                Currency: {}\n\
                Cumulative: {}\n\
                Limit: {}\n\
                Excess: {}\n\
                \n\
                This is a CRITICAL violation - rate limiting has been bypassed!\n\
                Users could drain funds by exceeding the cooldown limit.",
                currency_mint,
                onchain_cumulative,
                onchain_limit,
                onchain_cumulative - onchain_limit
            )
        ));
    }

    // STEP 3: Verify internal tracking matches on-chain

    crate::debug_log!(
        "INV-R1 Cumulative within limit for {}: {} <= {}",
        currency_mint, onchain_cumulative, onchain_limit
    );

    Ok(())
}

// ============================================================================
// INV-R2: Claim Amount Within Limit
// ============================================================================

/// INV-R2: Single Claim Amount Within Limit
pub fn check_claim_amount_within_limit(
    state: &FullSvmState,
    svm: &LiteSVM,
    currency_mint: &Pubkey,
    claim_amount: u64,
) -> Result<(), InvariantViolation> {
    // Read on-chain limit
    let (onchain_limit, _cumulative, _period_started) =
        read_on_chain_rate_limits(svm, currency_mint)
            .map_err(|e| InvariantViolation::new(
                "Claim",
                "INV-R2-ONCHAIN",
                &format!("Failed to read CurrencyToken rate limits: {}", e)
            ))?;

    // Verify claim amount doesn't exceed limit
    if claim_amount > onchain_limit {
        return Err(InvariantViolation::new(
            "Claim",
            "INV-R2",
            &format!(
                "CRITICAL: Single claim exceeds cooldown limit!\n\
                \n\
                Currency: {}\n\
                Claim Amount: {}\n\
                Limit: {}\n\
                Excess: {}\n\
                \n\
                A single claim should NEVER exceed the total cooldown limit.\n\
                This would bypass rate limiting entirely!",
                currency_mint,
                claim_amount,
                onchain_limit,
                claim_amount - onchain_limit
            )
        ));
    }

    crate::debug_log!(
        "INV-R2 Claim amount within limit for {}: {} <= {}",
        currency_mint, claim_amount, onchain_limit
    );

    Ok(())
}

/// INV-R3: Cooldown Reset Behavior
pub fn check_cooldown_reset_behavior(
    state: &FullSvmState,
    svm: &LiteSVM,
    currency_mint: &Pubkey,
    claim_amount: u64,
    before_cumulative: u64,
    before_period_started: i64,
    current_timestamp: i64,
) -> Result<(), InvariantViolation> {
    // STEP 1: Read on-chain state after the claim
    let (limit, after_cumulative, after_period_started) =
        read_on_chain_rate_limits(svm, currency_mint)
            .map_err(|e| InvariantViolation::new(
                "Claim",
                "INV-R3-ONCHAIN",
                &format!("Failed to read CurrencyToken rate limits: {}", e)
            ))?;

    // STEP 2: Read the cooldown duration from GlobalConfig
    let cooldown_duration = read_on_chain_cooldown_duration(svm)
        .map_err(|e| InvariantViolation::new(
            "Claim",
            "INV-R3-ONCHAIN",
            &format!("Failed to read cooldown duration: {}", e)
        ))?;

    // STEP 3: Determine if cooldown should have expired
    let should_reset = current_timestamp >= before_period_started + cooldown_duration as i64;

    // STEP 4: Verify correct behavior based on whether cooldown expired
    if should_reset {

        // Check cumulative reset to claim amount (not 0!)
        if after_cumulative != claim_amount {
            return Err(InvariantViolation::new(
                "Claim",
                "INV-R3",
                &format!(
                    "CRITICAL: Cooldown reset didn't set cumulative to claim amount!\n\
                    \n\
                    Currency: {}\n\
                    Expected cumulative: {} (claim amount)\n\
                    Actual cumulative: {}\n\
                    \n\
                    When cooldown expires, cumulative should reset to the current claim amount,\n\
                    NOT to 0! This is because the current claim counts toward the new period.",
                    currency_mint,
                    claim_amount,
                    after_cumulative
                )
            ));
        }

        // Check period_started was updated
        if after_period_started <= before_period_started {
            return Err(InvariantViolation::new(
                "Claim",
                "INV-R3",
                &format!(
                    "CRITICAL: Cooldown period_started didn't update!\n\
                    \n\
                    Currency: {}\n\
                    Before: {}\n\
                    After: {}\n\
                    Current time: {}\n\
                    \n\
                    When cooldown expires, period_started should update to current timestamp.",
                    currency_mint,
                    before_period_started,
                    after_period_started,
                    current_timestamp
                )
            ));
        }

        crate::debug_log!(
            "INV-R3 Cooldown reset correctly for {}: cumulative={}, period_started={}",
            currency_mint, after_cumulative, after_period_started
        );
    } else {

        // Check cumulative increased by claim amount
        let expected_cumulative = before_cumulative + claim_amount;
        if after_cumulative != expected_cumulative {
            return Err(InvariantViolation::new(
                "Claim",
                "INV-R3",
                &format!(
                    "CRITICAL: Cumulative didn't increase correctly within cooldown!\n\
                    \n\
                    Currency: {}\n\
                    Before: {}\n\
                    Claim amount: {}\n\
                    Expected: {}\n\
                    Actual: {}\n\
                    \n\
                    Within cooldown period, cumulative should increase by claim amount.",
                    currency_mint,
                    before_cumulative,
                    claim_amount,
                    expected_cumulative,
                    after_cumulative
                )
            ));
        }

        // Check period_started didn't change
        if after_period_started != before_period_started {
            return Err(InvariantViolation::new(
                "Claim",
                "INV-R3",
                &format!(
                    "CRITICAL: Cooldown period_started changed unexpectedly!\n\
                    \n\
                    Currency: {}\n\
                    Before: {}\n\
                    After: {}\n\
                    \n\
                    Within cooldown period, period_started should NOT change.",
                    currency_mint,
                    before_period_started,
                    after_period_started
                )
            ));
        }

        crate::debug_log!(
            "INV-R3 Cumulative accumulated correctly for {}: {} -> {}",
            currency_mint, before_cumulative, after_cumulative
        );
    }

    Ok(())
}

/// INV-R3 Helper: Capture state before claim for reset verification
pub fn capture_rate_limits_before_claim(
    svm: &LiteSVM,
    currency_mint: &Pubkey,
) -> Result<(u64, i64), String> {
    let (_limit, cumulative, period_started) = read_on_chain_rate_limits(svm, currency_mint)?;
    Ok((cumulative, period_started))
}