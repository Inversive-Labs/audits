use crate::targets::full_svm::{
    state::FullSvmState,
    invariants::InvariantViolation,
};
use solana_sdk::pubkey::Pubkey;
use litesvm::LiteSVM;
use borsh::BorshDeserialize;

// INV-T1: Message Deadline Not Expired
pub fn check_message_deadline_not_expired(
    deadline: i64,
    current_time: i64,
    claim_succeeded: bool,
    context: &str,
) -> Result<(), InvariantViolation> {
    let is_expired = current_time > deadline;

    if is_expired && claim_succeeded {
        return Err(InvariantViolation::new(
            context,
            "INV-T1",
            &format!(
                "CRITICAL: Claim succeeded with expired deadline!\n\
                \n\
                Deadline: {} (unix timestamp)\n\
                Current time: {} (unix timestamp)\n\
                Expired by: {} seconds\n\
                \n\
                This violates signature expiration policy.\n\
                Expired signatures should never be accepted.",
                deadline, current_time, current_time - deadline
            )
        ));
    }

    Ok(())
}

// INV-T2: Cooldown Period Calculation
pub fn check_cooldown_period_calculation(
    period_started: i64,
    cooldown_duration: u64,
    current_time: i64,
    old_cumulative: u64,
    new_cumulative: u64,
    claim_amount: u64,
    context: &str,
) -> Result<(), InvariantViolation> {
    let cooldown_end = period_started.saturating_add(cooldown_duration as i64);
    let should_be_expired = current_time >= cooldown_end;
    let was_reset = new_cumulative == claim_amount;
    let was_accumulated = new_cumulative == old_cumulative.saturating_add(claim_amount);

    // If cooldown expired, cumulative should reset to claim amount
    if should_be_expired && !was_reset {
        return Err(InvariantViolation::new(
            context,
            "INV-T2",
            &format!(
                "CRITICAL: Cooldown expired but cumulative not reset!\n\
                \n\
                Period started: {} (unix timestamp)\n\
                Cooldown duration: {} seconds\n\
                Current time: {} (unix timestamp)\n\
                Should have expired at: {}\n\
                \n\
                Old cumulative: {}\n\
                New cumulative: {} (expected: {})\n\
                Claim amount: {}\n\
                \n\
                When cooldown expires, cumulative should reset to claim amount.",
                period_started, cooldown_duration, current_time, cooldown_end,
                old_cumulative, new_cumulative, claim_amount, claim_amount
            )
        ));
    }

    // If cooldown not expired, cumulative should accumulate
    if !should_be_expired && !was_accumulated {
        return Err(InvariantViolation::new(
            context,
            "INV-T2",
            &format!(
                "CRITICAL: Cooldown active but cumulative not accumulated!\n\
                \n\
                Period started: {} (unix timestamp)\n\
                Cooldown duration: {} seconds\n\
                Current time: {} (unix timestamp)\n\
                Expires at: {}\n\
                Time remaining: {} seconds\n\
                \n\
                Old cumulative: {}\n\
                New cumulative: {} (expected: {})\n\
                Claim amount: {}\n\
                \n\
                During active cooldown, amounts should accumulate.",
                period_started, cooldown_duration, current_time, cooldown_end,
                cooldown_end - current_time,
                old_cumulative, new_cumulative, old_cumulative + claim_amount,
                claim_amount
            )
        ));
    }

    Ok(())
}

pub fn verify_cooldown_state_on_chain(
    svm: &LiteSVM,
    currency_id: &Pubkey,
) -> Result<(i64, u64, u64), String> {
    let (currency_pda, _) = Pubkey::find_program_address(
        &[b"currency-token", currency_id.as_ref()],
        &crate::targets::full_svm::PROGRAM_ID,
    );

    let account = svm.get_account(&currency_pda)
        .ok_or_else(|| format!("CurrencyToken account not found at {}", currency_pda))?;

    // Skip 8-byte Anchor discriminator
    let data = &account.data[8..];

    // CurrencyToken structure
    #[derive(BorshDeserialize)]
    struct CurrencyTokenOnChain {
        pub is_initialized: bool,
        pub token_mint: Pubkey,
        pub token_type: u8, // enum as u8
        pub is_active: bool,
        pub claim_limit_per_cooldown: u64,
        pub cumulative_claim_per_cooldown: u64,
        pub claim_cooldown_period_started: i64,
    }

    let currency = CurrencyTokenOnChain::try_from_slice(data)
        .map_err(|e| format!("Failed to deserialize CurrencyToken: {}", e))?;

    Ok((
        currency.claim_cooldown_period_started,
        currency.cumulative_claim_per_cooldown,
        currency.claim_limit_per_cooldown,
    ))
}

// INV-T3: Timestamps Are Monotonic
pub fn check_timestamps_monotonic(
    old_timestamp: i64,
    new_timestamp: i64,
    field_name: &str,
    context: &str,
) -> Result<(), InvariantViolation> {
    if new_timestamp < old_timestamp {
        return Err(InvariantViolation::new(
            context,
            "INV-T3",
            &format!(
                "CRITICAL: Timestamp went backwards!\n\
                \n\
                Field: {}\n\
                Old timestamp: {} (unix timestamp)\n\
                New timestamp: {} (unix timestamp)\n\
                Went back by: {} seconds\n\
                \n\
                Timestamps must be monotonic (never decrease).\n\
                This could indicate clock manipulation or state corruption.",
                field_name, old_timestamp, new_timestamp,
                old_timestamp - new_timestamp
            )
        ));
    }

    Ok(())
}

// INV-T4: Attribution Timestamp Accuracy
pub fn check_attribution_timestamp_accuracy(
    attribution_timestamp: i64,
    actual_time: i64,
    max_drift: i64,
    context: &str,
) -> Result<(), InvariantViolation> {
    let diff = (attribution_timestamp - actual_time).abs();

    if diff > max_drift {
        return Err(InvariantViolation::new(
            context,
            "INV-T4",
            &format!(
                "CRITICAL: Attribution timestamp too far from actual time!\n\
                \n\
                Attribution timestamp: {} (unix timestamp)\n\
                Actual clock time: {} (unix timestamp)\n\
                Difference: {} seconds\n\
                Max allowed drift: {} seconds\n\
                \n\
                Attribution timestamps should accurately reflect claim time.\n\
                Large drift could indicate timestamp manipulation.",
                attribution_timestamp, actual_time, diff, max_drift
            )
        ));
    }

    Ok(())
}

/// Read ProjectAttribution from on-chain
pub fn read_attribution_timestamp_on_chain(
    svm: &LiteSVM,
    project_id: &Pubkey,
    proof: &[u8; 32],
) -> Result<Option<i64>, String> {
    let (attribution_pda, _) = Pubkey::find_program_address(
        &[b"project-attribution", project_id.as_ref(), proof],
        &crate::targets::full_svm::PROGRAM_ID,
    );

    let account = match svm.get_account(&attribution_pda) {
        Some(acc) => acc,
        None => return Ok(None),
    };

    // Skip 8-byte Anchor discriminator
    let data = &account.data[8..];

    // ProjectAttribution structure
    #[derive(BorshDeserialize)]
    struct ProjectAttributionOnChain {
        pub nonce: u64,
        pub token_mint: Pubkey,
        pub amount: u64,
        pub recipient: Pubkey,
        pub proof: [u8; 32],     // proof comes BEFORE timestamp
        pub timestamp: i64,      // timestamp is last
    }

    let attribution = ProjectAttributionOnChain::try_from_slice(data)
        .map_err(|e| format!("Failed to deserialize ProjectAttribution: {}", e))?;

    Ok(Some(attribution.timestamp))
}

// Helper Functions

/// Get the current clock time from on-chain
pub fn get_clock_time_on_chain(svm: &LiteSVM) -> Result<i64, String> {
    use solana_sdk::sysvar::clock;

    // Get the clock from the SVM sysvar
    let clock_data = svm.get_sysvar::<clock::Clock>();

    Ok(clock_data.unix_timestamp)
}

/// Check all timing invariants for a claim operation
pub fn check_claim_timing_invariants(
    state: &FullSvmState,
    svm: &LiteSVM,
    deadline: i64,
    currency_id: &Pubkey,
    project_id: &Pubkey,
    proof: &[u8; 32],
    claim_amount: u64,
    claim_succeeded: bool,
    context: &str,
) -> Result<(), InvariantViolation> {
    // Get current time from on-chain clock
    let current_time = get_clock_time_on_chain(svm)
        .map_err(|e| InvariantViolation::new(context, "INV-T", &format!("Failed to get clock: {}", e)))?;

    // INV-T1: Check deadline not expired
    check_message_deadline_not_expired(deadline, current_time, claim_succeeded, context)?;

    // INV-T2: Check cooldown calculation (if claim succeeded)
    if claim_succeeded {
        // Get cooldown state before and after
        if let Some(currency) = state.currency_tokens.get(currency_id) {
            // Get on-chain state for comparison
            if let Ok((period_started_on_chain, cumulative_on_chain, _)) =
                verify_cooldown_state_on_chain(svm, currency_id) {

                // Get cooldown duration from global config
                let cooldown_duration = state.global_config.claim_cooldown;

                // Check the cooldown calculation logic
                check_cooldown_period_calculation(
                    currency.claim_cooldown_period_started,
                    cooldown_duration,
                    current_time,
                    currency.cumulative_claim_per_cooldown,
                    cumulative_on_chain,
                    claim_amount,
                    context
                )?;

                // INV-T3: Check timestamp monotonicity
                if period_started_on_chain != currency.claim_cooldown_period_started {
                    check_timestamps_monotonic(
                        currency.claim_cooldown_period_started,
                        period_started_on_chain,
                        "claim_cooldown_period_started",
                        context
                    )?;
                }
            }
        }

        // INV-T4: Check attribution timestamp accuracy
        if let Ok(Some(attribution_timestamp)) =
            read_attribution_timestamp_on_chain(svm, project_id, proof) {

            // Allow up to 5 seconds of drift
            check_attribution_timestamp_accuracy(
                attribution_timestamp,
                current_time,
                5, // max_drift in seconds
                context
            )?;
        }
    }

    Ok(())
}