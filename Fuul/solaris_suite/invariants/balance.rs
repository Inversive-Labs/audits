use super::types::InvariantViolation;
use crate::targets::full_svm::state::{FullSvmState, ProjectCurrencyBudget};
use crate::targets::full_svm::PROGRAM_ID;
use solana_sdk::pubkey::Pubkey;
use litesvm::LiteSVM;

// ============================================================================
// Helper Functions for Reading On-Chain State
// ============================================================================

/// Helper: Read On-Chain Budget from LiteSVM
/// ## Account Structure
/// The ProjectBudget account in the Fuul program has this structure:
/// ```
/// Offset | Size | Field
/// -------|------|------------------
/// 0      | 8    | discriminator (Anchor)
/// 8      | 32   | project (Pubkey)
/// 40     | 32   | currency (Pubkey)
/// 72     | 8    | total_deposited (u64)
/// 80     | 8    | total_claimed (u64)
/// 88     | 8    | available_balance (u64)
/// ```

pub fn read_on_chain_budget(
    svm: &LiteSVM,
    project: &Pubkey,
    currency: &Pubkey, 
) -> Result<(u64, u64, u64), String> {
    let (currency_token_pda, _bump) = Pubkey::find_program_address(
        &[b"currency-token", currency.as_ref()],
        &PROGRAM_ID,
    );

    // Derive the budget PDA using currency_token_pda
    // Seeds: ["project-currency-budget", project_pubkey, currency_token_pda]
    let (budget_pda, _bump) = Pubkey::find_program_address(
        &[
            b"project-currency-budget",
            project.as_ref(),
            currency_token_pda.as_ref(),  // derived PDA
        ],
        &PROGRAM_ID,
    );

    // Read the account from LiteSVM
    let account = svm.get_account(&budget_pda)
        .ok_or_else(|| {
            format!(
                "Budget account not found for project {} / mint {} / currency_token_pda {}. Budget PDA: {}",
                project, currency, currency_token_pda, budget_pda
            )
        })?;

    // ProjectCurrencyBudget account structure:
    // - 8 bytes: discriminator
    // - 8 bytes: budget (available balance)
    // - 32 bytes: token_mint
    // - 33 bytes: token_account (Option<Pubkey>)

    // Verify the account has the expected minimum size
    // 8 (discriminator) + 8 (budget) + 32 (token_mint) + 33 (Option<Pubkey>) = 81 bytes
    if account.data.len() < 81 {
        return Err(format!(
            "Budget account data too short: {} bytes (expected at least 81)",
            account.data.len()
        ));
    }

    // Read the budget field (available balance) at offset 8
    let available_balance = u64::from_le_bytes(
        account.data[8..16]
            .try_into()
            .map_err(|_| "Failed to read budget from bytes 8-16".to_string())?
    );

    let total_deposited = 0;
    let total_claimed = 0;

    Ok((total_deposited, total_claimed, available_balance))
}

// ============================================================================
// Invariant Checks
// ============================================================================

/// INV-B1: Budget Non-Negativity
pub fn check_budget_non_negative(
    state: &FullSvmState,
    svm: &LiteSVM,
    operation: &str,
    affected_project: Option<&Pubkey>,
    affected_currency: Option<&Pubkey>,
) -> Result<(), InvariantViolation> {
    // Iterate through ALL project budgets to ensure none are negative
    for ((project_id, currency_id), budget) in &state.project_budgets {

        // CHECK 1: Available balance cannot exceed total deposited
        // This catches bugs where deposits are under-counted or balance is over-counted
        if budget.available_balance > budget.total_deposited {
            return Err(InvariantViolation::new(
                operation,
                "INV-B1",
                &format!(
                    "CRITICAL: Available balance ({}) exceeds total deposited ({}) for project {} / currency {}. \
                    This indicates a serious accounting bug where more funds are available than were ever deposited!",
                    budget.available_balance,
                    budget.total_deposited,
                    project_id,
                    currency_id
                )
            ));
        }

        // CHECK 2: Total claimed cannot exceed total deposited
        if budget.total_claimed > budget.total_deposited {
            return Err(InvariantViolation::new(
                operation,
                "INV-B1",
                &format!(
                    "CRITICAL: Total claimed ({}) exceeds total deposited ({}) for project {} / currency {}. \
                    This means users claimed more tokens than were ever deposited - a critical underflow bug!",
                    budget.total_claimed,
                    budget.total_deposited,
                    project_id,
                    currency_id
                )
            ));
        }

        // CHECK 3: Accounting consistency - available should equal (deposited - claimed)
        let expected_max_balance = budget.total_deposited.saturating_sub(budget.total_claimed);
        if budget.available_balance > expected_max_balance {
            return Err(InvariantViolation::new(
                operation,
                "INV-B1",
                &format!(
                    "CRITICAL: Available balance ({}) inconsistent with deposits-claims ({} - {} = {}) for project {} / currency {}. \
                    The available balance exceeds what should remain after claims!",
                    budget.available_balance,
                    budget.total_deposited,
                    budget.total_claimed,
                    expected_max_balance,
                    project_id,
                    currency_id
                )
            ));
        }

        // CHECK 4: Verify our tracking matches on-chain reality
        if let Ok((onchain_deposited, onchain_claimed, onchain_available)) = 
            read_on_chain_budget(svm, project_id, currency_id) 
        {
            // Verify available_balance
            if budget.available_balance != onchain_available {
                return Err(InvariantViolation::new(
                    operation,
                    "INV-B1-SYNC",
                    &format!(
                        "CRITICAL: State tracking desync detected - available_balance mismatch!\n\
                        \n\
                        Project: {} / Currency: {}\n\
                        \n\
                        Our internal tracking: {}\n\
                        On-chain real value:   {}\n\
                        Difference:            {}\n\
                        \n\
                        This means our fuzzer's state tracking is NOT synchronized with the actual\n\
                        on-chain state in LiteSVM. This is a critical bug in our state update logic.",
                        project_id,
                        currency_id,
                        budget.available_balance,
                        onchain_available,
                        (budget.available_balance as i64) - (onchain_available as i64)
                    )
                ));
            }

            if let (Some(proj), Some(curr)) = (affected_project, affected_currency) {
                if project_id == proj && currency_id == curr {
                    crate::debug_log!(
                        "INV-B1 PASSED: {} / {} - tracking matches on-chain: available={}, deposited={}, claimed={}",
                        project_id, currency_id,
                        budget.available_balance,
                        budget.total_deposited,
                        budget.total_claimed
                    );
                }
            }
        } else {
            crate::debug_log!(
                "INV-B1 Budget account not found on-chain for {} / {} (might be first deposit)",
                project_id, currency_id
            );
        }
    }

    Ok(())
}

/// INV-B1 Extended: Budget Non-Negativity with Detailed Tracking
pub fn check_budget_change(
    state: &FullSvmState,
    svm: &LiteSVM,
    operation: &str,
    project: &Pubkey,
    currency: &Pubkey,
    expected_delta: i64,
    before_balance: u64,
) -> Result<(), InvariantViolation> {
    // Get current balance
    let current_balance = state.get_project_budget(project, currency);

    // Calculate actual delta
    let actual_delta = (current_balance as i64) - (before_balance as i64);

    // Verify delta matches expectation
    if actual_delta != expected_delta {
        return Err(InvariantViolation::new(
            operation,
            "INV-B1-DELTA",
            &format!(
                "CRITICAL: Budget change mismatch for project {} / currency {}!\n\
                Expected delta: {}\n\
                Actual delta: {}\n\
                Before: {}\n\
                After: {}\n\
                This indicates the operation did not update the budget correctly!",
                project,
                currency,
                expected_delta,
                actual_delta,
                before_balance,
                current_balance
            )
        ));
    }

    check_budget_non_negative(state, svm, operation, Some(project), Some(currency))?;

    Ok(())
}

/// Helper: Validate Budget Structure
pub fn validate_budget_structure(
    budget: &ProjectCurrencyBudget,
    operation: &str,
) -> Result<(), InvariantViolation> {
    // Check 1: Available can't exceed deposited
    if budget.available_balance > budget.total_deposited {
        return Err(InvariantViolation::new(
            operation,
            "INV-B1-STRUCT",
            &format!(
                "CRITICAL: Budget structure invalid - available ({}) > deposited ({}) for project {} / currency {}",
                budget.available_balance,
                budget.total_deposited,
                budget.project_id,
                budget.currency_id
            )
        ));
    }

    // Check 2: Claimed can't exceed deposited
    if budget.total_claimed > budget.total_deposited {
        return Err(InvariantViolation::new(
            operation,
            "INV-B1-STRUCT",
            &format!(
                "CRITICAL: Budget structure invalid - claimed ({}) > deposited ({}) for project {} / currency {}",
                budget.total_claimed,
                budget.total_deposited,
                budget.project_id,
                budget.currency_id
            )
        ));
    }

    // Check 3: Accounting consistency
    let expected_max_available = budget.total_deposited.saturating_sub(budget.total_claimed);
    if budget.available_balance > expected_max_available {
        return Err(InvariantViolation::new(
            operation,
            "INV-B1-STRUCT",
            &format!(
                "CRITICAL: Budget accounting inconsistent for project {} / currency {}\n\
                Available: {}\n\
                Deposited: {}\n\
                Claimed: {}\n\
                Expected max available: {}\n\
                Available balance exceeds (deposited - claimed)!",
                budget.project_id,
                budget.currency_id,
                budget.available_balance,
                budget.total_deposited,
                budget.total_claimed,
                expected_max_available
            )
        ));
    }

    Ok(())
}

/// INV-B3: Claim Decreases Budget Correctly

pub fn check_claim_decreases_budget_correctly(
    state: &FullSvmState,
    svm: &LiteSVM,
    project: &Pubkey,
    currency: &Pubkey,
    claim_amount: u64,
    project_fee_bp: u16,
    before_balance: u64,
    is_nft: bool,
) -> Result<(), InvariantViolation> {
    // Calculate the expected project claim fee
    const BASIS_POINTS: u64 = 10000;

    let expected_fee = if is_nft {
        // NFTs have NO project fee
        0
    } else {
        // Calculate fee: (amount * fee_bp) / 10000
        claim_amount
            .saturating_mul(project_fee_bp as u64)
            .saturating_div(BASIS_POINTS)
    };

    // Total expected deduction = claim amount + project fee
    let expected_total_deduction = claim_amount.saturating_add(expected_fee);

    // Get the actual budget after the claim
    let after_balance = state.get_project_budget(project, currency);

    // Calculate the actual deduction that occurred
    let actual_deduction = before_balance.saturating_sub(after_balance);

    // The actual deduction must exactly match the expected deduction
    if actual_deduction != expected_total_deduction {
        return Err(InvariantViolation::new(
            "ClaimFromProjectBudget",
            "INV-B3",
            &format!(
                "CRITICAL: Claim did not decrease budget by the correct amount!\n\
                \n\
                Project: {}\n\
                Currency: {}\n\
                \n\
                Claim Amount: {}\n\
                Project Fee ({}bp): {}\n\
                Expected Total Deduction: {} (amount + fee)\n\
                \n\
                Budget Before: {}\n\
                Budget After: {}\n\
                Actual Deduction: {}\n\
                \n\
                MISMATCH: Expected {} but got {}!\n\
                \n\
                This indicates a bug in fee calculation or budget deduction logic.\n\
                Possible causes:\n\
                - Fee calculated incorrectly\n\
                - Fee not deducted from budget\n\
                - Fee deducted twice\n\
                - Budget deduction logic has a bug",
                project,
                currency,
                claim_amount,
                project_fee_bp,
                expected_fee,
                expected_total_deduction,
                before_balance,
                after_balance,
                actual_deduction,
                expected_total_deduction,
                actual_deduction
            )
        ));
    }

    // Additional validation: Ensure budget decreased (not increased)
    if after_balance > before_balance {
        return Err(InvariantViolation::new(
            "ClaimFromProjectBudget",
            "INV-B3",
            &format!(
                "CRITICAL: Budget INCREASED after claim! This should never happen.\n\
                \n\
                Project: {}\n\
                Currency: {}\n\
                Budget Before: {}\n\
                Budget After: {}\n\
                \n\
                A claim should ALWAYS decrease the budget, never increase it!",
                project,
                currency,
                before_balance,
                after_balance
            )
        ));
    }

    // Log successful validation for debugging
    crate::debug_log!(
        "INV-B3 validated claim: amount={}, fee={}bp ({}), total={}, budget: {} -> {}",
        claim_amount,
        project_fee_bp,
        expected_fee,
        expected_total_deduction,
        before_balance,
        after_balance
    );

    // Also run INV-B1 to ensure budget is still non-negative
    check_budget_non_negative(state, svm, "ClaimFromProjectBudget", Some(project), Some(currency))?;

    Ok(())
}

/// Helper: Validate Budget Structure
pub fn validate_budget_structure_v2(
    budget: &ProjectCurrencyBudget,
    operation: &str,
) -> Result<(), InvariantViolation> {
    // Check 1: Available can't exceed deposited
    if budget.available_balance > budget.total_deposited {
        return Err(InvariantViolation::new(
            operation,
            "INV-B1-STRUCT",
            &format!(
                "CRITICAL: Budget structure invalid - available ({}) > deposited ({}) for project {} / currency {}",
                budget.available_balance,
                budget.total_deposited,
                budget.project_id,
                budget.currency_id
            )
        ));
    }

    // Check 2: Claimed can't exceed deposited
    if budget.total_claimed > budget.total_deposited {
        return Err(InvariantViolation::new(
            operation,
            "INV-B1-STRUCT",
            &format!(
                "CRITICAL: Budget structure invalid - claimed ({}) > deposited ({}) for project {} / currency {}",
                budget.total_claimed,
                budget.total_deposited,
                budget.project_id,
                budget.currency_id
            )
        ));
    }

    // Check 3: Accounting consistency
    let expected_max_available = budget.total_deposited.saturating_sub(budget.total_claimed);
    if budget.available_balance > expected_max_available {
        return Err(InvariantViolation::new(
            operation,
            "INV-B1-STRUCT",
            &format!(
                "CRITICAL: Budget accounting inconsistent for project {} / currency {}\n\
                Available: {}\n\
                Deposited: {}\n\
                Claimed: {}\n\
                Expected max available: {}\n\
                Available balance exceeds (deposited - claimed)!",
                budget.project_id,
                budget.currency_id,
                budget.available_balance,
                budget.total_deposited,
                budget.total_claimed,
                expected_max_available
            )
        ));
    }

    Ok(())
}

/// INV-B2: Deposit Increases Budget
pub fn check_deposit_increases_budget(
    state: &FullSvmState,
    svm: &LiteSVM,
    project: &Pubkey,
    currency: &Pubkey,
    deposit_amount: u64,
    before_balance: u64,
    before_total_deposited: u64,
) -> Result<(), InvariantViolation> {
    // STEP 1: Validate internal state tracking
    let after_balance = state.get_project_budget(project, currency);

    // Get the full budget structure to check total_deposited
    let budget_key = (project.clone(), currency.clone());
    let budget = state.project_budgets.get(&budget_key)
        .ok_or_else(|| InvariantViolation::new(
            "Deposit",
            "INV-B2",
            &format!("Budget not found after deposit for project {} / currency {}", project, currency)
        ))?;

    // Check 1: Available balance should increase by deposit amount
    let expected_balance = before_balance.saturating_add(deposit_amount);
    if after_balance != expected_balance {
        return Err(InvariantViolation::new(
            "Deposit",
            "INV-B2",
            &format!(
                "CRITICAL: Deposit did not increase available balance correctly!\n\
                \n\
                Project: {}\n\
                Currency: {}\n\
                Deposit Amount: {}\n\
                \n\
                Balance Before: {}\n\
                Balance After: {}\n\
                Expected After: {}\n\
                \n\
                MISMATCH: Expected {} but got {}!",
                project, currency, deposit_amount,
                before_balance, after_balance, expected_balance,
                expected_balance, after_balance
            )
        ));
    }

    // Check 2: Total deposited should increase by deposit amount
    let expected_total = before_total_deposited.saturating_add(deposit_amount);
    if budget.total_deposited != expected_total {
        return Err(InvariantViolation::new(
            "Deposit",
            "INV-B2",
            &format!(
                "CRITICAL: Deposit did not increase total_deposited correctly!\n\
                \n\
                Project: {}\n\
                Currency: {}\n\
                Deposit Amount: {}\n\
                \n\
                Total Deposited Before: {}\n\
                Total Deposited After: {}\n\
                Expected After: {}\n\
                \n\
                MISMATCH: Expected {} but got {}!",
                project, currency, deposit_amount,
                before_total_deposited, budget.total_deposited, expected_total,
                expected_total, budget.total_deposited
            )
        ));
    }

    // STEP 2: Read and validate ON-CHAIN state
    match read_on_chain_budget(svm, project, currency) {
        Ok((_onchain_deposited, _onchain_claimed, onchain_available)) => {

            // Verify on-chain available_balance increased correctly
            let expected_onchain_available = before_balance.saturating_add(deposit_amount);
            if onchain_available != expected_onchain_available {
                return Err(InvariantViolation::new(
                    "Deposit",
                    "INV-B2-ONCHAIN",
                    &format!(
                        "CRITICAL: On-chain available_balance did not increase correctly!\n\
                        \n\
                        Project: {}\n\
                        Currency: {}\n\
                        Deposit Amount: {}\n\
                        \n\
                        Before Deposit: {}\n\
                        After Deposit (on-chain): {}\n\
                        Expected: {}\n\
                        \n\
                        This means the on-chain budget did NOT increase as expected!",
                        project, currency, deposit_amount,
                        before_balance, onchain_available, expected_onchain_available
                    )
                ));
            }

            crate::debug_log!(
                "INV-B2 On-chain validation passed: available={}",
                onchain_available
            );
        },
        Err(e) => {
            // If this is the first deposit, the account might not exist yet, which is OK
            if before_balance == 0 && before_total_deposited == 0 {
                crate::debug_log!(
                    "INV-B2 Budget account not found on-chain (likely first deposit): {}",
                    e
                );
            } else {
                return Err(InvariantViolation::new(
                    "Deposit",
                    "INV-B2-ONCHAIN",
                    &format!(
                        "Failed to read on-chain budget after deposit!\n\
                        Project: {}\n\
                        Currency: {}\n\
                        Error: {}",
                        project, currency, e
                    )
                ));
            }
        }
    }

    // Non-negativity check
    check_budget_non_negative(state, svm, "Deposit", Some(project), Some(currency))?;

    crate::debug_log!(
        "INV-B2 Deposit fully validated: amount={}, balance: {} -> {}, total_deposited: {} -> {}",
        deposit_amount, before_balance, after_balance,
        before_total_deposited, budget.total_deposited
    );

    Ok(())
}

/// INV-B4: Remove Decreases Budget by Full Amount
pub fn check_remove_decreases_budget(
    state: &FullSvmState,
    svm: &LiteSVM,
    project: &Pubkey,
    currency: &Pubkey,
    remove_amount: u64,
    before_balance: u64,
) -> Result<(), InvariantViolation> {
    // STEP 1: Validate internal state tracking
    let after_balance = state.get_project_budget(project, currency);

    // Calculate expected balance after removal
    let expected_balance = before_balance.saturating_sub(remove_amount);

    // Check that budget decreased by exactly the remove amount
    if after_balance != expected_balance {
        return Err(InvariantViolation::new(
            "Remove",
            "INV-B4",
            &format!(
                "CRITICAL: Remove did not decrease budget by correct amount!\n\
                \n\
                Project: {}\n\
                Currency: {}\n\
                Remove Amount: {}\n\
                \n\
                Balance Before: {}\n\
                Balance After: {}\n\
                Expected After: {}\n\
                \n\
                MISMATCH: Expected {} but got {}!\n\
                \n\
                Note: Budget should decrease by FULL amount, even though\n\
                recipient only gets (amount - fee).",
                project, currency, remove_amount,
                before_balance, after_balance, expected_balance,
                expected_balance, after_balance
            )
        ));
    }

    // Additional check: ensure budget decreased (not increased)
    if after_balance > before_balance {
        return Err(InvariantViolation::new(
            "Remove",
            "INV-B4",
            &format!(
                "CRITICAL: Budget INCREASED after removal! This should never happen.\n\
                \n\
                Project: {}\n\
                Currency: {}\n\
                Balance Before: {}\n\
                Balance After: {}",
                project, currency, before_balance, after_balance
            )
        ));
    }

    // STEP 2: Read and validate state
    match read_on_chain_budget(svm, project, currency) {
        Ok((_onchain_deposited, _onchain_claimed, onchain_available)) => {

            // Verify on-chain available_balance decreased correctly
            let expected_onchain_available = before_balance.saturating_sub(remove_amount);
            if onchain_available != expected_onchain_available {
                return Err(InvariantViolation::new(
                    "Remove",
                    "INV-B4-ONCHAIN",
                    &format!(
                        "CRITICAL: On-chain available_balance did not decrease correctly!\n\
                        \n\
                        Project: {}\n\
                        Currency: {}\n\
                        Remove Amount: {}\n\
                        \n\
                        Before Remove: {}\n\
                        After Remove (on-chain): {}\n\
                        Expected: {}\n\
                        \n\
                        This means the on-chain budget did not decrease as expected!\n\
                        Either the transaction failed silently or there's a bug in the program.",
                        project, currency, remove_amount,
                        before_balance, onchain_available, expected_onchain_available
                    )
                ));
            }

            crate::debug_log!(
                "INV-B4 On-chain validation passed: available={}",
                onchain_available
            );
        },
        Err(e) => {
            return Err(InvariantViolation::new(
                "Remove",
                "INV-B4-ONCHAIN",
                &format!(
                    "Failed to read on-chain budget after remove!\n\
                    Project: {}\n\
                    Currency: {}\n\
                    Error: {}\n\
                    \n\
                    This shouldn't happen - budget account should exist if we're removing from it.",
                    project, currency, e
                )
            ));
        }
    }

    // Run standard non-negativity check
    check_budget_non_negative(state, svm, "Remove", Some(project), Some(currency))?;

    crate::debug_log!(
        "INV-B4 Remove fully validated: amount={}, balance: {} -> {}",
        remove_amount, before_balance, after_balance
    );

    Ok(())
}

/// INV-B5: Conservation of Funds (Claim)
pub fn check_claim_conservation_of_funds(
    state: &FullSvmState,
    svm: &LiteSVM,
    project: &Pubkey,
    currency: &Pubkey,
    budget_decrease: u64,
    recipient_amount: u64,
    fee_amount: u64,
    before_available: u64,
    before_claimed: u64,
) -> Result<(), InvariantViolation> {
    // STEP 1: Validate the conservation equation
    let total_out = recipient_amount.saturating_add(fee_amount);

    // Check conservation: budget decrease must equal total out
    if budget_decrease != total_out {
        return Err(InvariantViolation::new(
            "ClaimFromProjectBudget",
            "INV-B5",
            &format!(
                "CRITICAL: Funds not conserved during claim!\n\
                \n\
                Project: {}\n\
                Currency: {}\n\
                \n\
                Budget Decreased By: {}\n\
                Recipient Received: {}\n\
                Fee Collector Got: {}\n\
                Total Out: {}\n\
                \n\
                CONSERVATION VIOLATED: {} != {}!\n\
                \n\
                This means {} tokens were {}!",
                project, currency,
                budget_decrease,
                recipient_amount,
                fee_amount,
                total_out,
                budget_decrease, total_out,
                if budget_decrease > total_out {
                    budget_decrease - total_out
                } else {
                    total_out - budget_decrease
                },
                if budget_decrease > total_out { "lost" } else { "created from nothing" }
            )
        ));
    }

    // STEP 2: Verify on-chain state reflects the conservation
    match read_on_chain_budget(svm, project, currency) {
        Ok((_onchain_deposited, _onchain_claimed, onchain_available)) => {

            // Verify available balance decreased by the expected amount
            let expected_available = before_available.saturating_sub(budget_decrease);
            if onchain_available != expected_available {
                return Err(InvariantViolation::new(
                    "ClaimFromProjectBudget",
                    "INV-B5-ONCHAIN",
                    &format!(
                        "CRITICAL: On-chain available balance doesn't match conservation!\n\
                        \n\
                        Project: {}\n\
                        Currency: {}\n\
                        \n\
                        Before Claim: {}\n\
                        Budget Decrease: {}\n\
                        Expected After: {}\n\
                        Actual On-chain: {}\n\
                        \n\
                        This indicates funds were not properly conserved on-chain!",
                        project, currency,
                        before_available, budget_decrease,
                        expected_available, onchain_available
                    )
                ));
            }

            crate::debug_log!(
                "INV-B5 On-chain conservation verified: available={}",
                onchain_available
            );
        },
        Err(e) => {
            if before_available == 0 && before_claimed == 0 {
                crate::debug_log!(
                    "INV-B5 Budget account not found on-chain (likely no prior deposits): {}",
                    e
                );
                return Ok(());
            }

            // If we had a budget before, it should still exist
            return Err(InvariantViolation::new(
                "ClaimFromProjectBudget",
                "INV-B5-ONCHAIN",
                &format!(
                    "Failed to read on-chain budget after claim!\n\
                    Project: {}\n\
                    Currency: {}\n\
                    Error: {}\n\
                    \n\
                    Budget existed before (balance={}, claimed={}) but not found after claim!",
                    project, currency, e, before_available, before_claimed
                )
            ));
        }
    }

    crate::debug_log!(
        "INV-B5 Claim conservation fully validated: budget_decrease={} = recipient({}) + fee({})",
        budget_decrease, recipient_amount, fee_amount
    );

    Ok(())
}

/// INV-B6: Conservation of Funds (Remove)
pub fn check_remove_conservation_of_funds(
    state: &FullSvmState,
    svm: &LiteSVM,
    project: &Pubkey,
    currency: &Pubkey,
    budget_decrease: u64,
    authority_amount: u64,
    fee_amount: u64,
    before_available: u64,
) -> Result<(), InvariantViolation> {
    // STEP 1: Validate the conservation equation
    let total_out = authority_amount.saturating_add(fee_amount);

    // Check conservation: budget decrease must equal total out
    if budget_decrease != total_out {
        return Err(InvariantViolation::new(
            "Remove",
            "INV-B6",
            &format!(
                "CRITICAL: Funds not conserved during remove!\n\
                \n\
                Project: {}\n\
                Currency: {}\n\
                \n\
                Budget Decreased By: {}\n\
                Authority Received: {}\n\
                Fee Collector Got: {}\n\
                Total Out: {}\n\
                \n\
                CONSERVATION VIOLATED: {} != {}!\n\
                \n\
                This means {} tokens were {}!",
                project, currency,
                budget_decrease,
                authority_amount,
                fee_amount,
                total_out,
                budget_decrease, total_out,
                if budget_decrease > total_out {
                    budget_decrease - total_out
                } else {
                    total_out - budget_decrease
                },
                if budget_decrease > total_out { "lost" } else { "created from nothing" }
            )
        ));
    }

    // STEP 2: Verify state reflects the conservation
    match read_on_chain_budget(svm, project, currency) {
        Ok((_onchain_deposited, _onchain_claimed, onchain_available)) => {

            // Verify available balance decreased by the expected amount
            let expected_available = before_available.saturating_sub(budget_decrease);
            if onchain_available != expected_available {
                return Err(InvariantViolation::new(
                    "Remove",
                    "INV-B6-ONCHAIN",
                    &format!(
                        "CRITICAL: On-chain available balance doesn't match conservation!\n\
                        \n\
                        Project: {}\n\
                        Currency: {}\n\
                        \n\
                        Before Remove: {}\n\
                        Budget Decrease: {}\n\
                        Expected After: {}\n\
                        Actual On-chain: {}\n\
                        \n\
                        This indicates funds were not properly conserved on-chain!",
                        project, currency,
                        before_available, budget_decrease,
                        expected_available, onchain_available
                    )
                ));
            }

            crate::debug_log!(
                "INV-B6 On-chain conservation verified: available={}",
                onchain_available
            );
        },
        Err(e) => {
            if before_available == 0 {
                crate::debug_log!(
                    "INV-B6 Budget account not found on-chain after remove (was empty before): {}",
                    e
                );
                return Ok(());
            }

            // Budget should exist if we're removing from it and it had funds before
            return Err(InvariantViolation::new(
                "Remove",
                "INV-B6-ONCHAIN",
                &format!(
                    "Failed to read on-chain budget after remove!\n\
                    Project: {}\n\
                    Currency: {}\n\
                    Error: {}\n\
                    \n\
                    Budget had balance={} before remove but account not found after!",
                    project, currency, e, before_available
                )
            ));
        }
    }

    crate::debug_log!(
        "INV-B6 Remove conservation fully validated: budget_decrease={} = authority({}) + fee({})",
        budget_decrease, authority_amount, fee_amount
    );

    Ok(())
}
