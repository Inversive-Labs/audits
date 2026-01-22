use crate::targets::full_svm::{
    state::{FullSvmState, CurrencyType},
    invariants::InvariantViolation,
};
use solana_sdk::pubkey::Pubkey;
use litesvm::LiteSVM;
use borsh::BorshDeserialize;

// Constant from protocol
const BASIS_POINTS: u16 = 10000;

// ============================================================================
// INV-M1: Sum of All Budgets Conservation
// ============================================================================

/// INV-M1: Sum of All Budgets Conservation
pub fn check_global_conservation(
    state: &FullSvmState,
    svm: &LiteSVM,
    context: &str,
) -> Result<(), InvariantViolation> {
    // STEP 1: Validate internal state consistency
    let mut total_deposited: u128 = 0;
    let mut total_claimed: u128 = 0;
    let mut total_available: u128 = 0;

    for ((project_id, currency_id), budget) in &state.project_budgets {
        total_deposited = total_deposited.saturating_add(budget.total_deposited as u128);
        total_claimed = total_claimed.saturating_add(budget.total_claimed as u128);
        total_available = total_available.saturating_add(budget.available_balance as u128);
    }

    let expected_max_available = total_deposited.saturating_sub(total_claimed);

    // Check 1: available_balance can never exceed deposited - claimed
    if total_available > expected_max_available {
        // More funds available than should be - funds created from nothing!
        return Err(InvariantViolation::new(
            context,
            "INV-M1",
            &format!(
                "CRITICAL: Funds created from nothing!\n\
                \n\
                Total Deposited: {} lamports\n\
                Total Claimed: {} lamports\n\
                Expected Max Available: {} lamports (deposited - claimed)\n\
                Actual Available: {} lamports\n\
                Excess: {} lamports\n\
                \n\
                Available balance should NEVER exceed (deposited - claimed).\n\
                This indicates a fund creation vulnerability!",
                total_deposited, total_claimed, expected_max_available, total_available,
                total_available - expected_max_available
            )
        ));
    }

    // Check 2: total_claimed can never exceed total_deposited
    if total_claimed > total_deposited {
        return Err(InvariantViolation::new(
            context,
            "INV-M1",
            &format!(
                "CRITICAL: More claimed than deposited!\n\
                \n\
                Total Deposited: {} lamports\n\
                Total Claimed: {} lamports\n\
                Over-claimed: {} lamports\n\
                \n\
                This indicates an underflow vulnerability or double-claim bug!",
                total_deposited, total_claimed,
                total_claimed - total_deposited
            )
        ));
    }

    crate::debug_log!(
        "INV-M1 STEP 1 Internal conservation valid: deposited={}, claimed={}, available={}",
        total_deposited, total_claimed, total_available
    );

    // STEP 2: Verify local state matches on-chain state
    let mut on_chain_total_available: u128 = 0;
    let mut sync_errors: Vec<String> = Vec::new();

    for ((project_id, currency_id), budget) in &state.project_budgets {
        match read_project_budget_on_chain(svm, project_id, currency_id) {
            Ok(on_chain_budget) => {
                on_chain_total_available = on_chain_total_available.saturating_add(on_chain_budget as u128);

                // Verify this budget matches on-chain
                if budget.available_balance != on_chain_budget {
                    sync_errors.push(format!(
                        "  - Project {} / Currency {}: local={}, on-chain={}",
                        project_id, currency_id,
                        budget.available_balance, on_chain_budget
                    ));
                }
            }
            Err(e) => {
                // Budget account might not exist yet (before first deposit)
                if budget.available_balance > 0 {
                    crate::debug_log!(
                        "INV-M1 STEP 2 Budget not found on-chain for {}/{} but has balance {}: {}",
                        project_id, currency_id, budget.available_balance, e
                    );
                }
            }
        }
    }

    // If we found sync errors, report them
    if !sync_errors.is_empty() {
        return Err(InvariantViolation::new(
            context,
            "INV-M1-SYNC",
            &format!(
                "CRITICAL: Local state desync with on-chain state!\n\
                \n\
                The following budgets have mismatched available_balance:\n\
                {}\n\
                \n\
                Local Total Available: {} lamports\n\
                On-chain Total Available: {} lamports\n\
                \n\
                This indicates our fuzzer's state tracking is out of sync with LiteSVM.",
                sync_errors.join("\n"),
                total_available,
                on_chain_total_available
            )
        ));
    }

    crate::debug_log!(
        "INV-M1 STEP 2 On-chain sync verified: {} budgets checked, total={}",
        state.project_budgets.len(),
        on_chain_total_available
    );

    Ok(())
}

// INV-M2: Integer Overflow/Underflow Protection
pub fn check_arithmetic_safety(
    operation: &str,
    operand_a: u64,
    operand_b: u64,
    result: Option<u64>,
    context: &str,
) -> Result<(), InvariantViolation> {
    let expected = match operation {
        "add" => operand_a.checked_add(operand_b),
        "sub" => operand_a.checked_sub(operand_b),
        "mul" => operand_a.checked_mul(operand_b),
        "div" => if operand_b != 0 {
            operand_a.checked_div(operand_b)
        } else {
            None
        },
        _ => return Ok(()),
    };

    if result != expected {
        return Err(InvariantViolation::new(
            context,
            "INV-M2",
            &format!(
                "CRITICAL: Arithmetic safety violation!\n\
                \n\
                Operation: {} {} {}\n\
                Operand A: {}\n\
                Operand B: {}\n\
                Actual Result: {:?}\n\
                Expected Result: {:?}\n\
                \n\
                Protocol must use checked arithmetic to prevent overflow/underflow!",
                operand_a, operation, operand_b,
                operand_a, operand_b,
                result, expected
            )
        ));
    }

    if operation == "add" && result.is_none() {
        let unchecked = operand_a.wrapping_add(operand_b);
        if unchecked < operand_a || unchecked < operand_b {
            return Ok(());
        }
    }

    if operation == "sub" && result.is_none() && operand_a < operand_b {
        return Ok(());
    }

    Ok(())
}

// INV-M3: Fee Calculation Correctness
pub fn check_fee_calculation(
    amount: u64,
    fee_basis_points: u16,
    calculated_fee: u64,
    operation: &str,
    token_type: &CurrencyType,
    context: &str,
) -> Result<(), InvariantViolation> {
    // Check basis points bounds (0-10000)
    if fee_basis_points > BASIS_POINTS {
        return Err(InvariantViolation::new(
            context,
            "INV-M3",
            &format!(
                "Invalid fee basis points!\n\
                Operation: {}\n\
                Basis points: {} (max: {})",
                operation, fee_basis_points, BASIS_POINTS
            )
        ));
    }

    // NFT claims must have zero project fee
    if matches!(token_type, CurrencyType::NonFungible) && operation == "Claim" {
        if calculated_fee != 0 {
            return Err(InvariantViolation::new(
                context,
                "INV-M3",
                &format!(
                    "NFT claim has non-zero project fee!\n\
                    Fee: {} (must be 0)\n\
                    Protocol explicitly sets NFT claim fees to 0",
                    calculated_fee
                )
            ));
        }
        return Ok(());
    }

    // Calculate expected fee using protocol's exact formula
    let expected_fee = amount
        .checked_mul(fee_basis_points as u64)
        .and_then(|v| v.checked_div(BASIS_POINTS as u64))
        .unwrap_or(0);

    // For removes, check minimum fee enforcement
    if operation == "Remove" && fee_basis_points > 0 && expected_fee == 0 {
        // Protocol enforces minimum fee - this should have errored
        return Err(InvariantViolation::new(
            context,
            "INV-M3",
            &format!(
                "Remove operation with configured fee but zero calculated amount!\n\
                Amount: {}\n\
                Fee basis points: {}\n\
                Protocol should enforce minimum fee (FuulError::AmountTooSmall)",
                amount, fee_basis_points
            )
        ));
    }

    if calculated_fee != expected_fee {
        return Err(InvariantViolation::new(
            context,
            "INV-M3",
            &format!(
                "Fee calculation mismatch!\n\
                Operation: {}\n\
                Amount: {}\n\
                Fee basis points: {}\n\
                Calculated fee: {}\n\
                Expected fee: {}\n\
                Discrepancy: {} lamports",
                operation, amount, fee_basis_points,
                calculated_fee, expected_fee,
                calculated_fee.abs_diff(expected_fee)
            )
        ));
    }

    // Verify fee doesn't exceed amount
    if calculated_fee > amount {
        return Err(InvariantViolation::new(
            context,
            "INV-M3",
            &format!(
                "Fee exceeds amount!\n\
                Operation: {}\n\
                Amount: {}\n\
                Fee: {} ({:.2}%)",
                operation, amount, calculated_fee,
                (calculated_fee as f64 / amount as f64) * 100.0
            )
        ));
    }

    Ok(())
}

// INV-M4: NFT Amount Constraints
pub fn check_nft_constraints(
    token_type: &CurrencyType,
    operation: &str,
    amount: u64,
    budget_change: u64,
    project_fee: u64,
    context: &str,
) -> Result<(), InvariantViolation> {
    // Only check NFT tokens
    if !matches!(token_type, CurrencyType::NonFungible) {
        return Ok(());
    }

    // All NFT operations must use amount = 1
    if amount != 1 {
        return Err(InvariantViolation::new(
            context,
            "INV-M4",
            &format!(
                "CRITICAL: NFT operation with amount != 1!\n\
                \n\
                Operation: {}\n\
                Amount: {} (must be 1)\n\
                \n\
                Protocol enforces: NFTs are indivisible (line 782-784)",
                operation, amount
            )
        ));
    }

    // NFT budget changes must be exactly 1
    if budget_change != 0 && budget_change != 1 {
        return Err(InvariantViolation::new(
            context,
            "INV-M4",
            &format!(
                "NFT budget change != 1!\n\
                Operation: {}\n\
                Budget change: {} (must be 1)\n\
                Protocol adds/removes exactly 1 for NFTs",
                operation, budget_change
            )
        ));
    }

    // NFT claims must have zero project fee
    if operation == "Claim" && project_fee != 0 {
        return Err(InvariantViolation::new(
            context,
            "INV-M4",
            &format!(
                "NFT claim has non-zero project fee!\n\
                Project fee: {} (must be 0)\n\
                Protocol explicitly sets to 0 for NonFungibleSpl",
                project_fee
            )
        ));
    }

    Ok(())
}

// INV-M5: Budget Deduction Correctness for Claims
pub fn check_claim_budget_deduction(
    claim_amount: u64,
    project_fee: u64,
    budget_before: u64,
    budget_after: u64,
    context: &str,
) -> Result<(), InvariantViolation> {
    let expected_deduction = claim_amount
        .checked_add(project_fee)
        .ok_or_else(|| InvariantViolation::new(
            context,
            "INV-M5",
            "Overflow calculating total deduction"
        ))?;

    let expected_budget = budget_before
        .checked_sub(expected_deduction)
        .ok_or_else(|| InvariantViolation::new(
            context,
            "INV-M5",
            &format!(
                "Budget underflow!\n\
                Budget before: {}\n\
                Total to deduct: {} (claim: {} + fee: {})\n\
                Would result in negative budget!",
                budget_before, expected_deduction, claim_amount, project_fee
            )
        ))?;

    if budget_after != expected_budget {
        return Err(InvariantViolation::new(
            context,
            "INV-M5",
            &format!(
                "Incorrect budget deduction for claim!\n\
                \n\
                Budget before: {}\n\
                Claim amount: {}\n\
                Project fee: {}\n\
                Total deducted: {}\n\
                \n\
                Expected budget after: {}\n\
                Actual budget after: {}\n\
                Discrepancy: {} lamports\n\
                \n\
                Protocol requires: budget -= (amount + fee)",
                budget_before, claim_amount, project_fee, expected_deduction,
                expected_budget, budget_after,
                budget_after.abs_diff(expected_budget)
            )
        ));
    }

    Ok(())
}

// Helper Functions: read project budget from on-chain
pub fn read_project_budget_on_chain(
    svm: &LiteSVM,
    project_id: &Pubkey,
    currency_id: &Pubkey,
) -> Result<u64, String> {
    // Get currency token PDA
    let (currency_pda, _) = Pubkey::find_program_address(
        &[b"currency-token", currency_id.as_ref()],
        &crate::targets::full_svm::PROGRAM_ID,
    );

    // Get project budget PDA
    let (budget_pda, _) = Pubkey::find_program_address(
        &[b"project-currency-budget", project_id.as_ref(), currency_pda.as_ref()],
        &crate::targets::full_svm::PROGRAM_ID,
    );

    let account = svm.get_account(&budget_pda)
        .ok_or_else(|| format!("Budget account not found at {}", budget_pda))?;

    // Skip 8-byte Anchor discriminator
    let data = &account.data[8..];
    let mut slice = data;

    // ProjectCurrencyBudget first field is budget (u64)
    let budget = u64::deserialize(&mut slice)
        .map_err(|e| format!("Failed to deserialize budget: {}", e))?;

    Ok(budget)
}

/// Comprehensive math invariant checks for an operation
pub fn check_operation_math_invariants(
    state: &FullSvmState,
    operation: &str,
    amount: u64,
    fee_amount: u64,
    fee_basis_points: u16,
    token_type: &CurrencyType,
    budget_before: Option<u64>,
    budget_after: Option<u64>,
    context: &str,
) -> Result<(), InvariantViolation> {
    // INV-M2: Verify arithmetic safety for all critical operations
    if fee_basis_points > 0 {
        let fee_mul_result = amount.checked_mul(fee_basis_points as u64);

        // If multiplication would overflow, verify the operation was rejected
        if fee_mul_result.is_none() && fee_amount > 0 {
            return Err(InvariantViolation::new(
                context,
                "INV-M2",
                &format!(
                    "CRITICAL: Fee multiplication overflow not prevented!\n\
                    \n\
                    Operation: {}\n\
                    Amount: {}\n\
                    Fee Basis Points: {}\n\
                    Multiplication: {} * {} = OVERFLOW\n\
                    But fee_amount was: {} (should be 0 or rejected)\n\
                    \n\
                    The protocol should reject this with FuulError::Overflow.\n\
                    This indicates missing overflow protection in fee calculation.",
                    operation, amount, fee_basis_points,
                    amount, fee_basis_points, fee_amount
                )
            ));
        }

        // Verify the fee calculation matches: (amount * fee_bp) / 10000
        if let Some(product) = fee_mul_result {
            let expected_fee = product / (BASIS_POINTS as u64);
            check_arithmetic_safety(
                "mul",
                amount,
                fee_basis_points as u64,
                Some(product),
                &format!("{} - fee multiplication", context)
            )?;

            // Verify the division result
            check_arithmetic_safety(
                "div",
                product,
                BASIS_POINTS as u64,
                Some(expected_fee),
                &format!("{} - fee division", context)
            )?;
        }
    }

    // Check 2: Total deduction for claims/removes
    if operation == "Claim" || operation == "Remove" {
        let total_deduction = if operation == "Remove" {
            // For RemoveFungibleToken: budget decreases by amount only
            Some(amount)
        } else {
            // For Claims: budget decreases by amount + fee
            amount.checked_add(fee_amount)
        };

        if total_deduction.is_none() {
            return Err(InvariantViolation::new(
                context,
                "INV-M2",
                &format!(
                    "CRITICAL: Total deduction overflow!\n\
                    \n\
                    Operation: {}\n\
                    Amount: {}\n\
                    Fee: {}\n\
                    Sum: {} + {} = OVERFLOW\n\
                    \n\
                    The protocol should reject this with FuulError::Overflow.",
                    operation, amount, fee_amount, amount, fee_amount
                )
            ));
        }

        // Only check addition for Claims
        if operation == "Claim" {
            check_arithmetic_safety(
                "add",
                amount,
                fee_amount,
                total_deduction,
                &format!("{} - total deduction", context)
            )?;
        }

        // Check 3: Budget subtraction (budget - deduction)
        if let (Some(before), Some(deduction)) = (budget_before, total_deduction) {
            let expected_after = before.checked_sub(deduction);

            if expected_after.is_none() && budget_after.is_some() {
                return Err(InvariantViolation::new(
                    context,
                    "INV-M2",
                    &format!(
                        "CRITICAL: Budget underflow not prevented!\n\
                        \n\
                        Operation: {}\n\
                        Budget Before: {}\n\
                        Total Deduction: {}\n\
                        Subtraction: {} - {} = UNDERFLOW\n\
                        But budget_after is: {:?}\n\
                        \n\
                        The protocol should reject this with FuulError::Underflow.",
                        operation, before, deduction, before, deduction, budget_after
                    )
                ));
            }

            if let Some(after) = budget_after {
                check_arithmetic_safety(
                    "sub",
                    before,
                    deduction,
                    Some(after),
                    &format!("{} - budget subtraction", context)
                )?;
            }
        }
    }

    // Check 4: Deposit addition (budget + amount)
    if operation == "DepositFungibleToken" || operation == "DepositNonFungibleToken" {
        if let Some(before) = budget_before {
            let expected_after = before.checked_add(amount);

            // If addition would overflow, the transaction should have been rejected
            if expected_after.is_none() && budget_after.is_some() {
                return Err(InvariantViolation::new(
                    context,
                    "INV-M2",
                    &format!(
                        "CRITICAL: Deposit overflow not prevented!\n\
                        \n\
                        Operation: {}\n\
                        Budget Before: {}\n\
                        Deposit Amount: {}\n\
                        Addition: {} + {} = OVERFLOW\n\
                        But budget_after is: {:?}\n\
                        \n\
                        The protocol should reject this with FuulError::Overflow.",
                        operation, before, amount, before, amount, budget_after
                    )
                ));
            }

            if let Some(after) = budget_after {
                check_arithmetic_safety(
                    "add",
                    before,
                    amount,
                    Some(after),
                    &format!("{} - deposit addition", context)
                )?;
            }
        }
    }

    // INV-M3: Check fee calculation correctness
    if fee_basis_points > 0 || fee_amount > 0 {
        check_fee_calculation(
            amount,
            fee_basis_points,
            fee_amount,
            operation,
            token_type,
            context
        )?;
    }

    // INV-M4: Check NFT constraints
    if matches!(token_type, CurrencyType::NonFungible) {
        let budget_change = if let (Some(before), Some(after)) = (budget_before, budget_after) {
            after.abs_diff(before)
        } else {
            0
        };

        check_nft_constraints(
            token_type,
            operation,
            amount,
            budget_change,
            fee_amount,
            context
        )?;
    }

    // INV-M5: Check claim budget deduction
    if operation == "Claim" {
        if let (Some(before), Some(after)) = (budget_before, budget_after) {
            check_claim_budget_deduction(
                amount,
                fee_amount,
                before,
                after,
                context
            )?;
        }
    }

    Ok(())
}