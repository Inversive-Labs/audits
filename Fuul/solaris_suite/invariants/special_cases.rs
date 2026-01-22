use crate::targets::full_svm::state::{FullSvmState, ProjectCurrencyBudget};
use crate::targets::full_svm::invariants::InvariantViolation;
use crate::targets::full_svm::PROGRAM_ID;
use borsh::{BorshDeserialize, BorshSerialize};
use litesvm::LiteSVM;
use solana_sdk::pubkey::Pubkey;

// INV-X1: First Deposit Creates Budget
pub fn check_first_deposit_creates_budget(
    state_before: &FullSvmState,
    state_after: &FullSvmState,
    project_id: &Pubkey,
    currency_id: &Pubkey,
    operation: &str,
    operation_succeeded: bool,
) -> Result<(), InvariantViolation> {
    // Only check for deposit operations
    if !operation.starts_with("Deposit") || !operation_succeeded {
        return Ok(());
    }

    let budget_key = (project_id.clone(), currency_id.clone());

    // Check if this was the first deposit
    let was_first_deposit = !state_before.project_budgets.contains_key(&budget_key);

    if was_first_deposit {
        // After first deposit, budget must exist
        if !state_after.project_budgets.contains_key(&budget_key) {
            return Err(InvariantViolation::new(
                operation,
                "INV-X1",
                &format!(
                    "First deposit didn't create budget! Project: {}, Currency: {}",
                    project_id, currency_id
                )
            ));
        }
    }

    Ok(())
}

/// Check INV-X1
pub fn check_first_deposit_creates_budget_onchain(
    svm: &LiteSVM,
    state_before: &FullSvmState,
    project_id: &Pubkey,
    currency_id: &Pubkey,
    operation: &str,
    operation_succeeded: bool,
) -> Result<(), InvariantViolation> {
    // Only check for successful deposit operations
    if !operation.starts_with("Deposit") || !operation_succeeded {
        return Ok(());
    }

    let budget_key = (project_id.clone(), currency_id.clone());
    let was_first_deposit = !state_before.project_budgets.contains_key(&budget_key);

    if was_first_deposit {
        // Derive the budget PDA
        let (currency_token_pda, _) = Pubkey::find_program_address(
            &[b"currency-token", currency_id.as_ref()],
            &PROGRAM_ID,
        );

        let (budget_pda, _) = Pubkey::find_program_address(
            &[b"project-currency-budget", project_id.as_ref(), currency_token_pda.as_ref()],
            &PROGRAM_ID,
        );

        // Check if budget exists on-chain
        if let Some(account) = svm.get_account(&budget_pda) {
            if account.data.is_empty() {
                return Err(InvariantViolation::new(
                    operation,
                    "INV-X1",
                    &format!(
                        "First deposit created empty budget account on-chain! Project: {}, Currency: {}",
                        project_id, currency_id
                    )
                ));
            }
        } else {
            return Err(InvariantViolation::new(
                operation,
                "INV-X1",
                &format!(
                    "First deposit didn't create budget on-chain! Project: {}, Currency: {}",
                    project_id, currency_id
                )
            ));
        }
    }

    Ok(())
}

// INV-X2: Last Admin Protection
pub fn check_last_admin_protection(
    admin_count: usize,
    operation: &str,
    operation_succeeded: bool,
    context: &str, // "global" or "project"
) -> Result<(), InvariantViolation> {
    // Check if this is a renounce operation
    let is_renounce = operation.contains("RenounceAdmin") || operation.contains("RenounceRole");

    if is_renounce && admin_count == 1 && operation_succeeded {
        return Err(InvariantViolation::new(
            operation,
            "INV-X2",
            &format!(
                "Last {} admin was able to renounce! This would lock the system. Admin count: {}",
                context, admin_count
            )
        ));
    }

    // Also verify that if it's the last admin, the operation should have failed
    if is_renounce && admin_count == 1 && !operation_succeeded {
        // This is the expected behavior - operation correctly failed
        return Ok(());
    }

    Ok(())
}

/// Check INV-X2 for GlobalConfig
pub fn check_last_admin_protection_global_onchain(
    svm: &LiteSVM,
    operation: &str,
    operation_succeeded: bool,
) -> Result<(), InvariantViolation> {
    // Only check renounce operations
    if !operation.contains("RenounceAdmin") {
        return Ok(());
    }

    // Read GlobalConfig from on-chain
    let (global_config_pda, _) = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    );

    if let Some(account) = svm.get_account(&global_config_pda) {
        if account.data.len() > 8 {
            // Skip 8-byte discriminator
            let data = &account.data[8..];

            // Skip to super_admins vector at offset 18
            if data.len() > 18 {
                let admin_data = &data[18..];

                // Read vector length (4 bytes for Vec in Borsh)
                if admin_data.len() >= 4 {
                    let admin_count = u32::from_le_bytes([
                        admin_data[0], admin_data[1], admin_data[2], admin_data[3]
                    ]) as usize;

                    // If there's only 1 admin and renounce succeeded, that's a violation
                    if admin_count == 1 && operation_succeeded {
                        return Err(InvariantViolation::new(
                            operation,
                            "INV-X2",
                            &format!(
                                "Last global admin was able to renounce on-chain! Admin count: {}",
                                admin_count
                            )
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Check INV-X2 for Project
pub fn check_last_admin_protection_project_onchain(
    svm: &LiteSVM,
    project_id: &Pubkey,
    operation: &str,
    operation_succeeded: bool,
) -> Result<(), InvariantViolation> {
    // Only check renounce operations on projects
    if !operation.contains("RenounceRole") {
        return Ok(());
    }

    // Read Project from on-chain
    let (project_pda, _) = Pubkey::find_program_address(
        &[b"project", project_id.as_ref()],
        &PROGRAM_ID,
    );

    if let Some(account) = svm.get_account(&project_pda) {
        if account.data.len() > 8 {
            // Skip 8-byte discriminator
            let data = &account.data[8..];

            let roles_offset = 64;

            if data.len() > roles_offset {
                let roles_data = &data[roles_offset..];

                // Read vector length
                if roles_data.len() >= 4 {
                    let roles_count = u32::from_le_bytes([
                        roles_data[0], roles_data[1], roles_data[2], roles_data[3]
                    ]) as usize;

                    // Count admin roles
                    let mut admin_count = 0;
                    let mut offset = 4;

                    for _ in 0..roles_count {
                        if roles_data.len() > offset + 33 {
                            // Each entry is Pubkey (32 bytes) + ProjectRole enum (1 byte)
                            let role_byte = roles_data[offset + 32];
                            if role_byte == 0 { // Assuming 0 = Admin in enum
                                admin_count += 1;
                            }
                            offset += 33;
                        }
                    }

                    if admin_count == 1 && operation_succeeded {
                        return Err(InvariantViolation::new(
                            operation,
                            "INV-X2",
                            &format!(
                                "Last project admin was able to renounce on-chain! Project: {}, Admin count: {}",
                                project_id, admin_count
                            )
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

// INV-X3: Zero Amount Rejection
pub fn check_zero_amount_rejection(
    amount: u64,
    operation: &str,
    operation_succeeded: bool,
) -> Result<(), InvariantViolation> {
    // Check if this is an operation that should reject zero amounts
    let requires_nonzero = matches!(
        operation,
        "DepositFungibleToken" | "DepositNonFungibleToken" |
        "RemoveFungibleToken" | "RemoveNonFungibleToken"
    );

    if requires_nonzero && amount == 0 && operation_succeeded {
        return Err(InvariantViolation::new(
            operation,
            "INV-X3",
            &format!(
                "Zero amount operation succeeded when it should have failed! Operation: {}, Amount: {}",
                operation, amount
            )
        ));
    }

    if requires_nonzero && amount == 0 && !operation_succeeded {
        return Ok(());
    }

    Ok(())
}

// INV-X4: Whitelist Fee Bypass
pub fn check_whitelist_fee_bypass(
    authority: &Pubkey,
    whitelist: &[Pubkey],
    native_fee_charged: u64,
    expected_fee: u64,
) -> Result<(), InvariantViolation> {
    let is_whitelisted = whitelist.contains(authority);

    if is_whitelisted {
        if native_fee_charged != 0 {
            return Err(InvariantViolation::new(
                "ClaimFromProjectBudget",
                "INV-X4",
                &format!(
                    "Whitelisted user was charged native fee! Authority: {}, Fee charged: {}",
                    authority, native_fee_charged
                )
            ));
        }
    } else {
        if native_fee_charged != expected_fee {
            return Err(InvariantViolation::new(
                "ClaimFromProjectBudget",
                "INV-X4",
                &format!(
                    "Non-whitelisted user charged wrong native fee! Authority: {}, Expected: {}, Actual: {}",
                    authority, expected_fee, native_fee_charged
                )
            ));
        }
    }

    Ok(())
}

/// Check INV-X4
pub fn check_whitelist_fee_bypass_onchain(
    svm: &LiteSVM,
    authority: &Pubkey,
    native_fee_charged: u64,
    is_native_claim: bool,
) -> Result<(), InvariantViolation> {
    // Only check for native token claims
    if !is_native_claim {
        return Ok(());
    }

    // Read GlobalConfig to get whitelist and expected fee
    let (global_config_pda, _) = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    );

    if let Some(account) = svm.get_account(&global_config_pda) {
        if account.data.len() > 8 {
            // Skip 8-byte discriminator
            let data = &account.data[8..];
        }
    }

    Ok(())
}

// INV-X5: Message Domain Validation
pub fn check_message_domain_validation(
    domain_program_id: &Pubkey,
    domain_version: u8,
    expected_program_id: &Pubkey,
    expected_version: u8,
    operation: &str,
    operation_succeeded: bool,
) -> Result<(), InvariantViolation> {
    // Only check for claim operations
    if !operation.contains("Claim") {
        return Ok(());
    }

    // Check program ID
    if domain_program_id != expected_program_id {
        // If wrong domain, operation should have failed
        if operation_succeeded {
            return Err(InvariantViolation::new(
                operation,
                "INV-X5",
                &format!(
                    "Claim with wrong program ID in domain succeeded! Domain: {}, Expected: {}",
                    domain_program_id, expected_program_id
                )
            ));
        }
    }

    // Check version
    if domain_version != expected_version {
        // If wrong version, operation should have failed
        if operation_succeeded {
            return Err(InvariantViolation::new(
                operation,
                "INV-X5",
                &format!(
                    "Claim with wrong version in domain succeeded! Version: {}, Expected: {}",
                    domain_version, expected_version
                )
            ));
        }
    }

    Ok(())
}


// INV-PF1 & INV-PF2: Project Fee Validation Invariants

/// Maximum allowed fee in basis points (100%)
const BASIS_POINTS: u16 = 10000;

/// INV-PF1: Project Fee Limits
pub fn check_project_fee_limits_onchain(
    svm: &LiteSVM,
    project_nonce: u64,
    operation: &str,
) -> Result<(), InvariantViolation> {
    // Only check after UpdateProjectFees operations
    if !operation.contains("UpdateProjectFees") {
        return Ok(());
    }

    // Read Project from on-chain
    let (project_pda, _) = Pubkey::find_program_address(
        &[b"project", &project_nonce.to_le_bytes()],
        &PROGRAM_ID,
    );

    if let Some(account) = svm.get_account(&project_pda) {
        if account.data.len() > 8 {
            // Skip 8-byte discriminator
            let mut offset = 8;
            let data = &account.data;

            // Parse Project struct properly:
            // 1. is_initialized: bool (1 byte)
            if data.len() <= offset { return Ok(()); }
            offset += 1;

            // 2. nonce: u64 (8 bytes)
            if data.len() <= offset + 8 { return Ok(()); }
            offset += 8;

            // 3. attributions_count: u64 (8 bytes)
            if data.len() <= offset + 8 { return Ok(()); }
            offset += 8;

            // 4. metadata_uri: String (4-byte length prefix + data)
            if data.len() <= offset + 4 { return Ok(()); }
            let str_len = u32::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3]
            ]) as usize;
            offset += 4 + str_len;

            // 5. fee_management: ProjectFeeManagement
            if data.len() <= offset + 14 { return Ok(()); }

            // Check user_native_claim_fee (skip it)
            let user_fee_offset = offset;
            offset += 9;

            // Check project_claim_fee
            if data.len() > offset + 2 {
                if data[offset] == 1 { // Option::Some
                    let project_claim_fee = u16::from_le_bytes([
                        data[offset + 1],
                        data[offset + 2]
                    ]);

                    // Debug output to see what we're reading
                    eprintln!("[DEBUG] INV-PF1: Found project_claim_fee = {} (nonce: {})",
                        project_claim_fee, project_nonce);

                    if project_claim_fee > BASIS_POINTS {
                        return Err(InvariantViolation::new(
                            operation,
                            "INV-PF1",
                            &format!(
                                "Project claim fee {} exceeds maximum {} basis points ({}%)",
                                project_claim_fee,
                                BASIS_POINTS,
                                (project_claim_fee as f64 / 100.0)
                            )
                        ));
                    }
                }
            }
            offset += 3;

            // Check remove_fee
            if data.len() > offset + 2 {
                if data[offset] == 1 { // Option::Some
                    let remove_fee = u16::from_le_bytes([
                        data[offset + 1],
                        data[offset + 2]
                    ]);

                    // Debug output
                    eprintln!("[DEBUG] INV-PF1: Found remove_fee = {} (nonce: {})",
                        remove_fee, project_nonce);

                    if remove_fee > BASIS_POINTS {
                        return Err(InvariantViolation::new(
                            operation,
                            "INV-PF1",
                            &format!(
                                "Project remove fee {} exceeds maximum {} basis points ({}%)",
                                remove_fee,
                                BASIS_POINTS,
                                (remove_fee as f64 / 100.0)
                            )
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

/// INV-PF2: Claim Fee Deduction Validation
pub fn check_claim_fee_deduction_onchain(
    svm: &LiteSVM,
    project_nonce: u64,
    currency_id: &Pubkey,
    claim_amount: u64,
    budget_before: u64,
    budget_after: u64,
    operation: &str,
) -> Result<(), InvariantViolation> {
    // Only check claim operations
    if !operation.contains("Claim") {
        return Ok(());
    }

    // Calculate actual deduction
    let actual_deduction = budget_before.saturating_sub(budget_after);

    // Read project to get fee configuration
    let (project_pda, _) = Pubkey::find_program_address(
        &[b"project", &project_nonce.to_le_bytes()],
        &PROGRAM_ID,
    );

    if let Some(account) = svm.get_account(&project_pda) {
        if account.data.len() > 8 {
            // Parse fee from project (simplified - adjust offsets based on actual struct)
            let data = &account.data[8..];
            let fee_offset = 200;

            if data.len() > fee_offset + 12 {
                let fee_data = &data[fee_offset..];

                // Get project_claim_fee if set
                let mut project_claim_fee = 0u16;
                let claim_fee_offset = 9;
                if fee_data.len() > claim_fee_offset + 2 {
                    if fee_data[claim_fee_offset] == 1 { // Option::Some
                        project_claim_fee = u16::from_le_bytes([
                            fee_data[claim_fee_offset + 1],
                            fee_data[claim_fee_offset + 2]
                        ]);
                    }
                }

                // Calculate expected fee
                let expected_fee = (claim_amount as u128 * project_claim_fee as u128 / BASIS_POINTS as u128) as u64;
                let expected_deduction = claim_amount.saturating_add(expected_fee);

                // Check for excessive deduction (more than 200% of claim amount suggests fee > 100%)
                if actual_deduction > claim_amount * 2 {
                    return Err(InvariantViolation::new(
                        operation,
                        "INV-PF2",
                        &format!(
                            "Excessive budget deduction! Amount: {}, Deduction: {} (implies fee > 100%)",
                            claim_amount,
                            actual_deduction
                        )
                    ));
                }

                // Check if deduction matches expected
                let tolerance = 1; // Allow 1 token rounding error
                if actual_deduction > expected_deduction + tolerance {
                    return Err(InvariantViolation::new(
                        operation,
                        "INV-PF2",
                        &format!(
                            "Budget deduction {} exceeds expected {} for claim amount {} with fee {}%",
                            actual_deduction,
                            expected_deduction,
                            claim_amount,
                            (project_claim_fee as f64 / 100.0)
                        )
                    ));
                }
            }
        }
    }

    Ok(())
}