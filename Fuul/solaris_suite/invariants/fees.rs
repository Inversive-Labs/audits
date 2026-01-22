use crate::targets::full_svm::state::FullSvmState;
use crate::targets::full_svm::PROGRAM_ID;
use super::types::InvariantViolation;
use super::balance::read_on_chain_budget;
use litesvm::LiteSVM;
use solana_sdk::pubkey::Pubkey;
use borsh::BorshDeserialize;

/// Maximum valid value for basis points (100% = 10000 BP)
pub const MAX_BASIS_POINTS: u16 = 10000;

// ============================================================================
// On-Chain Data Structures (matching Fuul program exactly)
// ============================================================================

/// GlobalConfig structure matching on-chain layout
#[derive(BorshDeserialize, Debug)]
pub struct GlobalConfigOnChain {
    pub is_initialized: bool,
    pub paused: bool,
    pub project_nonce: u64,
    pub claim_cool_down: u64,
    pub required_signers_for_claim: u8,
    pub fee_management: FeeManagementOnChain,
    pub roles_mapping: GlobalRolesMappingOnChain,
}

/// FeeManagement structure matching on-chain layout
#[derive(BorshDeserialize, Debug)]
pub struct FeeManagementOnChain {
    pub fee_collector: Pubkey,
    pub no_claim_fee_whitelist: Vec<Pubkey>,
    pub user_native_claim_fee: u64,
    pub project_claim_fee: u16,
    pub remove_fee: u16,
}

/// GlobalRolesMapping structure (minimal for deserialization)
#[derive(BorshDeserialize, Debug)]
pub struct GlobalRolesMappingOnChain {
    pub roles: Vec<GlobalRoleEntryOnChain>,
}

#[derive(BorshDeserialize, Debug)]
pub struct GlobalRoleEntryOnChain {
    pub account: Pubkey,
    pub role: u8, // Enum represented as u8
}

/// Project structure matching on-chain layout
#[derive(BorshDeserialize, Debug)]
pub struct ProjectOnChain {
    pub is_initialized: bool,
    pub nonce: u64,
    pub attributions_count: u64,
    pub metadata_uri: String,
    pub fee_management: ProjectFeeManagementOnChain,
    pub roles_mapping: ProjectRolesMappingOnChain,
}

/// ProjectFeeManagement structure matching on-chain layout
#[derive(BorshDeserialize, Debug)]
pub struct ProjectFeeManagementOnChain {
    pub user_native_claim_fee: Option<u64>,
    pub project_claim_fee: Option<u16>,
    pub remove_fee: Option<u16>,
}

/// ProjectRolesMapping structure (minimal for deserialization)
#[derive(BorshDeserialize, Debug)]
pub struct ProjectRolesMappingOnChain {
    pub roles: Vec<ProjectRoleEntryOnChain>,
}

#[derive(BorshDeserialize, Debug)]
pub struct ProjectRoleEntryOnChain {
    pub account: Pubkey,
    pub role: u8, // Enum represented as u8
}

// ============================================================================
// Helper Functions for Reading On-Chain State
// ============================================================================

/// Helper: Read GlobalConfig
pub fn read_global_config_from_chain(svm: &LiteSVM) -> Result<GlobalConfigOnChain, String> {
    // GlobalConfig PDA uses seeds: ["global-config"]
    let (global_config_pda, _) = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    );

    crate::debug_log!("Reading GlobalConfig from PDA: {}", global_config_pda);

    let account = svm.get_account(&global_config_pda)
        .ok_or_else(|| format!("GlobalConfig account not found at {}", global_config_pda))?;

    // Skip 8-byte Anchor discriminator
    if account.data.len() < 8 {
        return Err("GlobalConfig account data too small".to_string());
    }
    let data = &account.data[8..];

    let mut slice = data;
    let is_initialized = bool::deserialize(&mut slice).map_err(|e| e.to_string())?;
    let paused = bool::deserialize(&mut slice).map_err(|e| e.to_string())?;
    let project_nonce = u64::deserialize(&mut slice).map_err(|e| e.to_string())?;
    let claim_cool_down = u64::deserialize(&mut slice).map_err(|e| e.to_string())?;
    let required_signers_for_claim = u8::deserialize(&mut slice).map_err(|e| e.to_string())?;
    let fee_collector = Pubkey::deserialize(&mut slice).map_err(|e| e.to_string())?;

    // Read whitelist Vec length and skip the entries
    let whitelist_len = u32::deserialize(&mut slice).map_err(|e| e.to_string())? as usize;
    // Skip whitelist entries (each is a Pubkey = 32 bytes)
    if slice.len() < whitelist_len * 32 {
        return Err("Not enough data for whitelist entries".to_string());
    }
    slice = &slice[whitelist_len * 32..];

    let user_native_claim_fee = u64::deserialize(&mut slice).map_err(|e| e.to_string())?;
    let project_claim_fee = u16::deserialize(&mut slice).map_err(|e| e.to_string())?;
    let remove_fee = u16::deserialize(&mut slice).map_err(|e| e.to_string())?;

    Ok(GlobalConfigOnChain {
        is_initialized,
        paused,
        project_nonce,
        claim_cool_down,
        required_signers_for_claim,
        fee_management: FeeManagementOnChain {
            fee_collector,
            no_claim_fee_whitelist: vec![],
            user_native_claim_fee,
            project_claim_fee,
            remove_fee,
        },
        roles_mapping: GlobalRolesMappingOnChain {
            roles: vec![],
        },
    })
}

/// Helper: Read Project
pub fn read_project_from_chain(svm: &LiteSVM, project_id: &Pubkey) -> Result<ProjectOnChain, String> {
    crate::debug_log!("Reading Project from account: {}", project_id);

    let account = svm.get_account(project_id)
        .ok_or_else(|| format!("Project account {} not found on chain", project_id))?;

    let data = &account.data;

    // Project struct layout (from actual protocol):
    // discriminator(8) + is_initialized(1) + nonce(8) + attributions_count(8) + uri_len(4) = 29 minimum
    if data.len() < 29 {
        crate::debug_err!("Project account data too small: {} bytes", data.len());
        return Ok(ProjectOnChain {
            is_initialized: true,
            nonce: 0,
            attributions_count: 0,
            metadata_uri: String::new(),
            fee_management: ProjectFeeManagementOnChain {
                user_native_claim_fee: None,
                project_claim_fee: None,
                remove_fee: None,
            },
            roles_mapping: ProjectRolesMappingOnChain {
                roles: vec![],
            },
        });
    }

    let mut offset = 8; // Skip 8-byte Anchor discriminator

    // Read is_initialized at offset 8
    let is_initialized = data[offset] != 0;
    offset += 1;

    // Read nonce at offset 9 (little-endian u64)
    let nonce = u64::from_le_bytes([
        data[offset], data[offset+1], data[offset+2], data[offset+3],
        data[offset+4], data[offset+5], data[offset+6], data[offset+7]
    ]);
    offset += 8;

    // Read attributions_count at offset 17 (little-endian u64)
    let attributions_count = u64::from_le_bytes([
        data[offset], data[offset+1], data[offset+2], data[offset+3],
        data[offset+4], data[offset+5], data[offset+6], data[offset+7]
    ]);
    offset += 8;

    // Read metadata_uri length at offset 25 (little-endian u32)
    let uri_len = u32::from_le_bytes([
        data[offset], data[offset+1], data[offset+2], data[offset+3]
    ]) as usize;
    offset += 4;

    // Skip the metadata_uri bytes
    offset += uri_len;

    let mut user_native_claim_fee = None;
    let mut project_claim_fee = None;
    let mut remove_fee = None;

    // Check if we have enough data for fee fields
    if offset + 3 <= data.len() {
        // Read user_native_claim_fee (Option<u64>)
        if offset < data.len() {
            let has_value = data[offset] != 0;
            offset += 1;
            if has_value && offset + 8 <= data.len() {
                user_native_claim_fee = Some(u64::from_le_bytes([
                    data[offset], data[offset+1], data[offset+2], data[offset+3],
                    data[offset+4], data[offset+5], data[offset+6], data[offset+7]
                ]));
                offset += 8;
            }
        }

        // Read project_claim_fee (Option<u16>)
        if offset < data.len() {
            let has_value = data[offset] != 0;
            offset += 1;
            if has_value && offset + 2 <= data.len() {
                project_claim_fee = Some(u16::from_le_bytes([
                    data[offset], data[offset+1]
                ]));
                offset += 2;
            }
        }

        // Read remove_fee (Option<u16>)
        if offset < data.len() {
            let has_value = data[offset] != 0;
            offset += 1;
            if has_value && offset + 2 <= data.len() {
                remove_fee = Some(u16::from_le_bytes([
                    data[offset], data[offset+1]
                ]));
            }
        }
    } else {
        crate::debug_log!("Not enough data for fee fields at offset {}, data len: {}", offset, data.len());
    }

    Ok(ProjectOnChain {
        is_initialized,
        nonce,
        attributions_count,
        metadata_uri: String::new(),
        fee_management: ProjectFeeManagementOnChain {
            user_native_claim_fee,
            project_claim_fee,
            remove_fee,
        },
        roles_mapping: ProjectRolesMappingOnChain {
            roles: vec![],
        },
    })
}

// ============================================================================
// INV-F1: Fee Basis Points Range (WITH ON-CHAIN VERIFICATION)
// ============================================================================

/// INV-F1: Fee Basis Points Range
pub fn check_fee_bp_range(
    state: &FullSvmState,
    context: &str,
) -> Result<(), InvariantViolation> {
    // Check global config fees
    let global_project_fee = state.global_config.fee_management.project_claim_fee;
    if global_project_fee > MAX_BASIS_POINTS {
        return Err(InvariantViolation::new(
            context,
            "INV-F1",
            &format!(
                "CRITICAL: Global project_claim_fee exceeds maximum!\n\
                \n\
                Fee Value: {} BP\n\
                Maximum Allowed: {} BP (100%)\n\
                Percentage: {:.2}%\n\
                \n\
                A fee > 10000 BP (100%) is invalid and could:\n\
                - Cause overflow in fee calculations\n\
                - Charge more than the claim amount\n\
                - Drain project budgets unexpectedly",
                global_project_fee,
                MAX_BASIS_POINTS,
                global_project_fee as f64 / 100.0
            )
        ));
    }

    let global_remove_fee = state.global_config.fee_management.remove_fee;
    if global_remove_fee > MAX_BASIS_POINTS {
        return Err(InvariantViolation::new(
            context,
            "INV-F1",
            &format!(
                "CRITICAL: Global remove_fee exceeds maximum!\n\
                \n\
                Fee Value: {} BP\n\
                Maximum Allowed: {} BP (100%)\n\
                Percentage: {:.2}%\n\
                \n\
                A fee > 10000 BP (100%) is invalid and could:\n\
                - Cause overflow in fee calculations\n\
                - Charge more than the removal amount\n\
                - Result in negative amounts after fee deduction",
                global_remove_fee,
                MAX_BASIS_POINTS,
                global_remove_fee as f64 / 100.0
            )
        ));
    }

    // Check project-specific fees
    for (index, project) in state.projects.iter().enumerate() {
        if let Some(project_fee) = project.fee_management.project_claim_fee {
            if project_fee > MAX_BASIS_POINTS {
                return Err(InvariantViolation::new(
                    context,
                    "INV-F1",
                    &format!(
                        "CRITICAL: Project {} project_claim_fee exceeds maximum!\n\
                        \n\
                        Project Index: {}\n\
                        Project ID: {}\n\
                        Fee Value: {} BP\n\
                        Maximum Allowed: {} BP (100%)\n\
                        Percentage: {:.2}%\n\
                        \n\
                        A fee > 10000 BP (100%) is invalid and could:\n\
                        - Cause overflow in fee calculations\n\
                        - Charge more than the claim amount\n\
                        - Drain project budgets unexpectedly",
                        index,
                        index,
                        project.project_id,
                        project_fee,
                        MAX_BASIS_POINTS,
                        project_fee as f64 / 100.0
                    )
                ));
            }
        }

        if let Some(remove_fee) = project.fee_management.remove_fee {
            if remove_fee > MAX_BASIS_POINTS {
                return Err(InvariantViolation::new(
                    context,
                    "INV-F1",
                    &format!(
                        "CRITICAL: Project {} remove_fee exceeds maximum!\n\
                        \n\
                        Project Index: {}\n\
                        Project ID: {}\n\
                        Fee Value: {} BP\n\
                        Maximum Allowed: {} BP (100%)\n\
                        Percentage: {:.2}%\n\
                        \n\
                        A fee > 10000 BP (100%) is invalid and could:\n\
                        - Cause overflow in fee calculations\n\
                        - Charge more than the removal amount\n\
                        - Result in negative amounts after fee deduction",
                        index,
                        index,
                        project.project_id,
                        remove_fee,
                        MAX_BASIS_POINTS,
                        remove_fee as f64 / 100.0
                    )
                ));
            }
        }
    }

    crate::debug_log!(
        "INV-F1 All fee basis points within valid range (global: project={}bp, remove={}bp)",
        global_project_fee,
        global_remove_fee
    );

    Ok(())
}

/// INV-F1 Convenience: Check Fee Range After Global Config Update
pub fn check_fee_range_after_global_update(
    state: &FullSvmState,
) -> Result<(), InvariantViolation> {
    check_fee_bp_range(state, "UpdateGlobalConfigFees")
}

/// INV-F1 Convenience: Check Fee Range After Project Fees Update
pub fn check_fee_range_after_project_update(
    state: &FullSvmState,
) -> Result<(), InvariantViolation> {
    check_fee_bp_range(state, "UpdateProjectFees")
}

/// INV-F1: Fee Basis Points Range
pub fn check_fee_bp_range_on_chain(
    svm: &LiteSVM,
    context: &str,
    projects: &[Pubkey],
) -> Result<(), InvariantViolation> {
    // First check GlobalConfig fees from chain
    match read_global_config_from_chain(svm) {
        Ok(config) => {
            // Check global project_claim_fee
            if config.fee_management.project_claim_fee > MAX_BASIS_POINTS {
                return Err(InvariantViolation::new(
                    context,
                    "INV-F1-ONCHAIN",
                    &format!(
                        "CRITICAL: On-chain GlobalConfig project_claim_fee exceeds maximum!\n\
                        \n\
                        Fee Value ON-CHAIN: {} BP\n\
                        Maximum Allowed: {} BP (100%)\n\
                        Percentage: {:.2}%\n\
                        \n\
                        The ON-CHAIN state has an invalid fee that would:\n\
                        - Cause overflow in fee calculations\n\
                        - Charge more than the claim amount\n\
                        - Drain project budgets unexpectedly\n\
                        \n\
                        This indicates the program accepted an invalid fee update!",
                        config.fee_management.project_claim_fee,
                        MAX_BASIS_POINTS,
                        config.fee_management.project_claim_fee as f64 / 100.0
                    )
                ));
            }

            // Check global remove_fee
            if config.fee_management.remove_fee > MAX_BASIS_POINTS {
                return Err(InvariantViolation::new(
                    context,
                    "INV-F1-ONCHAIN",
                    &format!(
                        "CRITICAL: On-chain GlobalConfig remove_fee exceeds maximum!\n\
                        \n\
                        Fee Value ON-CHAIN: {} BP\n\
                        Maximum Allowed: {} BP (100%)\n\
                        Percentage: {:.2}%",
                        config.fee_management.remove_fee,
                        MAX_BASIS_POINTS,
                        config.fee_management.remove_fee as f64 / 100.0
                    )
                ));
            }

            crate::debug_log!(
                "INV-F1 On-chain GlobalConfig fees valid: project_claim={} BP, remove={} BP",
                config.fee_management.project_claim_fee,
                config.fee_management.remove_fee
            );
        }
        Err(e) => {
            crate::debug_log!("INV-F1 Could not read GlobalConfig from chain: {}", e);
        }
    }

    // Check each project's fees from chain
    for project_id in projects {
        match read_project_from_chain(svm, project_id) {
            Ok(project) => {
                // Check project_claim_fee if set
                if let Some(project_fee) = project.fee_management.project_claim_fee {
                    if project_fee > MAX_BASIS_POINTS {
                        return Err(InvariantViolation::new(
                            context,
                            "INV-F1-ONCHAIN",
                            &format!(
                                "CRITICAL: On-chain Project {} project_claim_fee exceeds maximum!\n\
                                \n\
                                Fee Value ON-CHAIN: {} BP\n\
                                Maximum Allowed: {} BP (100%)\n\
                                Percentage: {:.2}%\n\
                                \n\
                                The program accepted an invalid project fee override!",
                                project_id,
                                project_fee,
                                MAX_BASIS_POINTS,
                                project_fee as f64 / 100.0
                            )
                        ));
                    }
                }

                // Check remove_fee if set
                if let Some(remove_fee) = project.fee_management.remove_fee {
                    if remove_fee > MAX_BASIS_POINTS {
                        return Err(InvariantViolation::new(
                            context,
                            "INV-F1-ONCHAIN",
                            &format!(
                                "CRITICAL: On-chain Project {} remove_fee exceeds maximum!\n\
                                \n\
                                Fee Value ON-CHAIN: {} BP\n\
                                Maximum Allowed: {} BP (100%)\n\
                                Percentage: {:.2}%",
                                project_id,
                                remove_fee,
                                MAX_BASIS_POINTS,
                                remove_fee as f64 / 100.0
                            )
                        ));
                    }
                }

                crate::debug_log!(
                    "INV-F1 On-chain Project {} fees valid",
                    project_id
                );
            }
            Err(e) => {
                crate::debug_log!(
                    "INV-F1 Could not read Project {} from chain: {}",
                    project_id, e
                );
            }
        }
    }

    Ok(())
}

// ============================================================================
// INV-F2: Fee Calculation Correctness
// ============================================================================

/// INV-F2: Fee Calculation Correctness
pub fn check_fee_calculation(
    amount: u64,
    fee_bp: u16,
    calculated_fee: u64,
    context: &str,
) -> Result<(), InvariantViolation> {
    // STEP 1: Calculate the expected fee using u128 to avoid overflow
    let expected_fee = ((amount as u128) * (fee_bp as u128) / 10000) as u64;

    // STEP 2: Verify the calculated fee matches expected
    if calculated_fee != expected_fee {
        return Err(InvariantViolation::new(
            context,
            "INV-F2",
            &format!(
                "CRITICAL: Fee calculation is incorrect!\n\
                \n\
                Amount: {}\n\
                Fee BP: {} ({:.2}%)\n\
                Calculated Fee: {}\n\
                Expected Fee: {}\n\
                Difference: {}\n\
                \n\
                Formula: fee = (amount * fee_bp) / 10000\n\
                Expected: ({} * {}) / 10000 = {}\n\
                \n\
                This could cause:\n\
                - Incorrect charges to users/projects\n\
                - Budget accounting errors\n\
                - Fee collector receiving wrong amounts",
                amount,
                fee_bp,
                fee_bp as f64 / 100.0,
                calculated_fee,
                expected_fee,
                (calculated_fee as i128) - (expected_fee as i128),
                amount,
                fee_bp,
                expected_fee
            )
        ));
    }

    // STEP 3: Verify fee never exceeds amount
    if calculated_fee > amount {
        return Err(InvariantViolation::new(
            context,
            "INV-F2",
            &format!(
                "CRITICAL: Fee exceeds claim amount!\n\
                \n\
                Amount: {}\n\
                Fee BP: {} ({:.2}%)\n\
                Calculated Fee: {}\n\
                Excess: {}\n\
                \n\
                A fee should NEVER exceed the amount being claimed.\n\
                This would cause underflow when calculating net amount.\n\
                \n\
                Possible causes:\n\
                - fee_bp > 10000 (should be caught by INV-F1)\n\
                - Calculation overflow\n\
                - Logic error in fee calculation",
                amount,
                fee_bp,
                fee_bp as f64 / 100.0,
                calculated_fee,
                calculated_fee - amount
            )
        ));
    }

    crate::debug_log!(
        "INV-F2 Fee calculation correct: ({} * {}) / 10000 = {}",
        amount, fee_bp, calculated_fee
    );

    Ok(())
}

/// INV-F2 Convenience: Check Fee Calculation After Claim
pub fn check_fee_calculation_after_claim(
    amount: u64,
    fee_bp: u16,
    calculated_fee: u64,
) -> Result<(), InvariantViolation> {
    check_fee_calculation(amount, fee_bp, calculated_fee, "Claim")
}

/// Helper: Calculate Expected Fee
pub fn calculate_expected_fee(amount: u64, fee_bp: u16) -> u64 {
    ((amount as u128) * (fee_bp as u128) / 10000) as u64
}

// ============================================================================
// INV-F4: Project Fee Comes from Budget
// ============================================================================

/// INV-F4: Project Fee Comes from Budget
pub fn check_project_fee_source(
    budget_before: u64,
    budget_after: u64,
    recipient_amount: u64,
    project_fee: u64,
    context: &str,
) -> Result<(), InvariantViolation> {
    // Calculate actual budget decrease
    let budget_decrease = budget_before.saturating_sub(budget_after);
    
    // Expected decrease = recipient amount + project fee
    let expected_decrease = recipient_amount.saturating_add(project_fee);

    if budget_decrease != expected_decrease {
        return Err(InvariantViolation::new(
            context,
            "INV-F4",
            &format!(
                "CRITICAL: Project fee accounting mismatch!\n\
                \n\
                Budget Before: {}\n\
                Budget After: {}\n\
                Budget Decrease: {}\n\
                \n\
                Recipient Amount: {}\n\
                Project Fee: {}\n\
                Expected Decrease: {} (amount + fee)\n\
                \n\
                Difference: {}\n\
                \n\
                The budget should decrease by EXACTLY (recipient_amount + project_fee).\n\
                This ensures:\n\
                - Recipient receives full claim amount\n\
                - Fee comes from project budget, not recipient\n\
                - Conservation of funds is maintained",
                budget_before,
                budget_after,
                budget_decrease,
                recipient_amount,
                project_fee,
                expected_decrease,
                (budget_decrease as i128) - (expected_decrease as i128)
            )
        ));
    }

    crate::debug_log!(
        "INV-F4 Fee source correct: budget decreased by {} = {} (amount) + {} (fee)",
        budget_decrease, recipient_amount, project_fee
    );

    Ok(())
}

/// INV-F4 Convenience: Check Project Fee Source After Claim
pub fn check_project_fee_source_after_claim(
    budget_before: u64,
    budget_after: u64,
    recipient_amount: u64,
    project_fee: u64,
) -> Result<(), InvariantViolation> {
    check_project_fee_source(budget_before, budget_after, recipient_amount, project_fee, "Claim")
}

/// INV-F4: Project Fee from Budget
pub fn check_project_fee_source_on_chain(
    svm: &LiteSVM,
    project_id: &Pubkey,
    currency_id: &Pubkey,
    budget_before_onchain: u64,
    recipient_amount: u64,
    project_fee: u64,
    context: &str,
) -> Result<(), InvariantViolation> {
    // Read the current on-chain budget AFTER the transaction
    let (_, _, budget_after_onchain) = read_on_chain_budget(svm, project_id, currency_id)
        .map_err(|e| InvariantViolation::new(
            context,
            "INV-F4-ONCHAIN",
            &format!("Could not read budget from chain: {}", e)
        ))?;

    // Calculate expected decrease
    let expected_decrease = recipient_amount.saturating_add(project_fee);
    let actual_decrease = budget_before_onchain.saturating_sub(budget_after_onchain);

    // Verify the budget decreased by exactly (amount + fee)
    if actual_decrease != expected_decrease {
        return Err(InvariantViolation::new(
            context,
            "INV-F4-ONCHAIN",
            &format!(
                "CRITICAL: On-chain budget decrease doesn't match expected!\n\
                \n\
                Project: {} / Currency: {}\n\
                \n\
                Budget Before (ON-CHAIN): {}\n\
                Budget After (ON-CHAIN):  {}\n\
                Actual Decrease:          {}\n\
                \n\
                Expected Decrease: {} (amount) + {} (fee) = {}\n\
                \n\
                Difference: {} (actual) - {} (expected) = {}\n\
                \n\
                This indicates the ON-CHAIN program:\n\
                - Deducted the wrong amount from the budget\n\
                - Applied fees incorrectly\n\
                - Has an accounting bug in budget updates",
                project_id,
                currency_id,
                budget_before_onchain,
                budget_after_onchain,
                actual_decrease,
                recipient_amount,
                project_fee,
                expected_decrease,
                actual_decrease,
                expected_decrease,
                actual_decrease as i64 - expected_decrease as i64
            )
        ));
    }

    // Additional check: ensure budget didn't increase (sanity check)
    if budget_after_onchain > budget_before_onchain {
        return Err(InvariantViolation::new(
            context,
            "INV-F4-ONCHAIN",
            &format!(
                "CRITICAL: Budget INCREASED during claim!\n\
                \n\
                Budget Before (ON-CHAIN): {}\n\
                Budget After (ON-CHAIN):  {}\n\
                Increase: {}\n\
                \n\
                This should NEVER happen - claims reduce budgets!",
                budget_before_onchain,
                budget_after_onchain,
                budget_after_onchain - budget_before_onchain
            )
        ));
    }

    crate::debug_log!(
        "INV-F4 On-chain budget correctly decreased by {} + {} = {}",
        recipient_amount, project_fee, expected_decrease
    );

    Ok(())
}
