use crate::targets::full_svm::state::FullSvmState;
use crate::targets::full_svm::PROGRAM_ID;
use super::types::InvariantViolation;
use solana_sdk::pubkey::Pubkey;
use litesvm::LiteSVM;

// ============================================================================
// Helper Functions for Reading On-Chain State
// ============================================================================

/// Helper: Read Project Nonce from GlobalConfig
/// Account Structure
/// The GlobalConfig account in the Fuul program has this structure:
/// ```
/// Offset | Size | Field
/// -------|------|------------------
/// 0      | 8    | discriminator (Anchor)
/// 8      | 1    | is_initialized (bool)
/// 9      | 1    | paused (bool)
/// 10     | 8    | project_nonce (u64)  ← We read this
/// 18     | 8    | claim_cool_down (u64)
/// 26     | 1    | required_signers_for_claim (u8)
/// ...    | ...  | fee_management, roles_mapping (complex)
/// ```

pub fn read_on_chain_project_nonce(svm: &LiteSVM) -> Result<u64, String> {
    // Derive the GlobalConfig PDA
    let (global_config_pda, _bump) = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    );

    // Read the account from LiteSVM
    let account = svm.get_account(&global_config_pda)
        .ok_or_else(|| {
            format!(
                "GlobalConfig account not found at PDA: {}",
                global_config_pda
            )
        })?;

    // Verify the account has the expected minimum size
    // 8 (discriminator) + 1 (is_initialized) + 1 (paused) + 8 (project_nonce) = 18 bytes minimum
    if account.data.len() < 18 {
        return Err(format!(
            "GlobalConfig account data too short: {} bytes (expected at least 18)",
            account.data.len()
        ));
    }

    // Read project_nonce at offset 10 (after discriminator + is_initialized + paused)
    let project_nonce = u64::from_le_bytes(
        account.data[10..18]
            .try_into()
            .map_err(|_| "Failed to read project_nonce from bytes 10-18".to_string())?
    );

    Ok(project_nonce)
}

// ============================================================================
// INV-C1: Project Nonce Monotonicity
// ============================================================================

/// INV-C1: Project Nonce Monotonicity
pub fn check_project_nonce_monotonicity(
    state: &FullSvmState,
    svm: &LiteSVM,
    operation: &str,
    before_nonce: u64,
    is_create_project: bool,
) -> Result<(), InvariantViolation> {
    // STEP 1: Validate internal state tracking
    let after_nonce = state.global_config.project_nonce;

    if is_create_project {
        // For CreateProject: nonce must increase by exactly 1
        let expected_nonce = before_nonce.saturating_add(1);
        
        if after_nonce != expected_nonce {
            return Err(InvariantViolation::new(
                operation,
                "INV-C1",
                &format!(
                    "CRITICAL: Project nonce did not increase by exactly 1 after CreateProject!\n\
                    \n\
                    Nonce Before: {}\n\
                    Nonce After: {}\n\
                    Expected: {}\n\
                    \n\
                    This could cause:\n\
                    - Project PDA collisions (if nonce didn't increase)\n\
                    - Gaps in project numbering (if nonce increased by more than 1)\n\
                    - Overwriting existing projects (if nonce decreased)",
                    before_nonce,
                    after_nonce,
                    expected_nonce
                )
            ));
        }
    } else {
        // For all other operations: nonce must remain unchanged
        if after_nonce != before_nonce {
            return Err(InvariantViolation::new(
                operation,
                "INV-C1",
                &format!(
                    "CRITICAL: Project nonce changed during non-CreateProject operation!\n\
                    \n\
                    Operation: {}\n\
                    Nonce Before: {}\n\
                    Nonce After: {}\n\
                    \n\
                    The project nonce should ONLY change during CreateProject operations.\n\
                    This indicates a serious bug in state tracking or the program itself.",
                    operation,
                    before_nonce,
                    after_nonce
                )
            ));
        }
    }

    // STEP 2: Verify state matches tracking
    match read_on_chain_project_nonce(svm) {
        Ok(onchain_nonce) => {
            if after_nonce != onchain_nonce {
                return Err(InvariantViolation::new(
                    operation,
                    "INV-C1-SYNC",
                    &format!(
                        "CRITICAL: Project nonce desync detected!\n\
                        \n\
                        Operation: {}\n\
                        Our internal tracking: {}\n\
                        On-chain real value: {}\n\
                        Difference: {}\n\
                        \n\
                        This means our fuzzer's nonce tracking is NOT synchronized with\n\
                        the actual on-chain state in LiteSVM.",
                        operation,
                        after_nonce,
                        onchain_nonce,
                        (after_nonce as i64) - (onchain_nonce as i64)
                    )
                ));
            }

            crate::debug_log!(
                "INV-C1 Project nonce validated: {} -> {} (on-chain: {})",
                before_nonce, after_nonce, onchain_nonce
            );
        },
        Err(e) => {
            // GlobalConfig should always exist after initialization
            return Err(InvariantViolation::new(
                operation,
                "INV-C1-ONCHAIN",
                &format!(
                    "Failed to read GlobalConfig from on-chain!\n\
                    Operation: {}\n\
                    Error: {}\n\
                    \n\
                    GlobalConfig should always exist after program initialization.",
                    operation, e
                )
            ));
        }
    }

    crate::debug_log!(
        "INV-C1 Nonce monotonicity validated: {} -> {} (is_create: {})",
        before_nonce, after_nonce, is_create_project
    );

    Ok(())
}

/// INV-C1 Simplified: Check Nonce After CreateProject
pub fn check_nonce_after_create_project(
    state: &FullSvmState,
    svm: &LiteSVM,
    before_nonce: u64,
) -> Result<(), InvariantViolation> {
    check_project_nonce_monotonicity(state, svm, "CreateProject", before_nonce, true)
}

/// INV-C1 Simplified: Check Nonce Unchanged
pub fn check_nonce_unchanged(
    state: &FullSvmState,
    svm: &LiteSVM,
    operation: &str,
    before_nonce: u64,
) -> Result<(), InvariantViolation> {
    check_project_nonce_monotonicity(state, svm, operation, before_nonce, false)
}

// ============================================================================
// INV-C2: Attributions Count Monotonicity
// ============================================================================

/// Helper: Read Attributions Count from Project
/// Account Structure
/// The Project account has this structure:
/// ```
/// Offset | Size | Field
/// -------|------|------------------
/// 0      | 8    | discriminator (Anchor)
/// 8      | 1    | is_initialized (bool)
/// 9      | 8    | nonce (u64)
/// 17     | 8    | attributions_count (u64)  ← We read this
/// 25     | 4+n  | metadata_uri (String - variable length)
/// ...    | ...  | fee_management, roles_mapping (complex)
/// ```
pub fn read_on_chain_attributions_count(
    svm: &LiteSVM,
    project_nonce: u64,
) -> Result<u64, String> {
    // Derive the Project PDA using the nonce
    let (project_pda, _bump) = Pubkey::find_program_address(
        &[b"project", &project_nonce.to_le_bytes()],
        &PROGRAM_ID,
    );

    // Read the account from LiteSVM
    let account = svm.get_account(&project_pda)
        .ok_or_else(|| {
            format!(
                "Project account not found at PDA: {} (nonce: {})",
                project_pda, project_nonce
            )
        })?;

    // Verify the account has the expected minimum size
    // 8 (discriminator) + 1 (is_initialized) + 8 (nonce) + 8 (attributions_count) = 25 bytes minimum
    if account.data.len() < 25 {
        return Err(format!(
            "Project account data too short: {} bytes (expected at least 25)",
            account.data.len()
        ));
    }

    // Read attributions_count at offset 17
    // Offset calculation: 8 (discriminator) + 1 (is_initialized) + 8 (nonce) = 17
    let attributions_count = u64::from_le_bytes(
        account.data[17..25]
            .try_into()
            .map_err(|_| "Failed to read attributions_count from bytes 17-25".to_string())?
    );

    Ok(attributions_count)
}

/// INV-C2: Attributions Count Monotonicity
pub fn check_attributions_count_monotonicity(
    state: &FullSvmState,
    svm: &LiteSVM,
    project_index: usize,
    before_count: u64,
) -> Result<(), InvariantViolation> {
    // Get the project from state
    let project = state.projects.get(project_index)
        .ok_or_else(|| InvariantViolation::new(
            "Claim",
            "INV-C2",
            &format!("Project at index {} not found in state", project_index)
        ))?;

    let after_count = project.attributions_count;
    let expected_count = before_count.saturating_add(1);

    // STEP 1: Validate internal state tracking
    if after_count != expected_count {
        return Err(InvariantViolation::new(
            "Claim",
            "INV-C2",
            &format!(
                "CRITICAL: Attributions count did not increase by exactly 1 after Claim!\n\
                \n\
                Project: {} (index: {})\n\
                Project Nonce: {}\n\
                Count Before: {}\n\
                Count After: {}\n\
                Expected: {}\n\
                \n\
                This could cause:\n\
                - Replay attacks (if count didn't increase, same attribution nonce could be reused)\n\
                - Gaps in attribution numbering (if count increased by more than 1)\n\
                - Overwriting existing attributions (if count decreased)",
                project.project_id,
                project_index,
                project.nonce,
                before_count,
                after_count,
                expected_count
            )
        ));
    }

    // STEP 2: Verify on-chain state matches our tracking
    match read_on_chain_attributions_count(svm, project.nonce) {
        Ok(onchain_count) => {
            if after_count != onchain_count {
                return Err(InvariantViolation::new(
                    "Claim",
                    "INV-C2-SYNC",
                    &format!(
                        "CRITICAL: Attributions count desync detected!\n\
                        \n\
                        Project: {} (nonce: {})\n\
                        Our internal tracking: {}\n\
                        On-chain real value: {}\n\
                        Difference: {}\n\
                        \n\
                        This means our fuzzer's attributions_count tracking is NOT synchronized with\n\
                        the actual on-chain state in LiteSVM.",
                        project.project_id,
                        project.nonce,
                        after_count,
                        onchain_count,
                        (after_count as i64) - (onchain_count as i64)
                    )
                ));
            }

            crate::debug_log!(
                "INV-C2 Attributions count validated for project {}: {} -> {} (on-chain: {})",
                project.project_id, before_count, after_count, onchain_count
            );
        },
        Err(e) => {
            // Project should exist if we're claiming from it
            return Err(InvariantViolation::new(
                "Claim",
                "INV-C2-ONCHAIN",
                &format!(
                    "Failed to read Project from on-chain!\n\
                    Project: {} (nonce: {})\n\
                    Error: {}\n\
                    \n\
                    Project should exist if we successfully claimed from it.",
                    project.project_id, project.nonce, e
                )
            ));
        }
    }

    Ok(())
}

/// INV-C2 Simplified: Check Attributions Count After Claim
pub fn check_attributions_after_claim(
    state: &FullSvmState,
    svm: &LiteSVM,
    project_index: usize,
    before_count: u64,
) -> Result<(), InvariantViolation> {
    check_attributions_count_monotonicity(state, svm, project_index, before_count)
}

// ============================================================================
// INV-C3: Total Claims Monotonicity (ProjectUser)
// ============================================================================

/// Helper: Read Total Claims from ProjectUser
/// Account Structure
/// The ProjectUser account in the Fuul program has this structure:
/// ```
/// Offset | Size | Field
/// -------|------|------------------
/// 0      | 8    | discriminator (Anchor)
/// 8      | 32   | authority (Pubkey)
/// 40     | 32   | project (Pubkey)
/// 72     | 8    | total_claims (u64)  ← We read this
/// 80     | 8    | total_native_claimed (u64)
/// ```

pub fn read_on_chain_total_claims(
    svm: &LiteSVM,
    project_id: &Pubkey,
    user_id: &Pubkey,
) -> Result<u64, String> {
    // Derive the ProjectUser PDA
    let (project_user_pda, _bump) = Pubkey::find_program_address(
        &[b"project-user", project_id.as_ref(), user_id.as_ref()],
        &PROGRAM_ID,
    );

    // Read the account from LiteSVM
    let account = svm.get_account(&project_user_pda)
        .ok_or_else(|| {
            format!(
                "ProjectUser account not found at PDA: {} (project: {}, user: {})",
                project_user_pda, project_id, user_id
            )
        })?;

    // Verify the account has the expected minimum size
    // 8 (discriminator) + 32 (authority) + 32 (project) + 8 (total_claims) = 80 bytes minimum
    if account.data.len() < 80 {
        return Err(format!(
            "ProjectUser account data too short: {} bytes (expected at least 80)",
            account.data.len()
        ));
    }

    // Read total_claims at offset 72
    // Offset calculation: 8 (discriminator) + 32 (authority) + 32 (project) = 72
    let total_claims = u64::from_le_bytes(
        account.data[72..80]
            .try_into()
            .map_err(|_| "Failed to read total_claims from bytes 72-80".to_string())?
    );

    Ok(total_claims)
}

/// INV-C3: Total Claims Monotonicity
pub fn check_total_claims_monotonicity(
    state: &FullSvmState,
    svm: &LiteSVM,
    project_id: &Pubkey,
    user_id: &Pubkey,
    before_count: u64,
) -> Result<(), InvariantViolation> {
    // Get the ProjectUser from state
    let user_key = (*project_id, *user_id);
    let project_user = state.project_users.get(&user_key)
        .ok_or_else(|| InvariantViolation::new(
            "Claim",
            "INV-C3",
            &format!("ProjectUser not found in state for project {} / user {}", project_id, user_id)
        ))?;

    let after_count = project_user.claim_count;
    let expected_count = before_count.saturating_add(1);

    // STEP 1: Validate internal state tracking
    if after_count != expected_count {
        return Err(InvariantViolation::new(
            "Claim",
            "INV-C3",
            &format!(
                "CRITICAL: Total claims did not increase by exactly 1 after Claim!\n\
                \n\
                Project: {}\n\
                User: {}\n\
                Count Before: {}\n\
                Count After: {}\n\
                Expected: {}\n\
                \n\
                This could cause:\n\
                - Rate limiting bypass (if count didn't increase)\n\
                - Incorrect user statistics (if count increased by more than 1)\n\
                - Reset of rate limits (if count decreased)",
                project_id,
                user_id,
                before_count,
                after_count,
                expected_count
            )
        ));
    }

    // STEP 2: Verify on-chain state matches our tracking
    match read_on_chain_total_claims(svm, project_id, user_id) {
        Ok(onchain_count) => {
            if after_count != onchain_count {
                return Err(InvariantViolation::new(
                    "Claim",
                    "INV-C3-SYNC",
                    &format!(
                        "CRITICAL: Total claims desync detected!\n\
                        \n\
                        Project: {}\n\
                        User: {}\n\
                        Our internal tracking: {}\n\
                        On-chain real value: {}\n\
                        Difference: {}\n\
                        \n\
                        This means our fuzzer's total_claims tracking is NOT synchronized with\n\
                        the actual on-chain state in LiteSVM.",
                        project_id,
                        user_id,
                        after_count,
                        onchain_count,
                        (after_count as i64) - (onchain_count as i64)
                    )
                ));
            }

            crate::debug_log!(
                "INV-C3 Total claims validated for project {} / user {}: {} -> {} (on-chain: {})",
                project_id, user_id, before_count, after_count, onchain_count
            );
        },
        Err(e) => {
            // ProjectUser should exist if we're claiming
            return Err(InvariantViolation::new(
                "Claim",
                "INV-C3-ONCHAIN",
                &format!(
                    "Failed to read ProjectUser from on-chain!\n\
                    Project: {}\n\
                    User: {}\n\
                    Error: {}\n\
                    \n\
                    ProjectUser should exist if we successfully claimed.",
                    project_id, user_id, e
                )
            ));
        }
    }

    Ok(())
}

/// INV-C3 Simplified: Check Total Claims After Claim
pub fn check_total_claims_after_claim(
    state: &FullSvmState,
    svm: &LiteSVM,
    project_id: &Pubkey,
    user_id: &Pubkey,
    before_count: u64,
) -> Result<(), InvariantViolation> {
    check_total_claims_monotonicity(state, svm, project_id, user_id, before_count)
}

// ============================================================================
// INV-C4: Total Native Claimed Monotonicity (ProjectUser)
// ============================================================================

/// Helper: Read On-Chain Total Native Claimed from ProjectUser
/// Account Structure
/// The ProjectUser account in the Fuul program has this structure:
/// ```
/// Offset | Size | Field
/// -------|------|------------------
/// 0      | 8    | discriminator (Anchor)
/// 8      | 32   | authority (Pubkey)
/// 40     | 32   | project (Pubkey)
/// 72     | 8    | total_claims (u64)
/// 80     | 8    | total_native_claimed (u64)  ← We read this
/// ```
pub fn read_on_chain_total_native_claimed(
    svm: &LiteSVM,
    project_id: &Pubkey,
    user_id: &Pubkey,
) -> Result<u64, String> {
    // Derive the ProjectUser PDA
    let (project_user_pda, _bump) = Pubkey::find_program_address(
        &[b"project-user", project_id.as_ref(), user_id.as_ref()],
        &PROGRAM_ID,
    );

    // Read the account from LiteSVM
    let account = svm.get_account(&project_user_pda)
        .ok_or_else(|| {
            format!(
                "ProjectUser account not found at PDA: {} (project: {}, user: {})",
                project_user_pda, project_id, user_id
            )
        })?;

    // Verify the account has the expected minimum size
    // 8 (discriminator) + 32 (authority) + 32 (project) + 8 (total_claims) + 8 (total_native_claimed) = 88 bytes
    if account.data.len() < 88 {
        return Err(format!(
            "ProjectUser account data too short: {} bytes (expected at least 88)",
            account.data.len()
        ));
    }

    // Read total_native_claimed at offset 80
    // Offset calculation: 8 (discriminator) + 32 (authority) + 32 (project) + 8 (total_claims) = 80
    let total_native_claimed = u64::from_le_bytes(
        account.data[80..88]
            .try_into()
            .map_err(|_| "Failed to read total_native_claimed from bytes 80-88".to_string())?
    );

    Ok(total_native_claimed)
}

/// INV-C4: Total Native Claimed Monotonicity
pub fn check_total_native_claimed_monotonicity(
    state: &FullSvmState,
    svm: &LiteSVM,
    project_id: &Pubkey,
    user_id: &Pubkey,
    before_amount: u64,
    claim_amount: u64,
    is_native: bool,
) -> Result<(), InvariantViolation> {
    // Get the ProjectUser from state
    let user_key = (*project_id, *user_id);
    let project_user = state.project_users.get(&user_key)
        .ok_or_else(|| InvariantViolation::new(
            "Claim",
            "INV-C4",
            &format!("ProjectUser not found in state for project {} / user {}", project_id, user_id)
        ))?;

    let after_amount = project_user.total_native_claimed;

    // STEP 1: Validate internal state tracking based on claim type
    if is_native {
        // For native claims: amount increase by exactly claim_amount
        let expected_amount = before_amount.saturating_add(claim_amount);
        
        if after_amount != expected_amount {
            return Err(InvariantViolation::new(
                "Claim",
                "INV-C4",
                &format!(
                    "CRITICAL: Total native claimed did not increase correctly after native Claim!\n\
                    \n\
                    Project: {}\n\
                    User: {}\n\
                    Amount Before: {}\n\
                    Claim Amount: {}\n\
                    Amount After: {}\n\
                    Expected: {}\n\
                    \n\
                    For native token claims, total_native_claimed should increase by the claim amount.",
                    project_id,
                    user_id,
                    before_amount,
                    claim_amount,
                    after_amount,
                    expected_amount
                )
            ));
        }
    } else {
        // For non-native claims (SPL/NFT): amount remain unchanged
        if after_amount != before_amount {
            return Err(InvariantViolation::new(
                "Claim",
                "INV-C4",
                &format!(
                    "CRITICAL: Total native claimed changed during non-native Claim!\n\
                    \n\
                    Project: {}\n\
                    User: {}\n\
                    Amount Before: {}\n\
                    Amount After: {}\n\
                    Difference: {}\n\
                    \n\
                    For SPL/NFT claims, total_native_claimed should NOT change.",
                    project_id,
                    user_id,
                    before_amount,
                    after_amount,
                    (after_amount as i64) - (before_amount as i64)
                )
            ));
        }
    }

    // STEP 2: Verify on-chain state matches our tracking
    match read_on_chain_total_native_claimed(svm, project_id, user_id) {
        Ok(onchain_amount) => {
            if after_amount != onchain_amount {
                return Err(InvariantViolation::new(
                    "Claim",
                    "INV-C4-SYNC",
                    &format!(
                        "CRITICAL: Total native claimed desync detected!\n\
                        \n\
                        Project: {}\n\
                        User: {}\n\
                        Our internal tracking: {}\n\
                        On-chain real value: {}\n\
                        Difference: {}\n\
                        Is Native Claim: {}\n\
                        \n\
                        This means our fuzzer's total_native_claimed tracking is NOT synchronized with\n\
                        the actual on-chain state in LiteSVM.",
                        project_id,
                        user_id,
                        after_amount,
                        onchain_amount,
                        (after_amount as i64) - (onchain_amount as i64),
                        is_native
                    )
                ));
            }

            crate::debug_log!(
                "INV-C4 Total native claimed validated for project {} / user {}: {} -> {} (on-chain: {}, is_native: {})",
                project_id, user_id, before_amount, after_amount, onchain_amount, is_native
            );
        },
        Err(e) => {
            // ProjectUser should exist if we're claiming
            return Err(InvariantViolation::new(
                "Claim",
                "INV-C4-ONCHAIN",
                &format!(
                    "Failed to read ProjectUser from on-chain!\n\
                    Project: {}\n\
                    User: {}\n\
                    Error: {}\n\
                    \n\
                    ProjectUser should exist if we successfully claimed.",
                    project_id, user_id, e
                )
            ));
        }
    }

    Ok(())
}

/// INV-C4 Simplified: Check Total Native Claimed After Claim
pub fn check_total_native_claimed_after_claim(
    state: &FullSvmState,
    svm: &LiteSVM,
    project_id: &Pubkey,
    user_id: &Pubkey,
    before_amount: u64,
    claim_amount: u64,
    is_native: bool,
) -> Result<(), InvariantViolation> {
    check_total_native_claimed_monotonicity(state, svm, project_id, user_id, before_amount, claim_amount, is_native)
}
