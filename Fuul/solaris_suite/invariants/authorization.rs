use crate::targets::full_svm::state::FullSvmState;
use crate::targets::full_svm::PROGRAM_ID;
use super::types::InvariantViolation;
use litesvm::LiteSVM;
use solana_sdk::pubkey::Pubkey;
use sha3::{Digest, Keccak256};

// ============================================================================
// INV-A1: Replay Prevention via Proof Uniqueness
// ============================================================================

/// Check if ProjectAttribution PDA exists on-chain
pub fn check_proof_exists_on_chain(
    svm: &LiteSVM,
    project_id: &Pubkey,
    proof: &[u8; 32],
) -> bool {
    let (attribution_pda, _bump) = Pubkey::find_program_address(
        &[b"project-attribution", project_id.as_ref(), proof.as_ref()],
        &PROGRAM_ID,
    );

    // Check if the account exists
    svm.get_account(&attribution_pda).is_some()
}

/// INV-A1: Replay Prevention via Proof Uniqueness
pub fn check_proof_uniqueness(
    state: &FullSvmState,
    svm: &LiteSVM,
    project_id: &Pubkey,
    proof: &[u8; 32],
    check_type: &str,
) -> Result<(), InvariantViolation> {
    // Check our internal tracking

    let mut hasher = Keccak256::new();
    hasher.update(project_id.as_ref());
    hasher.update(proof);
    let proof_hash: [u8; 32] = hasher.finalize().into();
    let internally_used = state.is_proof_used(&proof_hash);
    
    // Check on-chain state
    let on_chain_exists = check_proof_exists_on_chain(svm, project_id, proof);

    match check_type {
        "before_claim" => {
            // Before a claim, if proof is already used, the claim should fail
            // This is informational - the actual protection is in the program
            if internally_used || on_chain_exists {
                crate::debug_log!(
                    "INV-A1 Proof already used, claim should fail: internal={}, on_chain={}",
                    internally_used, on_chain_exists
                );
            }
            
            // Check for desync between internal and on-chain
            if internally_used != on_chain_exists {
                return Err(InvariantViolation::new(
                    "Claim (before)",
                    "INV-A1-SYNC",
                    &format!(
                        "CRITICAL: Proof tracking desync detected!\n\
                        \n\
                        Project: {}\n\
                        Proof: {:?}\n\
                        \n\
                        Internal tracking says: {}\n\
                        On-chain state says: {}\n\
                        \n\
                        This indicates a bug in our proof tracking logic.\n\
                        The fuzzer's internal state doesn't match on-chain reality.",
                        project_id,
                        proof,
                        if internally_used { "USED" } else { "NOT USED" },
                        if on_chain_exists { "EXISTS" } else { "DOESN'T EXIST" }
                    )
                ));
            }
            
            Ok(())
        }
        
        "after_claim" => {
            if !on_chain_exists {
                return Err(InvariantViolation::new(
                    "Claim (after)",
                    "INV-A1",
                    &format!(
                        "CRITICAL: Proof not marked as used after successful claim!\n\
                        \n\
                        Project: {}\n\
                        Proof: {:?}\n\
                        \n\
                        The claim succeeded but the ProjectAttribution account\n\
                        was not created on-chain. This breaks replay protection!\n\
                        \n\
                        An attacker could reuse this proof to claim again.",
                        project_id,
                        proof
                    )
                ));
            }
            
            // Verify internal tracking is updated
            if !internally_used {
                return Err(InvariantViolation::new(
                    "Claim (after)",
                    "INV-A1-SYNC",
                    &format!(
                        "WARNING: Internal proof tracking not updated!\n\
                        \n\
                        Project: {}\n\
                        Proof: {:?}\n\
                        \n\
                        On-chain: Proof is marked as used (account exists)\n\
                        Internal: Proof not tracked as used\n\
                        \n\
                        This is a fuzzer bug, not a program bug.\n\
                        Our internal state tracking needs to be updated.",
                        project_id,
                        proof
                    )
                ));
            }
            
            crate::debug_log!(
                "INV-A1 Proof correctly marked as used: project={}, proof={:?}",
                project_id, &proof[..8]
            );
            
            Ok(())
        }
        
        _ => {
            Err(InvariantViolation::new(
                "Unknown",
                "INV-A1",
                &format!("Unknown check_type: {}", check_type)
            ))
        }
    }
}

/// INV-A1: Check Proof Before Claim
pub fn check_proof_before_claim(
    state: &FullSvmState,
    svm: &LiteSVM,
    project_id: &Pubkey,
    proof: &[u8; 32],
) -> Result<(), InvariantViolation> {
    check_proof_uniqueness(state, svm, project_id, proof, "before_claim")
}

/// **INV-A1 Convenience: Check Proof After Claim**
pub fn check_proof_after_claim(
    state: &FullSvmState,
    svm: &LiteSVM,
    project_id: &Pubkey,
    proof: &[u8; 32],
) -> Result<(), InvariantViolation> {
    check_proof_uniqueness(state, svm, project_id, proof, "after_claim")
}

/// Helper: Verify Replay Attack Would Fail
pub fn would_replay_fail(
    svm: &LiteSVM,
    project_id: &Pubkey,
    proof: &[u8; 32],
) -> bool {
    check_proof_exists_on_chain(svm, project_id, proof)
}

// ============================================================================
// INV-A2: Multi-Signature Requirement
// ============================================================================

/// INV-A2: Multi-Signature Requirement
pub fn check_multisig_requirement(
    valid_signers_count: u8,
    required_signers: u8,
    claim_succeeded: bool,
) -> Result<(), InvariantViolation> {
    let should_succeed = valid_signers_count >= required_signers;

    if claim_succeeded && !should_succeed {
        return Err(InvariantViolation::new(
            "Claim",
            "INV-A2",
            &format!(
                "CRITICAL: Claim succeeded with insufficient signers!\n\
                \n\
                Valid signers provided: {}\n\
                Required signers: {}\n\
                \n\
                The claim should have FAILED because:\n\
                {} < {} (not enough valid signers)\n\
                \n\
                This is a multi-sig bypass vulnerability!\n\
                An attacker with fewer keys than required could steal funds.",
                valid_signers_count,
                required_signers,
                valid_signers_count,
                required_signers
            )
        ));
    }

    if !claim_succeeded && should_succeed {
        crate::debug_log!(
            "INV-A2 Claim failed with sufficient signers ({} >= {}). \
            Failure may be due to other reasons (insufficient budget, etc.)",
            valid_signers_count, required_signers
        );
    }

    if claim_succeeded && should_succeed {
        crate::debug_log!(
            "INV-A2 Multi-sig requirement satisfied: {} >= {} signers",
            valid_signers_count, required_signers
        );
    }

    Ok(())
}

/// INV-A2 Convenience: Verify Multi-Sig After Claim Attempt
pub fn verify_multisig_enforcement(
    signers: &[Pubkey],
    roles_mapping: &crate::targets::full_svm::state::GlobalRolesMapping,
    required_signers: u8,
    claim_succeeded: bool,
) -> Result<(), InvariantViolation> {
    // Count how many signers have the Signer role
    let valid_count = signers
        .iter()
        .filter(|signer| {
            roles_mapping.roles.iter().any(|entry| {
                entry.account == **signer && entry.role == crate::targets::full_svm::state::GlobalRole::Signer
            })
        })
        .count() as u8;

    check_multisig_requirement(valid_count, required_signers, claim_succeeded)
}

// ============================================================================
// INV-A3: Paused State Blocks Claims
// ============================================================================

/// Helper: Check if GlobalConfig is paused on-chain
pub fn check_paused_state_on_chain(svm: &LiteSVM) -> Result<bool, String> {
    use borsh::BorshDeserialize;

    let (global_config_pda, _) = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    );

    let account = svm.get_account(&global_config_pda)
        .ok_or_else(|| format!("GlobalConfig account not found at {}", global_config_pda))?;

    // GlobalConfig structure
    #[derive(BorshDeserialize)]
    struct FeeManagementOnChain {
        pub fee_collector: Pubkey,
        pub no_claim_fee_whitelist: Vec<Pubkey>,
        pub user_native_claim_fee: u64,
        pub project_claim_fee: u16,
        pub remove_fee: u16,
    }

    #[derive(BorshDeserialize)]
    #[repr(C)]
    enum GlobalRoleOnChain {
        Admin,
        Pauser,
        Unpauser,
        Signer,
    }

    #[derive(BorshDeserialize)]
    struct GlobalRoleEntry {
        pub account: Pubkey,
        pub role: GlobalRoleOnChain,
    }

    #[derive(BorshDeserialize)]
    struct GlobalRolesMapping {
        pub roles: Vec<GlobalRoleEntry>,
    }

    #[derive(BorshDeserialize)]
    struct GlobalConfigOnChain {
        pub is_initialized: bool,
        pub paused: bool,
        pub project_nonce: u64,
        pub claim_cool_down: u64,
        pub required_signers_for_claim: u8,
        pub fee_management: FeeManagementOnChain,
        pub roles_mapping: GlobalRolesMapping,
    }

    let data = &account.data[8..]; // Skip 8-byte Anchor discriminator

    // Create a mutable slice for deserialization
    let mut slice = data;

    // Read only the fields we need up to paused
    let is_initialized = bool::deserialize(&mut slice)
        .map_err(|e| format!("Failed to read is_initialized: {}", e))?;
    let paused = bool::deserialize(&mut slice)
        .map_err(|e| format!("Failed to read paused: {}", e))?;

    Ok(paused)
}

/// INV-A3: Paused State Blocks Claims
pub fn check_pause_enforcement(
    is_paused: bool,
    claim_succeeded: bool,
    context: &str,
) -> Result<(), InvariantViolation> {
    if is_paused && claim_succeeded {
        return Err(InvariantViolation::new(
            context,
            "INV-A3",
            &format!(
                "CRITICAL: Claim succeeded while protocol is paused!\n\
                \n\
                The pause mechanism is broken. This is a critical security issue.\n\
                Claims must be blocked when GlobalConfig.paused = true."
            )
        ));
    }

    if is_paused && !claim_succeeded {
        crate::debug_log!("INV-A3 Claim correctly blocked due to paused state");
    }

    if !is_paused && claim_succeeded {
        crate::debug_log!("INV-A3 Claim succeeded while not paused (expected)");
    }

    Ok(())
}

/// INV-A3 On-Chain: Verify Pause State Matches
pub fn verify_pause_state_consistency(
    svm: &LiteSVM,
    local_paused: bool,
    context: &str,
) -> Result<(), InvariantViolation> {
    match check_paused_state_on_chain(svm) {
        Ok(on_chain_paused) => {
            if local_paused != on_chain_paused {
                return Err(InvariantViolation::new(
                    context,
                    "INV-A3-SYNC",
                    &format!(
                        "Pause state mismatch!\n\
                        Local tracking: {}\n\
                        On-chain state: {}\n\
                        \n\
                        This indicates our state tracking is out of sync.",
                        if local_paused { "PAUSED" } else { "NOT PAUSED" },
                        if on_chain_paused { "PAUSED" } else { "NOT PAUSED" }
                    )
                ));
            }
            crate::debug_log!(
                "INV-A3-SYNC Pause state consistent: {}",
                if local_paused { "PAUSED" } else { "NOT PAUSED" }
            );
        }
        Err(e) => {
            crate::debug_log!("INV-A3-SYNC Could not verify on-chain pause state: {}", e);
        }
    }
    Ok(())
}

// ============================================================================
// INV-A4: Currency Active Required for Operations
// ============================================================================

/// Helper: Check if CurrencyToken is active on-chain
pub fn check_currency_active_on_chain(svm: &LiteSVM, currency_id: &Pubkey) -> Result<bool, String> {
    use borsh::BorshDeserialize;

    // CurrencyToken is at a PDA, not at the currency_id
    let (currency_pda, _) = Pubkey::find_program_address(
        &[b"currency-token", currency_id.as_ref()],
        &crate::targets::full_svm::PROGRAM_ID,
    );

    let account = svm.get_account(&currency_pda)
        .ok_or_else(|| format!("CurrencyToken account not found at PDA {}", currency_pda))?;

    // CurrencyToken structure
    #[derive(BorshDeserialize)]
    #[repr(C)]
    enum TokenTypeOnChain {
        Native,
        FungibleSpl,
        NonFungibleSpl,
    }

    #[derive(BorshDeserialize)]
    struct CurrencyTokenOnChain {
        pub is_initialized: bool,
        pub token_mint: Pubkey,
        pub token_type: TokenTypeOnChain,
        pub is_active: bool,
        pub claim_limit_per_cooldown: u64,
        pub cumulative_claim_per_cooldown: u64,
        pub claim_cooldown_period_started: i64,
    }

    let data = &account.data[8..]; // Skip 8-byte Anchor discriminator

    // Create a mutable slice for deserialization
    let mut slice = data;

    // Read fields in order: is_initialized, token_mint, token_type, is_active
    let is_initialized = bool::deserialize(&mut slice)
        .map_err(|e| format!("Failed to read is_initialized: {}", e))?;
    let token_mint = Pubkey::deserialize(&mut slice)
        .map_err(|e| format!("Failed to read token_mint: {}", e))?;
    let token_type = u8::deserialize(&mut slice)
        .map_err(|e| format!("Failed to read token_type: {}", e))?;
    let is_active = bool::deserialize(&mut slice)
        .map_err(|e| format!("Failed to read is_active: {}", e))?;

    Ok(is_active)
}

/// INV-A4: Currency Active Required for Deposits
pub fn check_currency_active_requirement(
    is_active: bool,
    operation: &str,
    operation_succeeded: bool,
    context: &str,
) -> Result<(), InvariantViolation> {
    let requires_active = matches!(operation,
        "DepositFungibleToken" | "DepositNonFungibleToken"
    );

    if requires_active && !is_active && operation_succeeded {
        return Err(InvariantViolation::new(
            context,
            "INV-A4",
            &format!(
                "CRITICAL: {} succeeded with inactive currency!\n\
                \n\
                Operation: {}\n\
                Currency active: false\n\
                \n\
                Deposits must be blocked for inactive currencies.\n\
                This prevents adding funds to deprecated tokens.\n\
                Note: Claims/removes are allowed for fund recovery.",
                operation, operation
            )
        ));
    }

    // Claims and remove operations should work even with inactive currency
    let is_remove = matches!(operation,
        "RemoveFungibleToken" | "RemoveNonFungibleToken"
    );
    if is_remove && !is_active && operation_succeeded {
        crate::debug_log!(
            "INV-A4 Remove operation correctly allowed with inactive currency"
        );
    }

    if requires_active && !is_active && !operation_succeeded {
        crate::debug_log!(
            "INV-A4 {} correctly blocked due to inactive currency",
            operation
        );
    }

    Ok(())
}

/// INV-A4 On-Chain: Verify Currency Active State
pub fn verify_currency_active_consistency(
    svm: &LiteSVM,
    currency_id: &Pubkey,
    local_active: bool,
    context: &str,
) -> Result<(), InvariantViolation> {
    match check_currency_active_on_chain(svm, currency_id) {
        Ok(on_chain_active) => {
            if local_active != on_chain_active {
                return Err(InvariantViolation::new(
                    context,
                    "INV-A4-SYNC",
                    &format!(
                        "Currency active state mismatch!\n\
                        Currency: {}\n\
                        Local tracking: {}\n\
                        On-chain state: {}\n\
                        \n\
                        This indicates our state tracking is out of sync.",
                        currency_id,
                        if local_active { "ACTIVE" } else { "INACTIVE" },
                        if on_chain_active { "ACTIVE" } else { "INACTIVE" }
                    )
                ));
            }
        }
        Err(e) => {
            crate::debug_log!("INV-A4-SYNC Could not verify on-chain currency state: {}", e);
        }
    }
    Ok(())
}

// ============================================================================
// INV-A5: Only Admins Can Manage Budgets
// ============================================================================

/// Helper: Check if account has ProjectRole::Admin on-chain
pub fn check_project_admin_on_chain(
    svm: &LiteSVM,
    project_id: &Pubkey,
    account: &Pubkey,
) -> Result<bool, String> {
    use borsh::BorshDeserialize;

    let project_account = svm.get_account(project_id)
        .ok_or_else(|| format!("Project account not found at {}", project_id))?;

    // Project structure

    // ProjectRole enum
    #[derive(BorshDeserialize)]
    #[repr(C)]
    enum ProjectRoleOnChain {
        Admin,
    }

    #[derive(BorshDeserialize)]
    struct ProjectRoleEntry {
        pub account: Pubkey,
        pub role: ProjectRoleOnChain,
    }

    #[derive(BorshDeserialize)]
    struct ProjectRolesMapping {
        pub roles: Vec<ProjectRoleEntry>,
    }

    #[derive(BorshDeserialize)]
    struct ProjectFeeManagement {
        pub user_native_claim_fee: Option<u64>,
        pub project_claim_fee: Option<u16>,
        pub remove_fee: Option<u16>,
    }

    #[derive(BorshDeserialize)]
    struct ProjectOnChain {
        pub is_initialized: bool,
        pub nonce: u64,
        pub attributions_count: u64,
        pub metadata_uri: String,
        pub fee_management: ProjectFeeManagement,
        pub roles_mapping: ProjectRolesMapping,
    }

    let data = &project_account.data[8..]; // Skip 8-byte Anchor discriminator
    let project = ProjectOnChain::try_from_slice(data)
        .map_err(|e| format!("Failed to deserialize Project: {}", e))?;

    // Check if the account has Admin role
    let is_admin = project.roles_mapping.roles.iter()
        .any(|entry| entry.account == *account && matches!(entry.role, ProjectRoleOnChain::Admin));

    Ok(is_admin)
}

/// INV-A5: Only Admins Can Remove From Budgets
pub fn check_admin_authorization(
    authority: &Pubkey,
    project_admins: &[Pubkey],
    operation: &str,
    operation_succeeded: bool,
    context: &str,
) -> Result<(), InvariantViolation> {
    let requires_admin = matches!(operation,
        "RemoveFungibleToken" | "RemoveNonFungibleToken"
    );

    let is_admin = project_admins.contains(authority);

    if requires_admin && !is_admin && operation_succeeded {
        return Err(InvariantViolation::new(
            context,
            "INV-A5",
            &format!(
                "CRITICAL: Non-admin performed admin-only operation!\n\
                \n\
                Authority: {}\n\
                Operation: {}\n\
                Is admin: false\n\
                \n\
                Only project admins should be able to manage budgets.\n\
                This is an authorization bypass vulnerability!",
                authority, operation
            )
        ));
    }

    if requires_admin && is_admin && operation_succeeded {
        crate::debug_log!(
            "INV-A5 Admin {} successfully performed {}",
            authority, operation
        );
    }

    if requires_admin && !is_admin && !operation_succeeded {
        crate::debug_log!(
            "INV-A5 Non-admin correctly blocked from {}",
            operation
        );
    }

    Ok(())
}

/// INV-A5: Verify Admin Role for Project Operations
pub fn verify_project_admin_authorization(
    state: &crate::targets::full_svm::state::FullSvmState,
    project_index: usize,
    authority: &Pubkey,
    operation: &str,
    operation_succeeded: bool,
) -> Result<(), InvariantViolation> {
    if project_index >= state.projects.len() {
        return Err(InvariantViolation::new(
            operation,
            "INV-A5",
            &format!("Invalid project index: {}", project_index)
        ));
    }

    let project = &state.projects[project_index];
    let admins: Vec<Pubkey> = project.roles_mapping.roles.iter()
        .filter_map(|entry| {
            if entry.role == crate::targets::full_svm::state::ProjectRole::Admin {
                Some(entry.account)
            } else {
                None
            }
        })
        .collect();

    check_admin_authorization(authority, &admins, operation, operation_succeeded, operation)
}

/// INV-A5 On-Chain: Verify Admin Authorization
pub fn verify_admin_role_consistency(
    svm: &LiteSVM,
    project_id: &Pubkey,
    authority: &Pubkey,
    local_is_admin: bool,
    context: &str,
) -> Result<(), InvariantViolation> {
    match check_project_admin_on_chain(svm, project_id, authority) {
        Ok(on_chain_is_admin) => {
            if local_is_admin != on_chain_is_admin {
                return Err(InvariantViolation::new(
                    context,
                    "INV-A5-SYNC",
                    &format!(
                        "Admin role mismatch!\n\
                        Project: {}\n\
                        Authority: {}\n\
                        Local tracking: {}\n\
                        On-chain state: {}\n\
                        \n\
                        This indicates our role tracking is out of sync.",
                        project_id,
                        authority,
                        if local_is_admin { "IS ADMIN" } else { "NOT ADMIN" },
                        if on_chain_is_admin { "IS ADMIN" } else { "NOT ADMIN" }
                    )
                ));
            }
        }
        Err(e) => {
            crate::debug_log!("INV-A5-SYNC Could not verify on-chain admin role: {}", e);
        }
    }
    Ok(())
}
