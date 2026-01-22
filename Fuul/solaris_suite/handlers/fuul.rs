use crate::core::harness::HarnessBase;
use crate::targets::full_svm::{
    proto::*,
    state::{*, ProjectFeeManagement, ProjectRolesMapping},
    invariants::{
        check_budget_non_negative,
        check_claim_decreases_budget_correctly,
        check_deposit_increases_budget,
        check_remove_decreases_budget,
        check_claim_conservation_of_funds,
        check_remove_conservation_of_funds,
        check_nonce_after_create_project,
        check_attributions_after_claim,
        check_total_claims_after_claim,
        check_total_native_claimed_after_claim,
        check_cumulative_within_limit,
        check_claim_amount_within_limit,
        check_cooldown_reset_behavior,
        capture_rate_limits_before_claim,
        check_fee_range_after_global_update,
        check_fee_range_after_project_update,
        check_fee_bp_range_on_chain,
        check_fee_calculation_after_claim,
        check_project_fee_source_after_claim,
        check_project_fee_source_on_chain,
        check_proof_after_claim,
        check_multisig_requirement,
        read_on_chain_budget,
        InvariantViolation,
        authorization::{
            check_pause_enforcement, verify_pause_state_consistency,
            check_currency_active_requirement, verify_currency_active_consistency,
            verify_project_admin_authorization, verify_admin_role_consistency,
            check_admin_authorization,
        },
        timing::{
            check_message_deadline_not_expired, check_cooldown_period_calculation,
            check_timestamps_monotonic, check_attribution_timestamp_accuracy,
            verify_cooldown_state_on_chain, read_attribution_timestamp_on_chain,
            get_clock_time_on_chain,
        },
        math::{
            check_operation_math_invariants, check_global_conservation,
            check_claim_budget_deduction, check_nft_constraints,
            read_project_budget_on_chain,
        },
        state_consistency::{
            check_budget_exists_after_deposit,
            check_attribution_count_consistency,
            check_attribution_count_consistency_onchain,
            check_user_claims_consistency,
            check_user_claims_consistency_onchain,
            check_currency_exists_for_budget,
            check_currency_type_consistency,
        },
        special_cases::{
            check_first_deposit_creates_budget, check_first_deposit_creates_budget_onchain,
            check_last_admin_protection, check_last_admin_protection_global_onchain,
            check_last_admin_protection_project_onchain, check_zero_amount_rejection,
            check_whitelist_fee_bypass, check_whitelist_fee_bypass_onchain,
            check_message_domain_validation,
            check_project_fee_limits_onchain, check_claim_fee_deduction_onchain,
        }
    },
    PROGRAM_ID
};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_program,
    transaction::Transaction,
};
use borsh::{BorshSerialize, BorshDeserialize};
use crate::{debug_err, debug_log};
use std::str::FromStr;
use spl_token::state::Account as TokenAccount;
use solana_sdk::program_pack::Pack;

/// Helper to convert bytes to Pubkey
fn bytes_to_pubkey(bytes: &[u8]) -> Result<Pubkey, Box<dyn std::error::Error>> {
    if bytes.len() != 32 {
        return Err(format!("Invalid pubkey length: {}", bytes.len()).into());
    }
    Ok(Pubkey::from(
        <[u8; 32]>::try_from(bytes).map_err(|_| "Failed to convert bytes to pubkey")?
    ))
}

/// Helper to get anchor instruction discriminator using sighash
fn get_anchor_discriminator(instruction_name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let preimage = format!("global:{}", instruction_name);
    let mut hasher = Sha256::new();
    hasher.update(preimage.as_bytes());
    let hash = hasher.finalize();
    let mut discriminator = [0u8; 8];
    discriminator.copy_from_slice(&hash[..8]);
    discriminator
}

// ============================================================================
// Instruction Data Structures matching Anchor function signatures
// ============================================================================

#[derive(BorshSerialize, BorshDeserialize)]
struct CreateGlobalConfigIx {
    fee_collector: Pubkey, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct UpdateGlobalConfigIx {
    claim_cool_down: Option<u64>, 
    required_signers_for_claim: Option<u8>, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct UpdateGlobalConfigFeesIx {
    fee_collector: Option<Pubkey>, 
    user_native_claim_fee: Option<u64>, 
    project_claim_fee: Option<u16>, 
    remove_fee: Option<u16>, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct AddNoClaimFeeWhitelistIx {
    account: Pubkey, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct RemoveNoClaimFeeWhitelistIx {
    account: Pubkey,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct GrantGlobalRoleIx {
    account: Pubkey, 
    role: u8, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct RevokeGlobalRoleIx {
    account: Pubkey, 
    role: u8, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct RenounceGlobalRoleIx {
    role: u8,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct AddCurrencyTokenIx {
    token_type: u8, 
    claim_limit_per_cooldown: u64, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct UpdateCurrencyTokenLimitIx {
    claim_limit_per_cooldown: Option<u64>, 
    is_active: Option<bool>, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct CreateProjectIx {
    admin: Pubkey, 
    metadata_uri: String, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct UpdateProjectConfigIx {
    project_nonce: u64, 
    metadata_uri: String, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct UpdateProjectFeesIx {
    project_nonce: u64, 
    user_native_claim_fee: Option<u64>, 
    project_claim_fee: Option<u16>, 
    remove_fee: Option<u16>, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct GrantProjectRoleIx {
    project_nonce: u64, 
    account: Pubkey, 
    role: u8, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct RevokeProjectRoleIx {
    project_nonce: u64, 
    account: Pubkey, 
    role: u8, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct RenounceProjectRoleIx {
    project_nonce: u64, 
    role: u8, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct DepositFungibleTokenIx {
    project_nonce: u64, 
    amount: u64, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct DepositNonFungibleTokenIx {
    project_nonce: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct RemoveFungibleTokenIx {
    project_nonce: u64, 
    amount: u64, 
}

#[derive(BorshSerialize, BorshDeserialize)]
struct RemoveNonFungibleTokenIx {
    project_nonce: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct ClaimIx {
    project_nonce: u64, 
    proof: [u8; 32], 
}

// ============================================================================
// Global Config Instructions
// ============================================================================

pub fn execute_create_global_config(
    harness: &mut HarnessBase,
    msg: &CreateGlobalConfig,
) -> Result<(), Box<dyn std::error::Error>> {

    debug_log!("[FUUL] Starting execute_create_global_config");
    debug_log!("[FUUL] Program ID: {}", PROGRAM_ID);

    let state = harness.state.get_or_insert_extension::<FullSvmState>();
    let authority = state.get_random_authority(msg.authority_id as usize).insecure_clone();

    // Use the fee_collector_keypair from state
    // We have a valid non-zero pubkey
    let fee_collector = state.fee_collector_keypair.pubkey();

    // Global config is at a fixed hardcoded address
    let global_config_address = Pubkey::from_str("6tmBxYUDkm8xg2NybDU5hgrpHLgs4gT1CPF1ngkQe9iY").unwrap();

    debug_log!("[FUUL] Global config PDA: {}", global_config_address);
    debug_log!("[FUUL] Authority: {}", authority.pubkey());
    debug_log!("[FUUL] Fee collector: {}", fee_collector);

    // Build instruction data with proper Borsh serialization
    let mut data = get_anchor_discriminator("create_global_config").to_vec();
    debug_log!("[FUUL] Discriminator for 'create_global_config': {:?}", &data[..8]);

    // Serialize the fee_collector parameter
    let ix_data = CreateGlobalConfigIx {
        fee_collector,
    };
    let serialized = borsh::to_vec(&ix_data)?;
    data.extend_from_slice(&serialized);
    debug_log!("[FUUL] Full instruction data length: {} (should be 8 + 32 = 40)", data.len());

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),  // authority is the signer and mutable
            AccountMeta::new(global_config_address, false),  // global_config is mutable, not signer
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    };

    debug_log!("[FUUL] Instruction accounts:");
    for (i, acc) in instruction.accounts.iter().enumerate() {
        debug_log!("  [{}] {}: writable={}, signer={}", i, acc.pubkey, acc.is_writable, acc.is_signer);
    }

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&authority.pubkey()),
        &[&authority],
        harness.svm.latest_blockhash(),
    );

    debug_log!("[FUUL] Sending transaction to create global config");
    let result = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        state.global_config.is_initialized = true;
        state.global_config.fee_management.fee_collector = fee_collector;
        state.global_config.fee_management.project_claim_fee = 0; // Default
        state.global_config.claim_cooldown = msg.claim_cooldown;
        state.global_config.required_signers_for_claim = 1; // Hardcoded by program
        debug_log!("[CREATE_GLOBAL_CONFIG] Set required_signers_for_claim = 1");
        // Grant all roles to the initial authority
        state.grant_global_role(authority.pubkey(), GlobalRole::Admin);
        state.grant_global_role(authority.pubkey(), GlobalRole::Pauser);
        state.grant_global_role(authority.pubkey(), GlobalRole::Unpauser);
        state.grant_global_role(authority.pubkey(), GlobalRole::Signer);
        debug_log!("[CREATE_GLOBAL_CONFIG] Granted Signer role to authority: {}", authority.pubkey());

        debug_log!("[CREATE_GLOBAL_CONFIG] WARNING: Only {} has Signer role on-chain", authority.pubkey());
        debug_log!("Global config created successfully");
    });

    debug_log!("[FUUL] Transaction result: {:?}", result);
    match result {
        Ok(_) => debug_log!("[FUUL] Global config creation succeeded"),
        Err(ref e) => debug_log!("[FUUL] Global config creation failed: {:?}", e),
    }

    Ok(())
}

pub fn execute_update_global_config(
    harness: &mut HarnessBase,
    msg: &UpdateGlobalConfig,
) -> Result<(), Box<dyn std::error::Error>> {

    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Find an admin
    let admin = state.global_config.roles_mapping.roles.iter()
        .find(|entry| entry.role == GlobalRole::Admin)
        .and_then(|entry| {
            state.authority_keypairs.iter()
                .find(|kp| kp.pubkey() == entry.account)
        })
        .ok_or("No admin keypair found")?
        .insecure_clone();

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    // Build instruction data using proper Borsh serialization
    let mut data = get_anchor_discriminator("update_global_config").to_vec();
    let ix_data = UpdateGlobalConfigIx {
        claim_cool_down: if msg.claim_cooldown.is_some() && msg.claim_cooldown.unwrap() > 0 {
            Some(msg.claim_cooldown.unwrap())
        } else {
            None
        },
        required_signers_for_claim: if msg.required_signers_for_claim.is_some() && msg.required_signers_for_claim.unwrap() > 0 {
            Some(msg.required_signers_for_claim.unwrap() as u8)
        } else {
            None
        },
    };
    data.extend_from_slice(&borsh::to_vec(&ix_data)?);

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),  // 0. authority (signer)
            AccountMeta::new(global_config_address, false),  // 1. global_config
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&admin.pubkey()),
        &[&admin],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        if let Some(cooldown) = msg.claim_cooldown {
            state.global_config.claim_cooldown = cooldown;
        }
        if let Some(signers) = msg.required_signers_for_claim {
            state.global_config.required_signers_for_claim = signers as u8;
            debug_log!("[UPDATE_GLOBAL_CONFIG] Updated required_signers_for_claim to {}", signers);
        }
        debug_log!("Global config updated");
    });

    if let Some(required_signers) = msg.required_signers_for_claim {
        // Collect the data we need before borrowing state again
        let (current_signers, authority_pubkeys) = {
            let state = harness.state.get_or_insert_extension::<FullSvmState>();
            let current = state.count_global_roles(GlobalRole::Signer);
            let pubkeys: Vec<Pubkey> = state.authority_keypairs
                .iter()
                .map(|kp| kp.pubkey())
                .collect();
            (current, pubkeys)
        };

        if current_signers < required_signers as usize {
            // Grant Signer role to more authorities
            let needed = required_signers as usize - current_signers;
            let mut granted = 0;

            for pubkey in authority_pubkeys {
                let needs_signer = {
                    let state = harness.state.get_extension::<FullSvmState>()
                        .ok_or("State not initialized")?;
                    !state.has_global_role(&pubkey, GlobalRole::Signer)
                };

                if needs_signer {
                    // Build grant role instruction
                    let mut data = get_anchor_discriminator("grant_global_role").to_vec();
                    let ix_data = GrantGlobalRoleIx {
                        account: pubkey,
                        role: 3u8, // GlobalRole::Signer = 3
                    };
                    data.extend_from_slice(&borsh::to_vec(&ix_data)?);

                    let accounts = vec![
                        AccountMeta::new(admin.pubkey(), true),  // authority (admin)
                        AccountMeta::new(global_config_address, false),  // global_config
                    ];

                    let grant_instruction = Instruction {
                        program_id: PROGRAM_ID,
                        accounts,
                        data,
                    };

                    let tx = Transaction::new_signed_with_payer(
                        &[grant_instruction],
                        Some(&admin.pubkey()),
                        &[&admin],
                        harness.svm.latest_blockhash(),
                    );

                    let _ = crate::execute_transaction!(harness, tx, on_success: || {
                        let state = harness.state.get_or_insert_extension::<FullSvmState>();
                        state.grant_global_role(pubkey, GlobalRole::Signer);
                        debug_log!("Granted Signer role to {}", pubkey);
                    });

                    granted += 1;
                    if granted >= needed {
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// Currency Token Instructions
// ============================================================================

pub fn execute_add_currency_token(
    harness: &mut HarnessBase,
    msg: &AddCurrencyToken,
) -> Result<(), Box<dyn std::error::Error>> {

    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Find an admin
    let admin = state.global_config.roles_mapping.roles.iter()
        .find(|entry| entry.role == GlobalRole::Admin)
        .and_then(|entry| {
            state.authority_keypairs.iter()
                .find(|kp| kp.pubkey() == entry.account)
        })
        .ok_or("No admin keypair found")?
        .insecure_clone();

    // Use internal CurrencyType enum temporarily
    #[derive(Debug, Clone, Copy)]
    enum TempCurrencyType {
        Native = 0,
        Fungible = 1,
        NonFungible = 2,
    }

    // Resolve token mint and currency type from indices
    let (token_mint, temp_currency_type) = if msg.use_native {
        // Native token use Pubkey::default() as expected
        (Pubkey::default(), TempCurrencyType::Native)
    } else if !state.spl_token_mints.is_empty() {
        // Use the index into our SPL token mints
        let mint_index = (msg.spl_token_index as usize) % state.spl_token_mints.len();
        let mint = state.spl_token_mints[mint_index];
        // Determine currency type based on mint decimals
        // Mints 0-2 have decimals=9 (fungible), mints 3-5 have decimals=0 (NFT)
        let currency_type = if mint_index <= 2 {
            TempCurrencyType::Fungible
        } else {
            TempCurrencyType::NonFungible
        };
        (mint, currency_type)
    } else {
        // Fallback to native if no SPL mints available
        (Pubkey::default(), TempCurrencyType::Native)
    };

    
    // Check if this currency token already exists
    if state.currency_tokens.contains_key(&token_mint) {
        debug_log!("Currency token {} already exists, skipping", token_mint);
        return Ok(());
    }
    // Currency token PDA
    let currency_token_pda = Pubkey::find_program_address(
        &[b"currency-token", token_mint.as_ref()],
        &PROGRAM_ID,
    ).0;

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    // Build instruction data using proper Borsh serialization
    let mut data = get_anchor_discriminator("add_currency_token").to_vec();
    let ix_data = AddCurrencyTokenIx {
        token_type: temp_currency_type as u8,  // 0 for Native, 1 for Fungible, 2 for NonFungible
        claim_limit_per_cooldown: msg.claim_limit_per_cooldown,
    };
    data.extend_from_slice(&borsh::to_vec(&ix_data)?);

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),  // authority - signer and mutable
            AccountMeta::new(global_config_address, false),  // global_config - mutable
            AccountMeta::new(currency_token_pda, false),  // currency_token - mutable
            AccountMeta::new_readonly(token_mint, false),  // token_mint - readonly
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&admin.pubkey()),
        &[&admin],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        // Use the currency_type determined earlier
        let ct = match temp_currency_type {
            TempCurrencyType::Native => crate::targets::full_svm::state::CurrencyType::Native,
            TempCurrencyType::Fungible => crate::targets::full_svm::state::CurrencyType::Fungible,
            TempCurrencyType::NonFungible => crate::targets::full_svm::state::CurrencyType::NonFungible,
        };
        state.currency_tokens.insert(token_mint, CurrencyToken {
            is_initialized: true,
            token_mint,
            currency_type: ct.clone(),
            enabled: true, // Always true when adding a currency
            claim_limit_per_cooldown: msg.claim_limit_per_cooldown,
            cumulative_claim_per_cooldown: 0,
            claim_cooldown_period_started: 0,
        });
        debug_log!("Currency token added: {} (type: {:?})", token_mint, ct);

        // INV-N1: Check freeze authority on non-native currency tokens
        /*
        let is_native = matches!(temp_currency_type, TempCurrencyType::Native);
        if let Err(mut violation) = super::spl_token::check_freeze_authority_after_add_currency(
            &harness.svm,
            &token_mint,
            is_native,
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }
        */
    });

    Ok(())
}

// ============================================================================
// Project Instructions
// ============================================================================

pub fn execute_create_project(
    harness: &mut HarnessBase,
    msg: &CreateProject,
) -> Result<(), Box<dyn std::error::Error>> {

    let state = harness.state.get_or_insert_extension::<FullSvmState>();
    let authority = state.get_random_authority(msg.authority_id as usize).insecure_clone();

    // INV-C1: Capture nonce before the transaction for invariant verification
    let before_nonce = state.global_config.project_nonce;

    // Project PDA uses the current nonce from global_config
    let project_nonce = state.global_config.project_nonce;
    let project_pda = Pubkey::find_program_address(
        &[b"project", &project_nonce.to_le_bytes()],
        &PROGRAM_ID,
    ).0;

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    // Build instruction data using proper Borsh serialization
    // create_project takes admin: Pubkey and metadata_uri: String
    let mut data = get_anchor_discriminator("create_project").to_vec();

    // Get the admin from our state using the provided admin_id
    let admin_pubkey = state.get_random_authority(msg.admin_id as usize).pubkey();

    let ix_data = CreateProjectIx {
        admin: admin_pubkey,
        metadata_uri: msg.metadata_uri.clone(),
    };
    data.extend_from_slice(&borsh::to_vec(&ix_data)?);

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),  // authority - signer and mutable
            AccountMeta::new(global_config_address, false),  // global_config - mutable
            AccountMeta::new(project_pda, false),  // project - mutable (init)
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&authority.pubkey()),
        &[&authority],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        let used_nonce = state.global_config.project_nonce;
        state.global_config.project_nonce += 1;  // Increment nonce
        state.projects.push(Project {
            is_initialized: true,
            project_id: project_pda,
            nonce: used_nonce,
            metadata_uri: msg.metadata_uri.clone(),
            fee_management: ProjectFeeManagement {
                user_native_claim_fee: None,
                project_claim_fee: None,
                remove_fee: None,
            },
            roles_mapping: ProjectRolesMapping {
                roles: Vec::new(),  // Will be populated by grant_project_role below
            },
            attributions_count: 0,
            default_fee_bps: 0,  // Set by program internally
            cooldown_seconds: 0,  // Set by program internally
            max_claims_per_user: 0,  // Set by program internally
        });
        // Grant admin role to the project admin
        let project_index = state.projects.len() - 1;
        state.grant_project_role(project_index, admin_pubkey, ProjectRole::Admin);
        debug_log!("Project created with nonce {}", used_nonce);

        // INV-C1: Verify project nonce increased by exactly 1
        if let Err(violation) = check_nonce_after_create_project(
            state,
            &harness.svm,
            before_nonce,
        ) {
            violation.dump_and_abort();
        }
    });

    Ok(())
}

// ============================================================================
// Budget Operations
// ============================================================================

pub fn execute_deposit_fungible_token(
    harness: &mut HarnessBase,
    msg: &DepositFungibleToken,
) -> Result<(), Box<dyn std::error::Error>> {

    let state = harness.state.get_or_insert_extension::<FullSvmState>();
    let authority = state.get_random_authority(msg.authority_id as usize).insecure_clone();

    // Resolve project from index
    if state.projects.is_empty() {
        debug_log!("Skipping fungible deposit: no projects");
        return Ok(());
    }
    let project_index = msg.project_index as usize % state.projects.len();
    let project = &state.projects[project_index];
    let project_id = project.project_id;
    let project_nonce = project.nonce;

    // Resolve currency from index
    if state.currency_tokens.is_empty() {
        debug_log!("Skipping fungible deposit: no currencies");
        return Ok(());
    }
    let currency_tokens: Vec<Pubkey> = state.currency_tokens.keys().cloned().collect();
    let currency_index = msg.currency_token_index as usize % currency_tokens.len();
    let currency_id = currency_tokens[currency_index];

    debug_log!("Attempting fungible deposit: token {} to project {}",
               currency_id, project_id);

    // Check currency type
    let currency_token = state.currency_tokens.get(&currency_id);
    if currency_token.is_none() {
        debug_log!("Currency token {} not found in state", currency_id);
        return Ok(());
    }
    let currency_token = currency_token.unwrap();

    // Skip if this is an NFT (only handle Native and Fungible)
    if matches!(currency_token.currency_type, crate::targets::full_svm::state::CurrencyType::NonFungible) {
        debug_log!("Skipping fungible deposit for NFT token {}", currency_id);
        return Ok(());
    }

    // Native tokens use Pubkey::default() (all zeros) as the mint
    let is_native = currency_id == Pubkey::default() || currency_id == spl_token::native_mint::ID ||
                    matches!(currency_token.currency_type, crate::targets::full_svm::state::CurrencyType::Native);

    // Currency token PDA
    let currency_token_pda = Pubkey::find_program_address(
        &[b"currency-token", currency_id.as_ref()],
        &PROGRAM_ID,
    ).0;

    // Project currency budget PDA
    let project_budget_pda = Pubkey::find_program_address(
        &[b"project-currency-budget", project_id.as_ref(), currency_token_pda.as_ref()],
        &PROGRAM_ID,
    ).0;

    let mut instructions = Vec::new();

    // For SPL tokens, ensure ATAs exist
    if !is_native {
        // Create authority ATA if needed
        let authority_ata = spl_associated_token_account::get_associated_token_address(&authority.pubkey(), &currency_id);
        if harness.svm.get_account(&authority_ata).is_none() {
            let create_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
                &authority.pubkey(),
                &authority.pubkey(),
                &currency_id,
                &spl_token::ID,
            );
            instructions.push(create_ata_ix);

            // Initialize with some tokens for testing
            // Get the mint authority (first authority is always the mint authority as per harness init)
            let mint_authority = &state.authority_keypairs[0];
            let mint_ix = spl_token::instruction::mint_to(
                &spl_token::ID,
                &currency_id,
                &authority_ata,
                &mint_authority.pubkey(),  // mint authority
                &[&mint_authority.pubkey()],
                1000,
            )?;
            instructions.push(mint_ix);
        }

        // Create project ATA if needed
        let project_ata = spl_associated_token_account::get_associated_token_address(&project_id, &currency_id);
        if harness.svm.get_account(&project_ata).is_none() {
            let create_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
                &authority.pubkey(),
                &project_id,
                &currency_id,
                &spl_token::ID,
            );
            instructions.push(create_ata_ix);
        }
    }

    // Build instruction data
    let mut data = get_anchor_discriminator("deposit_fungible_token").to_vec();
    data.extend_from_slice(&project_nonce.to_le_bytes());
    data.extend_from_slice(&msg.amount.to_le_bytes());

    // Build accounts
    let accounts = vec![
        AccountMeta::new_readonly(currency_id, false),     // token_mint
        AccountMeta::new(currency_token_pda, false),       // currency_token
        AccountMeta::new(authority.pubkey(), true),        // authority (signer)
        // authority_ata - PROGRAM_ID for native, actual ATA for SPL
        if is_native {
            AccountMeta::new_readonly(PROGRAM_ID, false)
        } else {
            let authority_ata = spl_associated_token_account::get_associated_token_address(&authority.pubkey(), &currency_id);
            AccountMeta::new(authority_ata, false)
        },
        AccountMeta::new(project_id, false),              // project
        // project_ata - PROGRAM_ID for native, actual ATA for SPL
        if is_native {
            AccountMeta::new_readonly(PROGRAM_ID, false)
        } else {
            let project_ata = spl_associated_token_account::get_associated_token_address(&project_id, &currency_id);
            AccountMeta::new(project_ata, false)
        },
        AccountMeta::new(project_budget_pda, false),      // project_currency_budget
        AccountMeta::new_readonly(system_program::ID, false),  // system_program
        AccountMeta::new_readonly(spl_token::ID, false),  // token_program
    ];

    let deposit_instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    };
    instructions.push(deposit_instruction);

    let deposit_ix_index = instructions.len() - 1; // Deposit is always last

    if !is_native && instructions.len() > 1 {
        // Setup instructions (create ATA, mint)
        let mint_authority = &state.authority_keypairs[0];

        // Process setup instructions one by one to handle different signer requirements
        for ix in instructions[0..deposit_ix_index].iter() {
            // Check if this instruction needs mint_authority as a signer
            let needs_mint_authority = ix.accounts.iter().any(|acc|
                acc.pubkey == mint_authority.pubkey() && acc.is_signer
            );

            let signers: Vec<&dyn Signer> = if needs_mint_authority {
                if authority.pubkey() == mint_authority.pubkey() {
                    vec![&authority]
                } else {
                    vec![&authority, mint_authority]
                }
            } else {
                vec![&authority]
            };

            let setup_tx = Transaction::new_signed_with_payer(
                &[ix.clone()],
                Some(&authority.pubkey()),
                &signers,
                harness.svm.latest_blockhash(),
            );

            let _ = crate::execute_transaction!(harness, setup_tx);
        }
    }

    // Now execute the deposit instruction
    let tx = Transaction::new_signed_with_payer(
        &[instructions[deposit_ix_index].clone()],
        Some(&authority.pubkey()),
        &[&authority],
        harness.svm.latest_blockhash(),
    );

    // Capture before state for INV-B2
    let before_balance = state.get_project_budget(&project_id, &currency_id);
    let budget_key = (project_id, currency_id);
    let before_total_deposited = state.project_budgets.get(&budget_key)
        .map(|b| b.total_deposited)
        .unwrap_or(0);

    // INV-A4: Capture currency active state
    let is_currency_active = currency_token.enabled;
    // INV-M*: Capture currency type for math invariants
    let currency_type = currency_token.currency_type.clone();

    let deposit_result = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        let budget_key = (project_id, currency_id);
        let budget = state.project_budgets.entry(budget_key)
            .or_insert(ProjectCurrencyBudget {
                project_id,
                currency_id,
                total_deposited: 0,
                total_claimed: 0,
                available_balance: 0,
            });
        budget.total_deposited = budget.total_deposited.saturating_add(msg.amount);
        budget.available_balance = budget.available_balance.saturating_add(msg.amount);
        debug_log!("Deposited {} tokens", msg.amount);

        // INV-B2: Check deposit increases budget by exact amount
        if let Err(violation) = check_deposit_increases_budget(
            state,
            &harness.svm,
            &project_id,
            &currency_id,
            msg.amount,
            before_balance,
            before_total_deposited,
        ) {
            violation.dump_and_abort();
        }

        // INV-B1: Check budget non-negativity after deposit
        if let Err(violation) = check_budget_non_negative(
            state,
            &harness.svm,
            "DepositFungibleToken",
            Some(&project_id),
            Some(&currency_id)
        ) {
            violation.dump_and_abort();
        }
    });

    let deposit_succeeded = deposit_result.is_ok();

    {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();

        // INV-X1: Check first deposit creates budget
        let budget_existed_before = before_total_deposited > 0;

        debug_log!("INV-X1 CHECK: First deposit creates budget - existed_before: {}, deposit_succeeded: {}",
                   budget_existed_before, deposit_succeeded);

        if !budget_existed_before && deposit_succeeded {
            debug_log!("INV-X1: Verifying first deposit created budget for project: {}, currency: {}",
                      project_id, currency_id);
            // Create a minimal state_before for the check
            let mut state_before = FullSvmState::default();

            if let Err(mut violation) = check_first_deposit_creates_budget(
                &state_before,
                state,
                &project_id,
                &currency_id,
                "DepositFungibleToken",
                deposit_succeeded,
            ) {
                debug_err!("INV-X1 VIOLATION DETECTED: {}", violation.details);
                if let Some(ref pb_data) = state.current_protobuf {
                    violation = violation.with_protobuf(pb_data.clone());
                }
                if let Some(seed) = state.current_seed {
                    violation = violation.with_seed(seed);
                }
                violation.dump_and_abort();
            } else {
                debug_log!("INV-X1 PASSED: First deposit correctly created budget");
            }

            // INV-X1: Check with on-chain verification
            debug_log!("INV-X1: Performing on-chain verification");
            if let Err(mut violation) = check_first_deposit_creates_budget_onchain(
                &harness.svm,
                &state_before,
                &project_id,
                &currency_id,
                "DepositFungibleToken",
                deposit_succeeded,
            ) {
                debug_err!("INV-X1 ON-CHAIN VIOLATION: {}", violation.details);
                if let Some(ref pb_data) = state.current_protobuf {
                    violation = violation.with_protobuf(pb_data.clone());
                }
                if let Some(seed) = state.current_seed {
                    violation = violation.with_seed(seed);
                }
                violation.dump_and_abort();
            } else {
                debug_log!("INV-X1 ON-CHAIN PASSED: Budget exists on-chain");
            }
        } else {
            debug_log!("INV-X1: Skipped - not a first deposit or deposit failed");
        }

        // INV-X3: Check zero amount rejection
        debug_log!("INV-X3 CHECK: Zero amount rejection for deposit - amount: {}, succeeded: {}",
                  msg.amount, deposit_succeeded);

        if let Err(mut violation) = check_zero_amount_rejection(
            msg.amount,
            "DepositFungibleToken",
            deposit_succeeded,
        ) {
            debug_err!("INV-X3 VIOLATION DETECTED: {}", violation.details);
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        } else {
            if msg.amount == 0 {
                debug_log!("INV-X3 PASSED: Zero amount deposit correctly rejected");
            } else {
                debug_log!("INV-X3 PASSED: Non-zero amount deposit handled correctly");
            }
        }

        // INV-A4: Check currency active requirement for deposit
        if let Err(mut violation) = check_currency_active_requirement(
            is_currency_active,
            "DepositFungibleToken",
            deposit_succeeded,
            "DepositFungibleToken"
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-M*: Check math invariants for deposit operation
        if deposit_succeeded {
            // Get updated budget
            let budget_after = state.get_project_budget(&project_id, &currency_id);

            // Check math invariants (deposits have no fees)
            if let Err(violation) = check_operation_math_invariants(
                state,
                "DepositFungibleToken",
                msg.amount,
                0, // No fee for deposits
                0, // No fee basis points for deposits
                &currency_type,
                Some(before_balance),
                Some(budget_after),
                "DepositFungibleToken"
            ) {
                let mut violation: InvariantViolation = violation;
                if let Some(ref pb_data) = state.current_protobuf {
                    violation = violation.with_protobuf(pb_data.clone());
                }
                if let Some(seed) = state.current_seed {
                    violation = violation.with_seed(seed);
                }
                violation.dump_and_abort();
            }

            // INV-M1: Check global conservation after successful deposit
            if let Err(violation) = check_global_conservation(
                state,
                &harness.svm,
                "DepositFungibleToken"
            ) {
                let mut violation: InvariantViolation = violation;
                if let Some(ref pb_data) = state.current_protobuf {
                    violation = violation.with_protobuf(pb_data.clone());
                }
                if let Some(seed) = state.current_seed {
                    violation = violation.with_seed(seed);
                }
                violation.dump_and_abort();
            }

            // INV-S1: Check budget exists after successful deposit
            if let Err(violation) = check_budget_exists_after_deposit(
                state,
                &harness.svm,
                &project_id,
                &currency_id,
                true, // deposit succeeded
                "DepositFungibleToken"
            ) {
                let mut violation: InvariantViolation = violation;
                if let Some(ref pb_data) = state.current_protobuf {
                    violation = violation.with_protobuf(pb_data.clone());
                }
                if let Some(seed) = state.current_seed {
                    violation = violation.with_seed(seed);
                }
                violation.dump_and_abort();
            }

            // INV-S4: Check currency exists for budget
            if let Err(mut violation) = check_currency_exists_for_budget(
                state,
                &project_id,
                &currency_id,
                "DepositFungibleToken"
            ) {
                if let Some(ref pb_data) = state.current_protobuf {
                    violation = violation.with_protobuf(pb_data.clone());
                }
                if let Some(seed) = state.current_seed {
                    violation = violation.with_seed(seed);
                }
                violation.dump_and_abort();
            }

            // INV-S5: Check currency type consistency
            if let Err(mut violation) = check_currency_type_consistency(
                state,
                &project_id,
                &currency_id,
                "DepositFungibleToken"
            ) {
                if let Some(ref pb_data) = state.current_protobuf {
                    violation = violation.with_protobuf(pb_data.clone());
                }
                if let Some(seed) = state.current_seed {
                    violation = violation.with_seed(seed);
                }
                violation.dump_and_abort();
            }
        }

    }

    Ok(())
}

// ============================================================================
// Claim Instruction
// ============================================================================

pub fn execute_claim_from_project_budget(
    harness: &mut HarnessBase,
    msg: &ClaimFromProjectBudget,
) -> Result<(), Box<dyn std::error::Error>> {

    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Get project using index
    if state.projects.is_empty() {
        debug_log!("Skiping claim: no projects available");
        return Ok(());
    }
    let project_index = msg.project_index as usize % state.projects.len();
    let project = &state.projects[project_index];
    let project_id = project.project_id;
    let project_nonce = project.nonce;

    // Get currency using index
    if state.currency_tokens.is_empty() {
        return Err("No currencies available".into());
    }
    let currencies: Vec<_> = state.currency_tokens.keys().cloned().collect();
    let currency_index = msg.currency_token_index as usize % currencies.len();
    let currency_id = currencies[currency_index];

    // Get currency info early so we can use it throughout the function
    let currency = state.currency_tokens.get(&currency_id)
        .ok_or("Currency not found")?;
    let currency_type = currency.currency_type.clone();

    // Check if budget exists for this project-currency combination
    if !state.project_budgets.contains_key(&(project_id, currency_id)) {
        debug_log!("Skipping claim: no budget exists for project {} and currency {}", project_id, currency_id);
        return Ok(());
    }

    // Get recipient from user keypairs
    if state.user_keypairs.is_empty() {
        return Err("No user keypairs available".into());
    }
    let recipient_index = msg.recipient_id as usize % state.user_keypairs.len();
    let recipient = state.user_keypairs[recipient_index].pubkey();

    // Get required number of signers from global config (always 1 currently)
    let required_signers = state.global_config.required_signers_for_claim as usize;
    debug_log!("[CLAIM] Required signers from config: {}", required_signers);

    // Collect signers that have GlobalRole::Signer
    let mut valid_signers = Vec::new();
    let mut checked_count = 0;
    for keypair in &state.authority_keypairs {
        checked_count += 1;
        if state.has_global_role(&keypair.pubkey(), GlobalRole::Signer) {
            valid_signers.push(keypair);
            debug_log!("[CLAIM] Found signer #{}: {}", valid_signers.len(), keypair.pubkey());
            if valid_signers.len() >= required_signers {
                break;
            }
        }
    }
    debug_log!("[CLAIM] Checked {} authorities, found {} with Signer role", checked_count, valid_signers.len());

    // Ensure we have enough signers
    if valid_signers.len() < required_signers {
        debug_err!("Not enough signers with GlobalRole::Signer. Required: {}, Available: {}", required_signers, valid_signers.len());
        return Err(format!("Not enough signers. Required: {}, Available: {}", required_signers, valid_signers.len()).into());
    }

    let primary_signer = valid_signers[0];

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    let currency_token_pda = Pubkey::find_program_address(
        &[b"currency-token", currency_id.as_ref()],
        &PROGRAM_ID,
    ).0;

    let project_budget_pda = Pubkey::find_program_address(
        &[b"project-currency-budget", project_id.as_ref(), currency_token_pda.as_ref()],
        &PROGRAM_ID,
    ).0;

    let project_user_pda = Pubkey::find_program_address(
        &[b"project-user", project_id.as_ref(), recipient.as_ref()],
        &PROGRAM_ID,
    ).0;

    // Project attribution PDA
    let mut proof = [0u8; 32];
    for (i, chunk) in proof.chunks_mut(4).enumerate() {
        let value = msg.proof_index.wrapping_mul((i as u32) + 1);
        chunk.copy_from_slice(&value.to_le_bytes()[..chunk.len()]);
    }

    let project_attribution_pda = Pubkey::find_program_address(
        &[b"project-attribution", project_id.as_ref(), &proof],
        &PROGRAM_ID,
    ).0;

    // Get fee collector from global config
    let fee_collector = state.global_config.fee_management.fee_collector;

    // Build instruction data for claim using proper Borsh serialization
    let mut data = get_anchor_discriminator("claim").to_vec();
    let ix_data = ClaimIx {
        project_nonce,
        proof,
    };
    data.extend_from_slice(&borsh::to_vec(&ix_data)?);

    // Determine if we need token accounts (only for SPL tokens, not for native)
    let is_native = currency_id == Pubkey::default() || currency_id == spl_token::native_mint::ID;

    // Build accounts list - for Option accounts, pass PROGRAM_ID when None (native tokens)
    let accounts = vec![
        AccountMeta::new(primary_signer.pubkey(), true),  // 0. authority (signer)
        AccountMeta::new(project_id, false),  // 1. project
        AccountMeta::new_readonly(global_config_address, false),  // 2. global_config
        AccountMeta::new_readonly(currency_id, false),  // 3. token_mint
        AccountMeta::new(fee_collector, false),  // 4. fee_collector
        // 5. fee_collector_ata (Option) - PROGRAM_ID for native, actual ATA for SPL
        if is_native {
            AccountMeta::new_readonly(PROGRAM_ID, false)
        } else {
            let fee_collector_ata = spl_associated_token_account::get_associated_token_address(&fee_collector, &currency_id);
            AccountMeta::new(fee_collector_ata, false)
        },
        AccountMeta::new(currency_token_pda, false),  // 6. currency_token
        // 7. project_ata (Option) - PROGRAM_ID for native, actual ATA for SPL
        if is_native {
            AccountMeta::new_readonly(PROGRAM_ID, false)
        } else {
            let project_ata = spl_associated_token_account::get_associated_token_address(&project_id, &currency_id);
            AccountMeta::new(project_ata, false)
        },
        AccountMeta::new(recipient, false),  // 8. recipient
        // 9. recipient_ata (Option) - PROGRAM_ID for native, actual ATA for SPL
        if is_native {
            AccountMeta::new_readonly(PROGRAM_ID, false)
        } else {
            let recipient_ata = spl_associated_token_account::get_associated_token_address(&recipient, &currency_id);
            AccountMeta::new(recipient_ata, false)
        },
        AccountMeta::new(project_budget_pda, false),  // 10. project_currency_budget
        AccountMeta::new(project_attribution_pda, false),  // 11. project_attribution
        AccountMeta::new(project_user_pda, false),  // 12. project_user
        AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),  // 13. instruction_sysvar
        AccountMeta::new_readonly(system_program::ID, false),  // 14. system_program
        AccountMeta::new_readonly(spl_token::ID, false),  // 15. token_program
        AccountMeta::new_readonly(spl_associated_token_account::ID, false),  // 16. associated_token_program
    ];

    // Build the claim instruction
    let claim_instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    };

    // We'll collect ATA creation instructions separately to ensure proper ordering
    let mut ata_instructions = vec![];
    if !is_native {
        // Create fee_collector ATA if needed
        let fee_collector_ata = spl_associated_token_account::get_associated_token_address(&fee_collector, &currency_id);
        if harness.svm.get_account(&fee_collector_ata).is_none() {
            let create_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
                &primary_signer.pubkey(),
                &fee_collector,
                &currency_id,
                &spl_token::ID,
            );
            ata_instructions.push(create_ata_ix);
        }

        // Create project ATA if needed
        let project_ata = spl_associated_token_account::get_associated_token_address(&project_id, &currency_id);
        if harness.svm.get_account(&project_ata).is_none() {
            let create_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
                &primary_signer.pubkey(),
                &project_id,
                &currency_id,
                &spl_token::ID,
            );
            ata_instructions.push(create_ata_ix);
        }

        // Create recipient ATA if needed
        let recipient_ata = spl_associated_token_account::get_associated_token_address(&recipient, &currency_id);
        if harness.svm.get_account(&recipient_ata).is_none() {
            let create_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
                &primary_signer.pubkey(),
                &recipient,
                &currency_id,
                &spl_token::ID,
            );
            ata_instructions.push(create_ata_ix);
        }
    }

    // Build ED25519 signature verification instruction
    // The claim expects a specific message format that includes the actual claim data

    #[derive(Clone, Copy)]
    #[repr(u8)]
    enum TokenType {
        Native = 0,
        FungibleSpl = 1,
        NonFungibleSpl = 2,
    }

    impl BorshSerialize for TokenType {
        fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let variant = match self {
                TokenType::Native => 0u8,
                TokenType::FungibleSpl => 1u8,
                TokenType::NonFungibleSpl => 2u8,
            };
            writer.write_all(&[variant])
        }
    }

    #[derive(Clone, Copy)]
    #[repr(u8)]
    enum ClaimReason {
        AffiliatePayout = 0,
        EndUserPayout = 1,
    }

    impl BorshSerialize for ClaimReason {
        fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let variant = match self {
                ClaimReason::AffiliatePayout => 0u8,
                ClaimReason::EndUserPayout => 1u8,
            };
            writer.write_all(&[variant])
        }
    }

    #[derive(BorshSerialize)]
    struct MessageDomain {
        program_id: Pubkey,
        version: u8,
        deadline: i64,
    }

    #[derive(BorshSerialize)]
    struct ClaimMessageData {
        amount: u64,
        project: Pubkey,
        recipient: Pubkey,
        token_type: TokenType,
        token_mint: Pubkey,
        proof: [u8; 32],
        reason: ClaimReason,
    }

    #[derive(BorshSerialize)]
    struct ClaimMessage {
        data: ClaimMessageData,
        domain: MessageDomain,
    }

    let token_type_value = match currency_type {
        crate::targets::full_svm::state::CurrencyType::Native => TokenType::Native,
        crate::targets::full_svm::state::CurrencyType::Fungible => TokenType::FungibleSpl,
        crate::targets::full_svm::state::CurrencyType::NonFungible => TokenType::NonFungibleSpl,
    };

    // Convert claim reason to enum value
    let reason_value = match msg.reason {
        0 => ClaimReason::AffiliatePayout,
        1 => ClaimReason::EndUserPayout,
        _ => ClaimReason::AffiliatePayout,  // Default to affiliate
    };

    // Use current time + 1 hour for deadline
    let deadline = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64 + 3600;

    let claim_msg = ClaimMessage {
        data: ClaimMessageData {
            amount: msg.amount,
            project: project_id,
            recipient,
            token_type: token_type_value,
            token_mint: currency_id,
            proof,
            reason: reason_value,
        },
        domain: MessageDomain {
            program_id: PROGRAM_ID,
            version: 1,
            deadline,
        },
    };

    let message_bytes = borsh::to_vec(&claim_msg)?;

    // Sign the message with all required signers
    let mut signatures = Vec::new();
    for signer_kp in &valid_signers {
        signatures.push(signer_kp.sign_message(&message_bytes));
    }

    // Build the ED25519 instruction with multiple signatures
    // Format: [num_signatures] [padding] [offsets per signature] [signatures] [pubkeys] [message]
    let mut ed25519_data = Vec::new();

    // Header
    ed25519_data.push(required_signers as u8); // number of signatures
    ed25519_data.push(0u8); // padding

    // Calculate offsets for each signature
    let header_len = 2 + (14 * required_signers); // 2 bytes header + 14 bytes per signature
    let signatures_start = header_len as u16;
    let pubkeys_start = signatures_start + (64 * required_signers) as u16;
    let message_start = pubkeys_start + (32 * required_signers) as u16;
    let message_len = message_bytes.len() as u16;

    // Write offsets for each signature
    for i in 0..required_signers {
        let sig_offset = signatures_start + (i * 64) as u16;
        let pubkey_offset = pubkeys_start + (i * 32) as u16;

        // Write 7 u16 values for this signature
        ed25519_data.extend_from_slice(&sig_offset.to_le_bytes());
        ed25519_data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // signature_instruction_index
        ed25519_data.extend_from_slice(&pubkey_offset.to_le_bytes());
        ed25519_data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // pubkey_instruction_index
        ed25519_data.extend_from_slice(&message_start.to_le_bytes());
        ed25519_data.extend_from_slice(&message_len.to_le_bytes());
        ed25519_data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // message_instruction_index
    }

    // Append all signatures (64 bytes each)
    for sig in &signatures {
        ed25519_data.extend_from_slice(sig.as_ref());
    }

    // Append all public keys (32 bytes each)
    for signer_kp in &valid_signers {
        ed25519_data.extend_from_slice(&signer_kp.pubkey().to_bytes());
    }

    // Append message once
    ed25519_data.extend_from_slice(&message_bytes);

    // Create the ED25519 instruction
    use std::str::FromStr;
    let ed25519_program_id = Pubkey::from_str("Ed25519SigVerify111111111111111111111111111").unwrap();
    let ed25519_instruction = Instruction {
        program_id: ed25519_program_id,
        accounts: vec![], // ED25519 program doesn't use accounts
        data: ed25519_data,
    };

    // Build final instruction list:
    // 1. First, add all ATA creation instructions (if any)
    // 2. Then ED25519 instruction immediately followed by claim instruction
    let mut instructions = Vec::new();
    instructions.extend(ata_instructions);  // Add ATA creations first
    instructions.push(ed25519_instruction); // ED25519 must be immediately before claim
    instructions.push(claim_instruction);    // Claim instruction right after ED25519

    // INV-B3 & INV-B5: Capture budget BEFORE the transaction executes
    // Read from STATE for normal invariants (they expect simulated state)
    let before_balance = state.get_project_budget(&project_id, &currency_id);

    // For INV-M5, we need the ACTUAL on-chain budget before the transaction
    let before_balance_onchain_for_m5 = read_project_budget_on_chain(
        &harness.svm,
        &project_id,
        &currency_id
    ).unwrap_or(0);

    debug_log!("INV-M5 Debug: before_balance_onchain = {}, before_balance_state = {}",
        before_balance_onchain_for_m5, before_balance);

    // Capture before_claimed for INV-B5
    let budget_key = (project_id, currency_id);
    let before_claimed = state.project_budgets.get(&budget_key)
        .map(|b| b.total_claimed)
        .unwrap_or(0);

    // INV-F4: Capture budget (available_balance) BEFORE the transaction
    let before_budget = state.project_budgets.get(&budget_key)
        .map(|b| b.available_balance)
        .unwrap_or(0);

    // INV-F4-ONCHAIN: Capture on-chain budget BEFORE the transaction
    let (_, _, before_budget_onchain) = read_on_chain_budget(&harness.svm, &project_id, &currency_id)
        .unwrap_or((0, 0, 0));

    // INV-C2: Capture attributions_count BEFORE the transaction
    let before_attributions_count = state.projects.get(project_index)
        .map(|p| p.attributions_count)
        .unwrap_or(0);

    // INV-C3: Capture total_claims (claim_count) BEFORE the transaction
    let user_key = (project_id, recipient);
    let before_claim_count = state.project_users.get(&user_key)
        .map(|u| u.claim_count)
        .unwrap_or(0);

    // INV-C4: Capture total_native_claimed BEFORE the transaction
    let before_native_claimed = state.project_users.get(&user_key)
        .map(|u| u.total_native_claimed)
        .unwrap_or(0);

    // Get the project fee for INV-B3 validation (must be captured before transaction)
    let project_fee_bp = state.get_project_claim_fee(project_index);

    // Determine if this is an NFT claim (NFTs have 0% fee)
    let actual_currency_type = state.currency_tokens.get(&currency_id)
        .map(|c| &c.currency_type)
        .unwrap_or(&crate::targets::full_svm::state::CurrencyType::Fungible);
    let is_nft_claim = matches!(actual_currency_type, crate::targets::full_svm::state::CurrencyType::NonFungible);

    // INV-A2: Capture signer count before closure to avoid borrow conflicts
    let valid_signers_count = valid_signers.len() as u8;

    // INV-R3: Capture rate limits BEFORE the claim for cooldown reset verification
    let (before_cumulative, before_period_started) =
        capture_rate_limits_before_claim(&harness.svm, &currency_id)
            .unwrap_or((0, 0));

    // Get current timestamp for cooldown calculations
    let current_timestamp = harness.svm.get_sysvar::<solana_sdk::clock::Clock>().unix_timestamp;

    // INV-A3: Capture pause state before transaction
    let is_paused = state.global_config.paused;

    // INV-A4: Capture currency active state before transaction
    let is_currency_active = currency.enabled;


    // INV-T2: Capture cooldown state before transaction
    let old_cooldown_started = currency.claim_cooldown_period_started;
    let old_cumulative = currency.cumulative_claim_per_cooldown;

    // Create transaction with all instructions
    let tx_signer = valid_signers[0];
    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&tx_signer.pubkey()),
        &[tx_signer],
        harness.svm.latest_blockhash(),
    );

    // Variable to hold budget_after for INV-M5 check
    let mut budget_after_for_inv_m5 = 0u64;

    let claim_result = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();

        // Update budget
        // The budget must be decreased by both the claim amount and the project fee
        //   total_to_deduct = claim.data.amount + project_claim_fee_amount
        //   budget = budget.checked_sub(total_to_deduct)
        //
        // Calculate the project fee using the same formula as the Solana program
        const BASIS_POINTS: u64 = 10000;
        let project_fee = if is_nft_claim {
            // NFTs have 0% project fee
            0
        } else {
            // Fee calculation: (amount * fee_bp) / 10000
            let calculated = msg.amount
                .saturating_mul(project_fee_bp as u64)
                .saturating_div(BASIS_POINTS);
            debug_log!("INV-M5 Debug: Fee calculation: {} * {} / 10000 = {}",
                msg.amount, project_fee_bp, calculated);
            calculated
        };

        // INV-F2: Verify fee calculation is correct (only for non-NFT claims)
        if !is_nft_claim {
            if let Err(mut violation) = check_fee_calculation_after_claim(
                msg.amount,
                project_fee_bp,
                project_fee,
            ) {
                if let Some(ref pb_data) = state.current_protobuf {
                    violation = violation.with_protobuf(pb_data.clone());
                }
                if let Some(seed) = state.current_seed {
                    violation = violation.with_seed(seed);
                }
                violation.dump_and_abort();
            }
        }

        // Total deduction = claim amount + project fee
        let total_deduction = msg.amount.saturating_add(project_fee);

        debug_log!("INV-M5 Debug: msg.amount = {}, project_fee = {}, total_deduction = {}",
            msg.amount, project_fee, total_deduction);

        // Read the actual on-chain budget after the transaction
        budget_after_for_inv_m5 = read_project_budget_on_chain(
            &harness.svm,
            &project_id,
            &currency_id
        ).unwrap_or(0);

        debug_log!("INV-M5 Debug: budget_after_onchain = {}, total_deduction = {}",
            budget_after_for_inv_m5, total_deduction);

        if let Some(budget) = state.project_budgets.get_mut(&(project_id, currency_id)) {
            // Deduct both amount and fee from available balance
            budget.available_balance = budget.available_balance.saturating_sub(total_deduction);
            // Only the claim amount counts toward total_claimed (fees go to fee collector)
            budget.total_claimed = budget.total_claimed.saturating_add(msg.amount);
        }

        // INV-F4: Get budget after update and verify fee source
        let after_budget = state.project_budgets.get(&(project_id, currency_id))
            .map(|b| b.available_balance)
            .unwrap_or(0);

        // INV-F4: Verify project fee comes from budget (budget_decrease = amount + fee)
        if let Err(mut violation) = check_project_fee_source_after_claim(
            before_budget,
            after_budget,
            msg.amount,
            project_fee,
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-F4-ONCHAIN: Verify on-chain budget decreased correctly
        debug_log!("INV-F4-ONCHAIN: Checking with project_fee={}, amount={}, before_budget_onchain={}",
            project_fee, msg.amount, before_budget_onchain);
        if let Err(mut violation) = check_project_fee_source_on_chain(
            &harness.svm,
            &project_id,
            &currency_id,
            before_budget_onchain,
            msg.amount,
            project_fee,
            "Claim",
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // Update user tracking
        let user_key = (project_id, recipient);
        let project_user = state.project_users.entry(user_key)
            .or_insert(ProjectUser {
                project_id,
                user_id: recipient,
                total_claimed: 0,
                last_claim_timestamp: 0,
                claim_count: 0,
                total_native_claimed: 0,
            });
        project_user.total_claimed = project_user.total_claimed.saturating_add(msg.amount);
        project_user.claim_count += 1;
        // INV-C4: Update total_native_claimed only for native token claims
        let is_native_claim = matches!(currency_type, crate::targets::full_svm::state::CurrencyType::Native);
        if is_native_claim {
            project_user.total_native_claimed = project_user.total_native_claimed.saturating_add(msg.amount);
        }

        // INV-X4: Track native fee for whitelist check
        let user_native_claim_fee = state.get_user_native_claim_fee(project_index);
        let is_whitelisted = state.global_config.fee_management.no_claim_fee_whitelist
            .contains(&recipient);
        // If whitelisted, they should pay 0, otherwise they pay the fee
        let expected_native_fee_charged = if is_whitelisted { 0 } else { user_native_claim_fee };

        // Mark proof as used
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(project_id.as_ref());  // Include project_id
        hasher.update(&proof);
        let proof_hash = hasher.finalize();
        state.project_attributions.insert(proof_hash.into());

        // INV-A1: Verify proof is now marked as used on-chain (replay protection)
        if let Err(mut violation) = check_proof_after_claim(
            state,
            &harness.svm,
            &project_id,
            &proof,
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-A2: Verify multi-sig requirement was enforced
        if let Err(mut violation) = check_multisig_requirement(
            valid_signers_count,
            required_signers as u8,
            true, // claim succeeded
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // Update project's attributions_count
        if let Some(project) = state.projects.get_mut(project_index) {
            project.attributions_count += 1;
        }

        // INV-S2: Track attribution count per project for consistency verification
        *state.project_attribution_counts.entry(project_id).or_insert(0) += 1;

        // INV-S3: Track claim count per user per project for consistency verification
        *state.user_claim_counts.entry((project_id, recipient)).or_insert(0) += 1;

        debug_log!("CLAIM SUCCESS: {} claimed from project", msg.amount);

        // Calculate the project fee for conservation check
        let project_fee = if is_nft_claim {
            0  // NFTs have no project fee
        } else {
            (msg.amount as u128 * project_fee_bp as u128 / 10000) as u64
        };

        // INV-B3: Check claim decreased budget by exactly the right amount
        // This validates:
        // 1. Fee calculated correctly: fee = (amount * fee_bp) / 10000
        // 2. Budget decreased by: amount + fee
        // 3. Special case: NFTs have 0% fee
        if let Err(mut violation) = check_claim_decreases_budget_correctly(
            state,
            &harness.svm,
            &project_id,
            &currency_id,
            msg.amount,
            project_fee_bp,
            before_balance,
            is_nft_claim
        ) {
            // Attach protobuf and seed for crash reproduction
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-B5: Check conservation of funds during claim
        // Verify: budget_decrease = recipient_amount + project_fee
        let after_balance = state.get_project_budget(&project_id, &currency_id);
        let budget_decrease = before_balance.saturating_sub(after_balance);

        if let Err(mut violation) = check_claim_conservation_of_funds(
            state,
            &harness.svm,
            &project_id,
            &currency_id,
            budget_decrease,
            msg.amount,  // recipient receives the full claim amount
            project_fee, // fee goes to fee collector
            before_balance,
            before_claimed,
        ) {
            // Attach protobuf and seed for crash reproduction
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-B1: Check budget non-negativity after claim
        if let Err(mut violation) = check_budget_non_negative(
            state,
            &harness.svm,
            "ClaimFromProjectBudget",
            Some(&project_id),
            Some(&currency_id)
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-C2: Check attributions_count increased by exactly 1
        if let Err(mut violation) = check_attributions_after_claim(
            state,
            &harness.svm,
            project_index,
            before_attributions_count,
        ) {
            // Attach protobuf and seed for crash reproduction
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-S2: Check attribution count consistency (total matches tracked)
        if let Err(mut violation) = check_attribution_count_consistency(
            state,
            &project_id,
            "Claim",
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-S2 ON-CHAIN: Verify attribution count matches on-chain
        if let Err(mut violation) = check_attribution_count_consistency_onchain(
            &harness.svm,
            state,
            &project_id,
            "Claim",
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-S3: Check user claim count consistency (total matches tracked)
        if let Err(mut violation) = check_user_claims_consistency(
            state,
            &project_id,
            &recipient,
            "Claim",
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-S3: Verify user claim count matches
        if let Err(mut violation) = check_user_claims_consistency_onchain(
            &harness.svm,
            state,
            &project_id,
            &recipient,
            "Claim",
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-C3: Check total_claims (claim_count) increased by 1
        if let Err(mut violation) = check_total_claims_after_claim(
            state,
            &harness.svm,
            &project_id,
            &recipient,
            before_claim_count,
        ) {
            // Attach protobuf and seed for crash reproduction
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-C4: Check total_native_claimed
        let is_native_for_invariant = matches!(currency_type, crate::targets::full_svm::state::CurrencyType::Native);
        if let Err(mut violation) = check_total_native_claimed_after_claim(
            state,
            &harness.svm,
            &project_id,
            &recipient,
            before_native_claimed,
            msg.amount,
            is_native_for_invariant,
        ) {
            // Attach protobuf and seed for crash reproduction
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // ========== RATE LIMITING INVARIANTS ==========

        // INV-R1: Verify cumulative claims never exceed limit
        if let Err(mut violation) = check_cumulative_within_limit(
            state,
            &harness.svm,
            &currency_id,
            "Claim",
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-R2: Verify single claim doesn't exceed limit
        if let Err(mut violation) = check_claim_amount_within_limit(
            state,
            &harness.svm,
            &currency_id,
            msg.amount,
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-R3: Verify cooldown reset behavior is correct
        if let Err(mut violation) = check_cooldown_reset_behavior(
            state,
            &harness.svm,
            &currency_id,
            msg.amount,
            before_cumulative,
            before_period_started,
            current_timestamp,
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }
    });

    // Check if transaction succeeded
    let claim_succeeded = claim_result.is_ok();

    // INV-A3: Check pause enforcement
    if let Err(mut violation) = check_pause_enforcement(
        is_paused,
        claim_succeeded,
        "ClaimFromProjectBudget"
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

    // INV-A3-SYNC: Verify pause state consistency
    if let Err(mut violation) = verify_pause_state_consistency(
        &harness.svm,
        is_paused,
        "ClaimFromProjectBudget"
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

    // INV-A4: Check currency active requirement
    if let Err(mut violation) = check_currency_active_requirement(
        is_currency_active,
        "ClaimFromProjectBudget",
        claim_succeeded,
        "ClaimFromProjectBudget"
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

    // INV-A4-SYNC: Verify currency active state consistency
    if let Err(mut violation) = verify_currency_active_consistency(
        &harness.svm,
        &currency_id,
        is_currency_active,
        "ClaimFromProjectBudget"
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

    // INV-T1, T2, T3, T4: Check all timing invariants
    {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();

        // INV-T1: Check deadline not expired
        let current_time = get_clock_time_on_chain(&harness.svm)
            .unwrap_or_else(|_| std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64);

        if let Err(mut violation) = check_message_deadline_not_expired(
            deadline,
            current_time,
            claim_succeeded,
            "ClaimFromProjectBudget"
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-T2: Check cooldown calculation (only if claim succeeded)
        if claim_succeeded {
            if let Ok((new_cooldown_started, new_cumulative, _)) =
                verify_cooldown_state_on_chain(&harness.svm, &currency_id) {

                let cooldown_duration = state.global_config.claim_cooldown;

                if let Err(mut violation) = check_cooldown_period_calculation(
                    old_cooldown_started,
                    cooldown_duration,
                    current_time,
                    old_cumulative,
                    new_cumulative,
                    msg.amount,
                    "ClaimFromProjectBudget"
                ) {
                    if let Some(ref pb_data) = state.current_protobuf {
                        violation = violation.with_protobuf(pb_data.clone());
                    }
                    if let Some(seed) = state.current_seed {
                        violation = violation.with_seed(seed);
                    }
                    violation.dump_and_abort();
                }

                // INV-T3: Check timestamp monotonicity
                if new_cooldown_started != old_cooldown_started {
                    if let Err(mut violation) = check_timestamps_monotonic(
                        old_cooldown_started,
                        new_cooldown_started,
                        "claim_cooldown_period_started",
                        "ClaimFromProjectBudget"
                    ) {
                        if let Some(ref pb_data) = state.current_protobuf {
                            violation = violation.with_protobuf(pb_data.clone());
                        }
                        if let Some(seed) = state.current_seed {
                            violation = violation.with_seed(seed);
                        }
                        violation.dump_and_abort();
                    }
                }
            }

            // INV-T4: Check attribution timestamp accuracy
            if let Ok(Some(attribution_timestamp)) =
                read_attribution_timestamp_on_chain(&harness.svm, &project_id, &proof) {

                // Get the actual current time after the claim
                let post_claim_time = harness.svm.get_sysvar::<solana_sdk::clock::Clock>().unix_timestamp;

                // Allow up to 60 seconds of drift (accounting for block time variations)
                if let Err(mut violation) = check_attribution_timestamp_accuracy(
                    attribution_timestamp,
                    post_claim_time,
                    60, // max_drift in seconds
                    "ClaimFromProjectBudget"
                ) {
                    if let Some(ref pb_data) = state.current_protobuf {
                        violation = violation.with_protobuf(pb_data.clone());
                    }
                    if let Some(seed) = state.current_seed {
                        violation = violation.with_seed(seed);
                    }
                    violation.dump_and_abort();
                }
            }
        }

        // INV-X3: Not checked for claims - protocol allows zero-amount claims
        debug_log!("INV-X3 NOTE: Zero-amount claims are ALLOWED by protocol (amount: {})", msg.amount);

        // INV-X4: Check whitelist fee bypass
        let is_native_for_x4 = matches!(currency_type, crate::targets::full_svm::state::CurrencyType::Native);

        debug_log!("INV-X4 CHECK: Whitelist fee bypass - is_native: {}, succeeded: {}",
                  is_native_for_x4, claim_succeeded);

        if claim_succeeded && is_native_for_x4 {
            // Re-calculate these values since we're in a different scope
            let user_native_fee = state.get_user_native_claim_fee(project_index);
            let is_whitelisted = state.global_config.fee_management.no_claim_fee_whitelist
                .contains(&recipient);
            let expected_fee = if is_whitelisted { 0 } else { user_native_fee };

            debug_log!("INV-X4: Checking fee for recipient {} - whitelisted: {}, native_fee: {}, expected: {}",
                      recipient, is_whitelisted, user_native_fee, expected_fee);

            let actual_fee_charged = expected_fee;

            if let Err(mut violation) = check_whitelist_fee_bypass(
                &recipient,
                &state.global_config.fee_management.no_claim_fee_whitelist,
                actual_fee_charged,
                user_native_fee,
            ) {
                debug_err!("INV-X4 VIOLATION DETECTED: {}", violation.details);
                if let Some(ref pb_data) = state.current_protobuf {
                    violation = violation.with_protobuf(pb_data.clone());
                }
                if let Some(seed) = state.current_seed {
                    violation = violation.with_seed(seed);
                }
                violation.dump_and_abort();
            } else {
                debug_log!("INV-X4 PASSED: Whitelist fee bypass working correctly");
            }
        } else {
            debug_log!("INV-X4: Skipped - not a successful native claim");
        }

        // INV-X5: Check message domain validation
        debug_log!("INV-X5 CHECK: Message domain validation - checking program_id and version");

        if let Err(mut violation) = check_message_domain_validation(
            &PROGRAM_ID, 
            1,
            &PROGRAM_ID,
            1,
            "ClaimFromProjectBudget",
            claim_succeeded,
        ) {
            debug_err!("INV-X5 VIOLATION DETECTED: {}", violation.details);
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        } else {
            debug_log!("INV-X5 PASSED: Message domain validation correct");
        }

        // INV-M*: Check math invariants for claim operation
        if claim_succeeded {
            // Calculate fee amount
            let fee_basis_points = state.get_project_claim_fee(project_index);

            // For NFT claims, project fee must be 0
            let calculated_fee = if matches!(currency_type, crate::targets::full_svm::state::CurrencyType::NonFungible) {
                0
            } else {
                // Use protocol's exact formula: (amount * fee_bp) / 10000
                msg.amount.saturating_mul(fee_basis_points as u64) / 10000
            };

            // Get updated budget
            let budget_after = state.get_project_budget(&project_id, &currency_id);

            // Check math invariants
            if let Err(violation) = check_operation_math_invariants(
                state,
                "Claim",
                msg.amount,
                calculated_fee,
                fee_basis_points,
                &currency_type,
                Some(before_balance),
                Some(budget_after),
                "ClaimFromProjectBudget"
            ) {
                let mut violation: InvariantViolation = violation;
                if let Some(ref pb_data) = state.current_protobuf {
                    violation = violation.with_protobuf(pb_data.clone());
                }
                if let Some(seed) = state.current_seed {
                    violation = violation.with_seed(seed);
                }
                violation.dump_and_abort();
            }

            // INV-M5: Specifically check claim budget deduction
            if let Err(violation) = check_claim_budget_deduction(
                msg.amount,
                calculated_fee,
                before_balance_onchain_for_m5,
                budget_after_for_inv_m5,
                "ClaimFromProjectBudget"
            ) {
                let mut violation: InvariantViolation = violation;
                if let Some(ref pb_data) = state.current_protobuf {
                    violation = violation.with_protobuf(pb_data.clone());
                }
                if let Some(seed) = state.current_seed {
                    violation = violation.with_seed(seed);
                }
                violation.dump_and_abort();
            }

            // INV-M1: Check global conservation after successful claim
            if let Err(violation) = check_global_conservation(
                state,
                &harness.svm,
                "ClaimFromProjectBudget"
            ) {
                let mut violation: InvariantViolation = violation;
                if let Some(ref pb_data) = state.current_protobuf {
                    violation = violation.with_protobuf(pb_data.clone());
                }
                if let Some(seed) = state.current_seed {
                    violation = violation.with_seed(seed);
                }
                violation.dump_and_abort();
            }
        }
    }

    Ok(())
}

// ============================================================================
// Role Management Instructions
// ============================================================================

pub fn execute_grant_global_role(
    harness: &mut HarnessBase,
    msg: &GrantGlobalRole,
) -> Result<(), Box<dyn std::error::Error>> {

    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Find an admin
    let admin = state.global_config.roles_mapping.roles.iter()
        .find(|entry| entry.role == GlobalRole::Admin)
        .and_then(|entry| {
            state.authority_keypairs.iter()
                .find(|kp| kp.pubkey() == entry.account)
        })
        .ok_or("No admin keypair found")?
        .insecure_clone();

    let account = state.get_random_authority(msg.account_id as usize).pubkey();

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    let mut data = get_anchor_discriminator("grant_global_role").to_vec();
    let ix_data = GrantGlobalRoleIx {
        account,
        role: msg.role() as u8,
    };
    data.extend_from_slice(&borsh::to_vec(&ix_data)?);

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),  // authority - signer and mutable
            AccountMeta::new(global_config_address, false),  // global_config - mutable
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&admin.pubkey()),
        &[&admin],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        let role = match msg.role() {
            ProtoGlobalRole::Admin => GlobalRole::Admin,
            ProtoGlobalRole::Pauser => GlobalRole::Pauser,
            ProtoGlobalRole::Unpauser => GlobalRole::Unpauser,
            ProtoGlobalRole::Signer => GlobalRole::Signer,
        };
        state.grant_global_role(account, role);
        debug_log!("Granted global role to {}", account);
    });

    Ok(())
}

pub fn execute_grant_project_role(
    harness: &mut HarnessBase,
    msg: &GrantProjectRole,
) -> Result<(), Box<dyn std::error::Error>> {

    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    if state.projects.is_empty() {
        return Err("No projects available".into());
    }
    let project_index = (msg.project_index as usize) % state.projects.len();

    let project = &state.projects[project_index];
    let project_id = project.project_id;

    let admin_entry = project.roles_mapping.roles.iter()
        .find(|entry| entry.role == ProjectRole::Admin)
        .ok_or("No project admin role found in project")?;

    let admin = state.authority_keypairs.iter()
        .find(|kp| kp.pubkey() == admin_entry.account)
        .ok_or_else(|| {
            debug_log!("ERROR: Project admin {} not in authority_keypairs", admin_entry.account);
            "Project admin keypair not found in authority_keypairs"
        })?
        .insecure_clone();

    let account = state.get_random_authority(msg.account_id as usize).pubkey();

    let mut data = get_anchor_discriminator("grant_project_role").to_vec();
    let ix_data = GrantProjectRoleIx {
        project_nonce: project.nonce,
        account,
        role: msg.role() as u8,
    };
    data.extend_from_slice(&borsh::to_vec(&ix_data)?);

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),  // authority - signer and mutable
            AccountMeta::new(project_id, false),     // project - mutable
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&admin.pubkey()),
        &[&admin],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        let project_index = (msg.project_index as usize) % state.projects.len();
        state.grant_project_role(project_index, account, ProjectRole::Admin);
        debug_log!("Granted project role to {}", account);
    });

    Ok(())
}

// ============================================================================
// Additional Transaction Handlers
// ============================================================================

pub fn execute_update_global_config_fees(
    harness: &mut HarnessBase,
    msg: &UpdateGlobalConfigFees,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Get admin authority
    let authority = state.get_authority_with_role(
        crate::targets::full_svm::state::GlobalRole::Admin,
        msg.authority_id as usize
    ).insecure_clone();

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    let mut data = get_anchor_discriminator("update_global_config_fees").to_vec();

    #[derive(BorshSerialize, BorshDeserialize)]
    struct UpdateGlobalConfigFeesIx {
        fee_collector: Option<Pubkey>,
        user_native_claim_fee: Option<u64>,
        project_claim_fee: Option<u16>,
        remove_fee: Option<u16>,
    }

    let ix_data = UpdateGlobalConfigFeesIx {
        fee_collector: None,  // Not updating fee collector
        user_native_claim_fee: msg.user_native_claim_fee,  // Option from protobuf
        project_claim_fee: msg.project_claim_fee.map(|f| f as u16),  // Convert u32 to u16
        remove_fee: msg.remove_fee.map(|f| f as u16),  // Convert u32 to u16
    };
    data.extend_from_slice(&borsh::to_vec(&ix_data)?);

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),  // authority - signer and mutable
            AccountMeta::new(global_config_address, false),  // global_config - mutable
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&authority.pubkey()),
        &[&authority],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        if let Some(fee) = msg.user_native_claim_fee {
            state.global_config.fee_management.user_native_claim_fee = fee;
        }
        if let Some(fee) = msg.project_claim_fee {
            state.global_config.fee_management.project_claim_fee = fee as u16;
        }
        if let Some(fee) = msg.remove_fee {
            state.global_config.fee_management.remove_fee = fee as u16;
        }
        debug_log!("Global config fees updated");

        // INV-F1: Verify all fee basis points are within valid range (0-10000)
        if let Err(mut violation) = check_fee_range_after_global_update(state) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-F1: Verify fees match our tracking
        let project_ids: Vec<Pubkey> = state.projects.iter().map(|p| p.project_id).collect();
        if let Err(mut violation) = check_fee_bp_range_on_chain(&harness.svm, "UpdateGlobalConfigFees", &project_ids) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }
    });

    Ok(())
}

pub fn execute_pause_program(
    harness: &mut HarnessBase,
    msg: &PauseProgram,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Get authority with Pauser role
    let authority = state.get_authority_with_role(
        crate::targets::full_svm::state::GlobalRole::Pauser,
        msg.authority_id as usize
    ).insecure_clone();

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    // Build instruction data
    let data = get_anchor_discriminator("pause_program").to_vec();

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),  // authority - signer and mutable
            AccountMeta::new(global_config_address, false),  // global_config - mutable
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&authority.pubkey()),
        &[&authority],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        state.global_config.paused = true;
        debug_log!("Program paused");
    });

    Ok(())
}

pub fn execute_unpause_program(
    harness: &mut HarnessBase,
    msg: &UnpauseProgram,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Get authority with Unpauser role
    let authority = state.get_authority_with_role(
        crate::targets::full_svm::state::GlobalRole::Unpauser,
        msg.authority_id as usize
    ).insecure_clone();

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    // Build instruction data
    let data = get_anchor_discriminator("unpause_program").to_vec();

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),  // authority - signer and mutable
            AccountMeta::new(global_config_address, false),  // global_config - mutable
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&authority.pubkey()),
        &[&authority],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        state.global_config.paused = false;
        debug_log!("Program unpaused");
    });

    Ok(())
}

pub fn execute_add_no_claim_fee_whitelist(
    harness: &mut HarnessBase,
    msg: &AddNoClaimFeeWhitelist,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Get admin authority with Admin role
    let authority = state.get_authority_with_role(
        crate::targets::full_svm::state::GlobalRole::Admin,
        msg.authority_id as usize
    ).insecure_clone();
    let account = state.get_random_user(msg.user_id as usize).pubkey();

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    // Build instruction data
    let mut data = get_anchor_discriminator("add_no_claim_fee_whitelist").to_vec();
    data.extend_from_slice(account.as_ref());

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(authority.pubkey(), true),  // 0. authority (signer)
            AccountMeta::new(global_config_address, false),        // 1. global_config
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&authority.pubkey()),
        &[&authority],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        state.global_config.fee_management.no_claim_fee_whitelist.push(account);
        debug_log!("Added {} to no claim fee whitelist", account);
    });

    Ok(())
}

pub fn execute_remove_no_claim_fee_whitelist(
    harness: &mut HarnessBase,
    msg: &RemoveNoClaimFeeWhitelist,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Get admin authority with Admin role
    let authority = state.get_authority_with_role(
        crate::targets::full_svm::state::GlobalRole::Admin,
        msg.authority_id as usize
    ).insecure_clone();
    let account = state.get_random_user(msg.user_id as usize).pubkey();

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    // Build instruction data using proper Borsh serialization
    let mut data = get_anchor_discriminator("remove_no_claim_fee_whitelist").to_vec();
    let ix_data = RemoveNoClaimFeeWhitelistIx {
        account,
    };
    data.extend_from_slice(&borsh::to_vec(&ix_data)?);

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),  // authority - signer and mutable
            AccountMeta::new(global_config_address, false),  // global_config - mutable
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&authority.pubkey()),
        &[&authority],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        state.global_config.fee_management.no_claim_fee_whitelist.retain(|&a| a != account);
        debug_log!("Removed {} from no claim fee whitelist", account);
    });

    Ok(())
}

pub fn execute_revoke_global_role(
    harness: &mut HarnessBase,
    msg: &RevokeGlobalRole,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Get admin authority with Admin role
    let authority = state.get_authority_with_role(
        crate::targets::full_svm::state::GlobalRole::Admin,
        msg.authority_id as usize
    ).insecure_clone();
    let account = state.get_random_authority(msg.account_id as usize).pubkey();

    // Convert proto role to state role
    let role = match msg.role() {
        ProtoGlobalRole::Admin => GlobalRole::Admin,
        ProtoGlobalRole::Pauser => GlobalRole::Pauser,
        ProtoGlobalRole::Unpauser => GlobalRole::Unpauser,
        ProtoGlobalRole::Signer => GlobalRole::Signer,
    };

    // Check if account has the role before attempting to revoke
    let has_role = state.global_config.roles_mapping.roles.iter()
        .any(|entry| entry.account == account && entry.role == role);

    if !has_role {
        debug_log!("Skipping revoke: account {} doesn't have role {:?} (current roles: {:?})",
            account, role,
            state.global_config.roles_mapping.roles.iter()
                .filter(|e| e.account == account)
                .map(|e| &e.role)
                .collect::<Vec<_>>()
        );
        return Ok(());
    }

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    // Build instruction data with role
    let mut data = get_anchor_discriminator("revoke_global_role").to_vec();
    data.extend_from_slice(account.as_ref());
    // Add role enum value
    let role_byte = match msg.role() {
        ProtoGlobalRole::Admin => 0u8,
        ProtoGlobalRole::Pauser => 1u8,
        ProtoGlobalRole::Unpauser => 2u8,
        ProtoGlobalRole::Signer => 3u8,
    };
    data.push(role_byte);

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),  // 0. authority (signer)
            AccountMeta::new(global_config_address, false),  // 1. global_config
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&authority.pubkey()),
        &[&authority],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        let role = match msg.role() {
            ProtoGlobalRole::Admin => GlobalRole::Admin,
            ProtoGlobalRole::Pauser => GlobalRole::Pauser,
            ProtoGlobalRole::Unpauser => GlobalRole::Unpauser,
            ProtoGlobalRole::Signer => GlobalRole::Signer,
        };
        state.revoke_global_role(&account, &role);
        debug_log!("Revoked global role from {}", account);
    });

    Ok(())
}

pub fn execute_renounce_global_role(
    harness: &mut HarnessBase,
    msg: &RenounceGlobalRole,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // The renouncer is the authority themselves
    let authority = state.get_random_authority(msg.authority_id as usize).insecure_clone();

    // INV-X2: Count admins before the operation
    let is_renouncing_admin = matches!(msg.role(), ProtoGlobalRole::Admin);
    let admin_count_before = if is_renouncing_admin {
        state.global_config.roles_mapping.roles
            .iter()
            .filter(|entry| matches!(entry.role, GlobalRole::Admin))
            .count()
    } else {
        0
    };

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    // Build instruction data with role
    let mut data = get_anchor_discriminator("renounce_global_role").to_vec();
    // Add role enum value
    let role_byte = match msg.role() {
        ProtoGlobalRole::Admin => 0u8,
        ProtoGlobalRole::Pauser => 1u8,
        ProtoGlobalRole::Unpauser => 2u8,
        ProtoGlobalRole::Signer => 3u8,
    };
    data.push(role_byte);

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),  // authority - signer and mutable
            AccountMeta::new(global_config_address, false),  // global_config - mutable
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&authority.pubkey()),
        &[&authority],
        harness.svm.latest_blockhash(),
    );

    let tx_result = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        let role = match msg.role() {
            ProtoGlobalRole::Admin => GlobalRole::Admin,
            ProtoGlobalRole::Pauser => GlobalRole::Pauser,
            ProtoGlobalRole::Unpauser => GlobalRole::Unpauser,
            ProtoGlobalRole::Signer => GlobalRole::Signer,
        };
        state.revoke_global_role(&authority.pubkey(), &role);
        debug_log!("{} renounced global role", authority.pubkey());
    });

    let renounce_succeeded = tx_result.is_ok();

    // INV-X2: Check last admin protection
    debug_log!("INV-X2 CHECK: Last admin protection - is_admin: {}, admin_count: {}, succeeded: {}",
              is_renouncing_admin, admin_count_before, renounce_succeeded);

    if is_renouncing_admin {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();

        debug_log!("INV-X2: Checking if last admin can renounce (count before: {})", admin_count_before);

        if let Err(mut violation) = check_last_admin_protection(
            admin_count_before,
            "RenounceGlobalRole",
            renounce_succeeded,
            "global"
        ) {
            debug_err!("INV-X2 VIOLATION DETECTED: {}", violation.details);
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        } else {
            debug_log!("INV-X2 PASSED: Last admin protection working correctly");
        }

        // Also check on-chain
        debug_log!("INV-X2: Performing on-chain verification");
        if let Err(mut violation) = check_last_admin_protection_global_onchain(
            &harness.svm,
            "RenounceGlobalRole",
            renounce_succeeded,
        ) {
            debug_err!("INV-X2 ON-CHAIN VIOLATION: {}", violation.details);
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        } else {
            debug_log!("INV-X2 ON-CHAIN PASSED: Admin protection verified on-chain");
        }
    } else {
        debug_log!("INV-X2: Skipped - not renouncing admin role");
    }

    Ok(())
}

pub fn execute_update_currency_token(
    harness: &mut HarnessBase,
    msg: &UpdateCurrencyToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Get admin authority with Admin role
    let authority = state.get_authority_with_role(
        crate::targets::full_svm::state::GlobalRole::Admin,
        msg.authority_id as usize
    ).insecure_clone();

    // Get an existing currency token from state
    if state.currency_tokens.is_empty() {
        return Ok(());
    }

    let currency_tokens: Vec<Pubkey> = state.currency_tokens.keys().cloned().collect();
    let token_index = msg.currency_token_index as usize % currency_tokens.len();
    let token_mint = currency_tokens[token_index];

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    let currency_token_pda = Pubkey::find_program_address(
        &[b"currency-token", token_mint.as_ref()],
        &PROGRAM_ID,
    ).0;

    // Build instruction data using proper Borsh serialization
    let mut data = get_anchor_discriminator("update_currency_token_limit").to_vec();
    let ix_data = UpdateCurrencyTokenLimitIx {
        claim_limit_per_cooldown: msg.claim_limit_per_cooldown,
        is_active: msg.is_active,
    };
    data.extend_from_slice(&borsh::to_vec(&ix_data)?);

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),  // authority - signer and mutable
            AccountMeta::new(global_config_address, false),  // global_config - mutable
            AccountMeta::new(currency_token_pda, false),  // currency_token - mutable
            AccountMeta::new_readonly(token_mint, false),  // token_mint - readonly
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&authority.pubkey()),
        &[&authority],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        if let Some(currency) = state.currency_tokens.get_mut(&token_mint) {
            if let Some(limit) = msg.claim_limit_per_cooldown {
                currency.claim_limit_per_cooldown = limit;
            }
            if let Some(active) = msg.is_active {
                currency.enabled = active;
            }
            debug_log!("Updated currency token {}", token_mint);
        }
    });

    Ok(())
}

pub fn execute_remove_currency_token(
    harness: &mut HarnessBase,
    msg: &RemoveCurrencyToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Get admin authority with Admin role
    let authority = state.get_authority_with_role(
        crate::targets::full_svm::state::GlobalRole::Admin,
        msg.authority_id as usize
    ).insecure_clone();

    // Get an existing currency token from state
    if state.currency_tokens.is_empty() {
        return Ok(());
    }

    let currency_tokens: Vec<Pubkey> = state.currency_tokens.keys().cloned().collect();
    let token_index = msg.currency_token_index as usize % currency_tokens.len();
    let token_mint = currency_tokens[token_index];

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    let currency_token_pda = Pubkey::find_program_address(
        &[b"currency-token", token_mint.as_ref()],
        &PROGRAM_ID,
    ).0;

    // Build instruction data
    let data = get_anchor_discriminator("remove_currency_token").to_vec();

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),  // authority - signer and mutable
            AccountMeta::new(global_config_address, false),  // global_config - mutable
            AccountMeta::new(currency_token_pda, false),  // currency_token - mutable
            AccountMeta::new_readonly(token_mint, false),  // token_mint - readonly
            AccountMeta::new_readonly(system_program::ID, false),  // system_program
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&authority.pubkey()),
        &[&authority],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        state.currency_tokens.remove(&token_mint);
        debug_log!("Removed currency token {}", token_mint);
    });

    Ok(())
}

pub fn execute_update_project(
    harness: &mut HarnessBase,
    msg: &UpdateProject,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    if state.projects.is_empty() {
        return Err("No projects available".into());
    }
    let project_index = (msg.project_index as usize) % state.projects.len();

    let project = &state.projects[project_index];
    let project_id = project.project_id;

    // Find project admin
    let admin_entry = project.roles_mapping.roles.iter()
        .find(|entry| entry.role == ProjectRole::Admin)
        .ok_or("No project admin role found in project")?;

    let admin = state.authority_keypairs.iter()
        .find(|kp| kp.pubkey() == admin_entry.account)
        .ok_or_else(|| {
            debug_log!("ERROR: Project admin {} not in authority_keypairs", admin_entry.account);
            "Project admin keypair not found in authority_keypairs"
        })?
        .insecure_clone();

    let mut data = get_anchor_discriminator("update_project_config").to_vec();

    #[derive(BorshSerialize, BorshDeserialize)]
    struct UpdateProjectConfigIx {
        project_nonce: u64,
        metadata_uri: String,
    }

    let ix_data = UpdateProjectConfigIx {
        project_nonce: project.nonce,
        metadata_uri: msg.metadata_uri.clone(),
    };
    data.extend_from_slice(&borsh::to_vec(&ix_data)?);

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(admin.pubkey(), true),  // 0. authority (signer)
            AccountMeta::new(project_id, false),              // 1. project
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&admin.pubkey()),
        &[&admin],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        let project_index = (msg.project_index as usize) % state.projects.len();
        state.projects[project_index].metadata_uri = msg.metadata_uri.clone();
        debug_log!("Updated project {}", project_id);
    });

    Ok(())
}

pub fn execute_update_project_fees(
    harness: &mut HarnessBase,
    msg: &UpdateProjectFees,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    if state.projects.is_empty() {
        return Err("No projects available".into());
    }
    let project_index = (msg.project_index as usize) % state.projects.len();

    let project = &state.projects[project_index];
    let project_id = project.project_id;

    // Find global admin => this function requires GlobalRole::Admin
    let admin = state.get_authority_with_role(
        crate::targets::full_svm::state::GlobalRole::Admin,
        0 // admin
    ).insecure_clone();

    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    // Build instruction data using Borsh serialization
    let mut data = get_anchor_discriminator("update_project_fees").to_vec();
    let ix_data = UpdateProjectFeesIx {
        project_nonce: project.nonce,
        user_native_claim_fee: msg.user_native_claim_fee,
        project_claim_fee: msg.project_claim_fee.map(|f| f as u16),
        remove_fee: msg.remove_fee.map(|f| f as u16),
    };
    data.extend_from_slice(&borsh::to_vec(&ix_data)?);

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),  // 0. authority (signer)
            AccountMeta::new(project_id, false),     // 1. project
            AccountMeta::new_readonly(global_config_address, false),  // 2. global_config
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&admin.pubkey()),
        &[&admin],
        harness.svm.latest_blockhash(),
    );

    // Debug log the fees being set
    debug_log!("UpdateProjectFees: project_claim_fee={:?}, remove_fee={:?}",
        msg.project_claim_fee, msg.remove_fee);

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        let project_index = (msg.project_index as usize) % state.projects.len();

        let project_nonce = state.projects[project_index].nonce;

        {
            let project = &mut state.projects[project_index];
            if let Some(fee) = msg.user_native_claim_fee {
                project.fee_management.user_native_claim_fee = Some(fee);
            }
            if let Some(fee) = msg.project_claim_fee {
                project.fee_management.project_claim_fee = Some(fee as u16);
                if fee > 10000 {
                    debug_log!("WARNING: Setting project_claim_fee > 100%: {}", fee);
                }
            }
            if let Some(fee) = msg.remove_fee {
                project.fee_management.remove_fee = Some(fee as u16);
                if fee > 10000 {
                    debug_log!("WARNING: Setting remove_fee > 100%: {}", fee);
                }
            }
        } // Mutable borrow ends here

        debug_log!("Updated project fees for {} (nonce: {})", project_id, project_nonce);

        // INV-F1: Verify all fee basis points are within valid range (0-10000)
        if let Err(mut violation) = check_fee_range_after_project_update(state) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-PF1: Check that project fees don't exceed BASIS_POINTS (100%)
        if let Err(mut violation) = check_project_fee_limits_onchain(
            &harness.svm,
            project_nonce,
            "UpdateProjectFees",
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }
    });

    Ok(())
}

pub fn execute_revoke_project_role(
    harness: &mut HarnessBase,
    msg: &RevokeProjectRole,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    if state.projects.is_empty() {
        return Err("No projects available".into());
    }
    let project_index = (msg.project_index as usize) % state.projects.len();

    let project = &state.projects[project_index];
    let project_id = project.project_id;

    // Find project admin
    let admin_entry = project.roles_mapping.roles.iter()
        .find(|entry| entry.role == ProjectRole::Admin)
        .ok_or("No project admin role found in project")?;

    let admin = state.authority_keypairs.iter()
        .find(|kp| kp.pubkey() == admin_entry.account)
        .ok_or_else(|| {
            debug_log!("ERROR: Project admin {} not in authority_keypairs", admin_entry.account);
            "Project admin keypair not found in authority_keypairs"
        })?
        .insecure_clone();

    let account = state.get_random_authority(msg.account_id as usize).pubkey();

    // Build instruction data
    let mut data = get_anchor_discriminator("revoke_project_role").to_vec();
    data.extend_from_slice(&project.nonce.to_le_bytes());
    data.extend_from_slice(account.as_ref());
    data.push(0); // ProjectRole::Admin

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(admin.pubkey(), true),  // 0. authority (signer)
            AccountMeta::new(project_id, false),              // 1. project
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&admin.pubkey()),
        &[&admin],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        let project_index = (msg.project_index as usize) % state.projects.len();
        state.revoke_project_role(project_index, &account, &ProjectRole::Admin);
        debug_log!("Revoked project role from {}", account);
    });

    Ok(())
}

pub fn execute_renounce_project_role(
    harness: &mut HarnessBase,
    msg: &RenounceProjectRole,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    if state.projects.is_empty() {
        return Err("No projects available".into());
    }
    let project_index = (msg.project_index as usize) % state.projects.len();

    let project = &state.projects[project_index];
    let project_id = project.project_id;

    // The renouncer is the authority themselves
    let authority = state.get_random_authority(msg.authority_id as usize).insecure_clone();

    // Build instruction data
    let mut data = get_anchor_discriminator("renounce_project_role").to_vec();
    data.extend_from_slice(&project.nonce.to_le_bytes());
    data.push(0); // ProjectRole::Admin

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(authority.pubkey(), true),  // 0. authority (signer)
            AccountMeta::new(project_id, false),                  // 1. project
        ],
        data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&authority.pubkey()),
        &[&authority],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        let project_index = (msg.project_index as usize) % state.projects.len();
        state.revoke_project_role(project_index, &authority.pubkey(), &ProjectRole::Admin);
        debug_log!("{} renounced project role", authority.pubkey());
    });

    Ok(())
}

pub fn execute_deposit_non_fungible_token(
    harness: &mut HarnessBase,
    msg: &DepositNonFungibleToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Get depositor authority
    let authority = state.get_random_authority(msg.authority_id as usize).insecure_clone();

    // Resolve project from index
    if state.projects.is_empty() {
        debug_log!("No projects available for NFT deposit");
        return Ok(());
    }
    let project_index = msg.project_index as usize % state.projects.len();
    let project = &state.projects[project_index];
    let project_id = project.project_id;
    let project_nonce = project.nonce;

    // Resolve currency token mint (NFT mint)
    if state.currency_tokens.is_empty() {
        debug_log!("No currency tokens available for NFT deposit");
        return Ok(());
    }
    let currency_tokens: Vec<Pubkey> = state.currency_tokens.keys().cloned().collect();
    let currency_index = msg.currency_token_index as usize % currency_tokens.len();
    let token_mint = currency_tokens[currency_index];

    // Verify this is an NFT (non-fungible token type)
    let currency_token = state.currency_tokens.get(&token_mint);
    if let Some(ct) = currency_token {
        if !matches!(ct.currency_type, crate::targets::full_svm::state::CurrencyType::NonFungible) {
            debug_log!("Skipping NFT deposit: token {} is not an NFT type", token_mint);
            return Ok(());
        }
    } else {
        debug_log!("Currency token not found for mint: {}", token_mint);
        return Ok(());
    }

    // Currency token PDA
    let currency_token_pda = Pubkey::find_program_address(
        &[b"currency-token", token_mint.as_ref()],
        &PROGRAM_ID,
    ).0;

    // Project currency budget PDA
    let project_budget_pda = Pubkey::find_program_address(
        &[b"project-currency-budget", project_id.as_ref(), currency_token_pda.as_ref()],
        &PROGRAM_ID,
    ).0;

    let mut instructions = Vec::new();

    // Get authority ATA
    let authority_ata = spl_associated_token_account::get_associated_token_address(
        &authority.pubkey(),
        &token_mint
    );

    // Check if authority ATA exists and has NFT
    let needs_ata_creation = harness.svm.get_account(&authority_ata).is_none();
    let needs_nft_mint = if !needs_ata_creation {
        // ATA exists, check if it has an NFT
        let account = harness.svm.get_account(&authority_ata).unwrap();
        match spl_token::state::Account::unpack(&account.data) {
            Ok(token_account) => token_account.amount == 0,
            Err(_) => true,
        }
    } else {
        true
    };

    // Create authority ATA if needed
    if needs_ata_creation {
        debug_log!("Creating authority ATA for NFT mint {}", token_mint);
        let create_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
            &authority.pubkey(),
            &authority.pubkey(),
            &token_mint,
            &spl_token::ID,
        );
        instructions.push(create_ata_ix);
    }

    // Mint NFT to authority if needed
    if needs_nft_mint {
        // Get the mint authority 
        //*first authority is always the mint authority as per harness init*
        let mint_authority = &state.authority_keypairs[0];

        debug_log!("Minting NFT {} to authority {} using mint authority {}",
                   token_mint, authority.pubkey(), mint_authority.pubkey());

        let mint_ix = spl_token::instruction::mint_to(
            &spl_token::ID,
            &token_mint,
            &authority_ata,
            &mint_authority.pubkey(),  // mint authority
            &[&mint_authority.pubkey()],
            1,  // NFT amount is always 1
        )?;
        instructions.push(mint_ix);
    }

    // Get project ATA
    let project_ata = spl_associated_token_account::get_associated_token_address(
        &project_id,
        &token_mint
    );

    // Create project ATA if needed
    if harness.svm.get_account(&project_ata).is_none() {
        debug_log!("Creating project ATA for NFT mint {}", token_mint);
        let create_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
            &authority.pubkey(),
            &project_id,
            &token_mint,
            &spl_token::ID,
        );
        instructions.push(create_ata_ix);
    }

    // Build instruction data for deposit_non_fungible_token
    let mut data = get_anchor_discriminator("deposit_non_fungible_token").to_vec();
    data.extend_from_slice(&project_nonce.to_le_bytes());

    // Build accounts by the program's DepositNonFungibleToken struct:
    // 1. authority: Signer<'info> - mut, signer
    // 2. authority_ata: Account<'info, TokenAccount> - mut
    // 3. project: Account<'info, Project> - mut
    // 4. project_ata: Account<'info, TokenAccount> - mut
    // 5. token_mint: Account<'info, Mint> - readonly
    // 6. currency_token: Account<'info, CurrencyToken> - mut
    // 7. project_currency_budget: Account<'info, ProjectCurrencyBudget> - mut
    // 8. system_program: Program<'info, System>
    // 9. token_program: Program<'info, Token>

    let accounts = vec![
        AccountMeta::new(authority.pubkey(), true),        // authority (mut, signer)
        AccountMeta::new(authority_ata, false),            // authority_ata (mut)
        AccountMeta::new(project_id, false),               // project (mut)
        AccountMeta::new(project_ata, false),              // project_ata (mut)
        AccountMeta::new_readonly(token_mint, false),      // token_mint (readonly)
        AccountMeta::new(currency_token_pda, false),       // currency_token (mut)
        AccountMeta::new(project_budget_pda, false),       // project_currency_budget (mut, init_if_needed)
        AccountMeta::new_readonly(system_program::ID, false),  // system_program
        AccountMeta::new_readonly(spl_token::ID, false),   // token_program
    ];

    let deposit_instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    };
    instructions.push(deposit_instruction);

    debug_log!(
        "Executing NFT deposit transaction with {} instructions for NFT {} to project {}",
        instructions.len(),
        token_mint,
        project_id
    );

    // Determine who needs to sign
    let signers: Vec<&dyn Signer> = if needs_nft_mint {
        let mint_authority = &state.authority_keypairs[0];
        if authority.pubkey() == mint_authority.pubkey() {
            vec![&authority]
        } else {
            vec![&authority, mint_authority]
        }
    } else {
        vec![&authority]
    };

    // Capture before state for INV-B2
    let before_balance = state.get_project_budget(&project_id, &token_mint);
    let budget_key = (project_id, token_mint);
    let before_total_deposited = state.project_budgets.get(&budget_key)
        .map(|b| b.total_deposited)
        .unwrap_or(0);

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&authority.pubkey()),
        &signers,
        harness.svm.latest_blockhash(),
    );

    let deposit_result = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();

        // Update project budget state
        let budget_key = (project_id, token_mint);
        let budget = state.project_budgets.entry(budget_key)
            .or_insert(ProjectCurrencyBudget {
                project_id,
                currency_id: token_mint,
                total_deposited: 0,
                total_claimed: 0,
                available_balance: 0,
            });

        // NFTs are counted as 1 unit
        budget.total_deposited = budget.total_deposited.saturating_add(1);
        budget.available_balance = budget.available_balance.saturating_add(1);

        debug_log!(
            "Successfully deposited NFT {} to project {}. Budget - Total deposited: {}, Available: {}",
            token_mint,
            project_id,
            budget.total_deposited,
            budget.available_balance
        );

        // INV-B2: Check deposit increases budget by exact amount (1 for NFT)
        if let Err(violation) = check_deposit_increases_budget(
            state,
            &harness.svm,
            &project_id,
            &token_mint,
            1,  // NFTs always have amount = 1
            before_balance,
            before_total_deposited,
        ) {
            violation.dump_and_abort();
        }

        // INV-B1: Check budget non-negativity after NFT deposit
        if let Err(violation) = check_budget_non_negative(
            state,
            &harness.svm,
            "DepositNonFungibleToken",
            Some(&project_id),
            Some(&token_mint)
        ) {
            violation.dump_and_abort();
        }
    });

    // Check if transaction succeeded
    let deposit_succeeded = deposit_result.is_ok();

    if deposit_succeeded {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();

        // Get updated budget
        let budget_after = state.get_project_budget(&project_id, &token_mint);

        // INV-M*: Check math invariants for NFT deposit
        if let Err(violation) = check_operation_math_invariants(
            state,
            "DepositNonFungibleToken",
            1, // NFT amount is always 1
            0, // No fee for deposits
            0, // No fee basis points for deposits
            &crate::targets::full_svm::state::CurrencyType::NonFungible,
            Some(before_balance),
            Some(budget_after),
            "DepositNonFungibleToken"
        ) {
            let mut violation: InvariantViolation = violation;
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-M4: NFT specific constraints
        if let Err(violation) = check_nft_constraints(
            &crate::targets::full_svm::state::CurrencyType::NonFungible,
            "DepositNonFungibleToken",
            1, // amount
            1, // budget_change
            0, // project_fee (no fee for deposits)
            "DepositNonFungibleToken"
        ) {
            let mut violation: InvariantViolation = violation;
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-M1: Check global conservation
        if let Err(violation) = check_global_conservation(
            state,
            &harness.svm,
            "DepositNonFungibleToken"
        ) {
            let mut violation: InvariantViolation = violation;
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-S1: Check budget exists after successful NFT deposit
        if let Err(violation) = check_budget_exists_after_deposit(
            state,
            &harness.svm,
            &project_id,
            &token_mint,
            true, // deposit succeeded
            "DepositNonFungibleToken"
        ) {
            let mut violation: InvariantViolation = violation;
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-S4: Check currency exists for budget
        if let Err(mut violation) = check_currency_exists_for_budget(
            state,
            &project_id,
            &token_mint,
            "DepositNonFungibleToken"
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-S5: Check currency type consistency
        if let Err(mut violation) = check_currency_type_consistency(
            state,
            &project_id,
            &token_mint,
            "DepositNonFungibleToken"
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }
    }

    Ok(())
}

pub fn execute_remove_fungible_token(
    harness: &mut HarnessBase,
    msg: &RemoveFungibleToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Resolve project from index
    if state.projects.is_empty() {
        return Ok(()); // No projects to remove from
    }
    let project_index = msg.project_index as usize % state.projects.len();
    let project = &state.projects[project_index];
    let project_id = project.project_id;
    let project_nonce = project.nonce;

    // Resolve currency from index
    if state.currency_tokens.is_empty() {
        return Ok(()); // No currencies to remove
    }
    let currency_tokens: Vec<Pubkey> = state.currency_tokens.keys().cloned().collect();
    let currency_index = msg.currency_token_index as usize % currency_tokens.len();
    let currency_id = currency_tokens[currency_index];

    // Get recipient from authority keypairs
    let recipient_index = msg.recipient_id as usize % state.authority_keypairs.len();
    let recipient = state.authority_keypairs[recipient_index].pubkey();

    // Find project admin
    let admin_entry = project.roles_mapping.roles.iter()
        .find(|entry| entry.role == ProjectRole::Admin)
        .ok_or("No project admin role found in project")?;

    let admin = state.authority_keypairs.iter()
        .find(|kp| kp.pubkey() == admin_entry.account)
        .ok_or_else(|| {
            debug_log!("ERROR: Project admin {} not in authority_keypairs", admin_entry.account);
            "Project admin keypair not found in authority_keypairs"
        })?
        .insecure_clone();

    // Check if this is a fungible token (skip NFTs)
    let currency_token = state.currency_tokens.get(&currency_id);
    if currency_token.is_none() {
        debug_log!("Currency token {} not found in state", currency_id);
        return Ok(());
    }
    let currency_token = currency_token.unwrap();

    if matches!(currency_token.currency_type, crate::targets::full_svm::state::CurrencyType::NonFungible) {
        debug_log!("Skipping remove fungible for NFT token {}", currency_id);
        return Ok(());
    }

    // Native tokens use Pubkey::default() (all zeros) as the mint
    let is_native = currency_id == Pubkey::default() || currency_id == spl_token::native_mint::ID ||
                    matches!(currency_token.currency_type, crate::targets::full_svm::state::CurrencyType::Native);

    // Get global config address and fee collector
    let global_config_address = Pubkey::find_program_address(
        &[b"global-config"],
        &PROGRAM_ID,
    ).0;

    let fee_collector = state.global_config.fee_management.fee_collector;

    // Currency token PDA
    let currency_token_pda = Pubkey::find_program_address(
        &[b"currency-token", currency_id.as_ref()],
        &PROGRAM_ID,
    ).0;

    // Project currency budget PDA
    let project_budget_pda = Pubkey::find_program_address(
        &[b"project-currency-budget", project_id.as_ref(), currency_token_pda.as_ref()],
        &PROGRAM_ID,
    ).0;

    // Check if budget exists in our state - can't remove from non-existent budget
    if !state.project_budgets.contains_key(&(project_id, currency_id)) {
        debug_log!("Skipping remove: no budget exists for project {} and currency {}", project_id, currency_id);
        return Ok(());
    }

    // Check if budget has any balance to remove
    let budget = state.project_budgets.get(&(project_id, currency_id)).unwrap();
    if budget.available_balance == 0 {
        debug_log!("Skipping remove: budget has zero available balance");
        return Ok(());
    }

    let mut instructions = Vec::new();

    // Create ATAs if needed for SPL tokens
    if !is_native {
        // Create fee collector ATA if needed
        let fee_collector_ata = spl_associated_token_account::get_associated_token_address(&fee_collector, &currency_id);
        let ata_exists = harness.svm.get_account(&fee_collector_ata)
            .map(|acc| acc.owner == spl_token::ID)
            .unwrap_or(false);

        if !ata_exists {
            let create_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
                &admin.pubkey(),
                &fee_collector,
                &currency_id,
                &spl_token::ID,
            );
            instructions.push(create_ata_ix);
        }

        // Create authority (recipient) ATA if needed
        let authority_ata = spl_associated_token_account::get_associated_token_address(&recipient, &currency_id);
        let auth_ata_exists = harness.svm.get_account(&authority_ata)
            .map(|acc| acc.owner == spl_token::ID)
            .unwrap_or(false);

        if !auth_ata_exists {
            let create_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
                &admin.pubkey(),
                &recipient,
                &currency_id,
                &spl_token::ID,
            );
            instructions.push(create_ata_ix);
        }

        // Project ATA should already exist from deposits
        let project_ata = spl_associated_token_account::get_associated_token_address(&project_id, &currency_id);
        let project_ata_exists = harness.svm.get_account(&project_ata)
            .map(|acc| acc.owner == spl_token::ID)
            .unwrap_or(false);

        if !project_ata_exists {
            debug_log!("Warning: Project ATA doesn't exist for token {}, creating it", currency_id);
            let create_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
                &admin.pubkey(),
                &project_id,
                &currency_id,
                &spl_token::ID,
            );
            instructions.push(create_ata_ix);
        }
    }

    // Build instruction data
    let mut data = get_anchor_discriminator("remove_fungible_token").to_vec();
    let ix_data = RemoveFungibleTokenIx {
        project_nonce,
        amount: msg.amount,
    };
    data.extend_from_slice(&borsh::to_vec(&ix_data)?);

    // Build accounts for RemoveFungibleToken instruction
    // For Option accounts: use PROGRAM_ID for native tokens, actual ATA for SPL tokens
    let accounts = vec![
        AccountMeta::new(global_config_address, false),    // 0. global_config
        AccountMeta::new_readonly(currency_id, false),     // 1. token_mint
        AccountMeta::new(fee_collector, false),            // 2. fee_collector (mut)
        // 3. protocol_fee_collector_ata (Option)
        if is_native {
            AccountMeta::new_readonly(PROGRAM_ID, false)
        } else {
            let fee_collector_ata = spl_associated_token_account::get_associated_token_address(&fee_collector, &currency_id);
            AccountMeta::new(fee_collector_ata, false)
        },
        AccountMeta::new(admin.pubkey(), true),           // 4. authority (signer)
        // 5. authority_ata (Option)
        if is_native {
            AccountMeta::new_readonly(PROGRAM_ID, false)
        } else {
            let authority_ata = spl_associated_token_account::get_associated_token_address(&recipient, &currency_id);
            AccountMeta::new(authority_ata, false)
        },
        AccountMeta::new(project_id, false),              // 6. project
        // 7. project_ata (Option)
        if is_native {
            AccountMeta::new_readonly(PROGRAM_ID, false)
        } else {
            let project_ata = spl_associated_token_account::get_associated_token_address(&project_id, &currency_id);
            AccountMeta::new(project_ata, false)
        },
        AccountMeta::new(currency_token_pda, false),        // 8. currency_token
        AccountMeta::new(project_budget_pda, false),        // 9. project_currency_budget
        AccountMeta::new_readonly(system_program::ID, false),   // 10. system_program
        AccountMeta::new_readonly(spl_token::ID, false),        // 11. token_program
    ];

    let remove_instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    };
    instructions.push(remove_instruction);

    debug_log!("Executing remove fungible token: {} amount from project {}", msg.amount, project_id);

    // Capture before state for INV-B4
    let before_balance = state.get_project_budget(&project_id, &currency_id);

    // INV-A5: Capture project admins for authorization check
    let project_admins: Vec<Pubkey> = project.roles_mapping.roles.iter()
        .filter_map(|entry| {
            if entry.role == ProjectRole::Admin {
                Some(entry.account)
            } else {
                None
            }
        })
        .collect();

    // Calculate the removal fee for conservation check
    let global_remove_fee_bp = state.global_config.fee_management.remove_fee;
    let removal_fee = (msg.amount as u128 * global_remove_fee_bp as u128 / 10000) as u64;
    let authority_receives = msg.amount.saturating_sub(removal_fee);

    // INV-M*: Capture currency type for math invariants
    let currency_type = currency_token.currency_type.clone();

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&admin.pubkey()),
        &[&admin],
        harness.svm.latest_blockhash(),
    );

    let remove_result = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();
        let budget_key = (project_id, currency_id);
        if let Some(budget) = state.project_budgets.get_mut(&budget_key) {
            budget.available_balance = budget.available_balance.saturating_sub(msg.amount);
            debug_log!("Removed {} tokens from project budget", msg.amount);
        }

        // INV-B4: Check remove decreases budget by full amount
        if let Err(violation) = check_remove_decreases_budget(
            state,
            &harness.svm,
            &project_id,
            &currency_id,
            msg.amount,
            before_balance,
        ) {
            violation.dump_and_abort();
        }

        // INV-B6: Check conservation of funds during remove
        // Verify: budget_decrease = authority_receives + removal_fee
        let after_balance = state.get_project_budget(&project_id, &currency_id);
        let budget_decrease = before_balance.saturating_sub(after_balance);

        if let Err(violation) = check_remove_conservation_of_funds(
            state,
            &harness.svm,
            &project_id,
            &currency_id,
            budget_decrease,
            authority_receives,
            removal_fee,
            before_balance,
        ) {
            violation.dump_and_abort();
        }

        // INV-A5: Check admin authorization for remove operation
        if let Err(violation) = check_admin_authorization(
            &admin.pubkey(),
            &project_admins,
            "RemoveFungibleToken",
            true, // remove succeeded
            "RemoveFungibleToken"
        ) {
            violation.dump_and_abort();
        }

        // INV-B1: Check budget non-negativity after remove
        if let Err(violation) = check_budget_non_negative(
            state,
            &harness.svm,
            "RemoveFungibleToken",
            Some(&project_id),
            Some(&currency_id)
        ) {
            violation.dump_and_abort();
        }
    });

    // Check if remove succeeded
    let remove_succeeded = remove_result.is_ok();

    {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();

        // INV-A5: Verify admin authorization even if transaction failed
        if let Err(mut violation) = check_admin_authorization(
            &admin.pubkey(),
            &project_admins,
            "RemoveFungibleToken",
            remove_succeeded,
            "RemoveFungibleToken"
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // On-chain verification for INV-A5
        if let Err(mut violation) = verify_project_admin_authorization(
            state,
            project_index,
            &admin.pubkey(),
            "RemoveFungibleToken",
            remove_succeeded
        ) {
            if let Some(ref pb_data) = state.current_protobuf {
                violation = violation.with_protobuf(pb_data.clone());
            }
            if let Some(seed) = state.current_seed {
                violation = violation.with_seed(seed);
            }
            violation.dump_and_abort();
        }

        // INV-M*: Check math invariants for remove operation
        if remove_succeeded {
            // Get updated budget
            let budget_after = state.get_project_budget(&project_id, &currency_id);

            // Calculate remove fee
            let remove_fee_bp = state.global_config.fee_management.remove_fee;
            let calculated_fee = msg.amount.saturating_mul(remove_fee_bp as u64) / 10000;

            // Check math invariants
            if let Err(violation) = check_operation_math_invariants(
                state,
                "Remove",
                msg.amount,
                calculated_fee,
                remove_fee_bp,
                &currency_type,
                Some(before_balance),
                Some(budget_after),
                "RemoveFungibleToken"
            ) {
                let mut violation: InvariantViolation = violation;
                if let Some(ref pb_data) = state.current_protobuf {
                    violation = violation.with_protobuf(pb_data.clone());
                }
                if let Some(seed) = state.current_seed {
                    violation = violation.with_seed(seed);
                }
                violation.dump_and_abort();
            }

            // INV-M1: Check global conservation after successful remove
            if let Err(violation) = check_global_conservation(
                state,
                &harness.svm,
                "RemoveFungibleToken"
            ) {
                let mut violation: InvariantViolation = violation;
                if let Some(ref pb_data) = state.current_protobuf {
                    violation = violation.with_protobuf(pb_data.clone());
                }
                if let Some(seed) = state.current_seed {
                    violation = violation.with_seed(seed);
                }
                violation.dump_and_abort();
            }
        }
    }

    Ok(())
}

pub fn execute_remove_non_fungible_token(
    harness: &mut HarnessBase,
    msg: &RemoveNonFungibleToken,
) -> Result<(), Box<dyn std::error::Error>> {
    // NFT removals are complex as they require token program interactions
    let state = harness.state.get_or_insert_extension::<FullSvmState>();

    // Resolve project from index
    if state.projects.is_empty() {
        return Ok(()); // No projects to remove from
    }
    let project_index = msg.project_index as usize % state.projects.len();
    let project = &state.projects[project_index];
    let project_id = project.project_id;

    // Resolve currency from index
    if state.currency_tokens.is_empty() {
        return Ok(()); // No currencies to remove
    }
    let currency_tokens: Vec<Pubkey> = state.currency_tokens.keys().cloned().collect();
    let currency_index = msg.currency_token_index as usize % currency_tokens.len();
    let currency_id = currency_tokens[currency_index];

    // Find project admin
    let admin_entry = project.roles_mapping.roles.iter()
        .find(|entry| entry.role == ProjectRole::Admin)
        .ok_or("No project admin role found in project")?;

    let admin = state.authority_keypairs.iter()
        .find(|kp| kp.pubkey() == admin_entry.account)
        .ok_or_else(|| {
            debug_log!("ERROR: Project admin {} not in authority_keypairs", admin_entry.account);
            "Project admin keypair not found in authority_keypairs"
        })?
        .insecure_clone();

    // Calculate PDAs and token accounts
    let currency_token_pda = Pubkey::find_program_address(
        &[b"currency-token", currency_id.as_ref()],
        &PROGRAM_ID,
    ).0;

    let project_budget_pda = Pubkey::find_program_address(
        &[b"project-currency-budget", project_id.as_ref(), currency_token_pda.as_ref()],
        &PROGRAM_ID,
    ).0;

    // Check if budget exists - can't remove NFT if no budget exists
    if !state.project_budgets.contains_key(&(project_id, currency_id)) {
        debug_log!("Skipping remove NFT: no budget exists for project {} and currency {}", project_id, currency_id);
        return Ok(());
    }

    // Get ATAs for authority and project
    let authority_ata = spl_associated_token_account::get_associated_token_address(&admin.pubkey(), &currency_id);
    let project_ata = spl_associated_token_account::get_associated_token_address(&project_id, &currency_id);

    // Check if project_ata exists - can't remove NFT if it wasn't deposited
    if harness.svm.get_account(&project_ata).is_none() {
        debug_log!("Skipping remove NFT: project ATA doesn't exist for {}", currency_id);
        return Ok(());
    }

    // Build instruction data
    let mut data = get_anchor_discriminator("remove_non_fungible_token").to_vec();
    data.extend_from_slice(&project.nonce.to_le_bytes());

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),  // 0. authority (signer)
            AccountMeta::new(authority_ata, false),  // 1. authority_ata
            AccountMeta::new(project_id, false),     // 2. project
            AccountMeta::new(project_ata, false),    // 3. project_ata
            AccountMeta::new_readonly(currency_id, false),  // 4. token_mint
            AccountMeta::new(currency_token_pda, false),    // 5. currency_token
            AccountMeta::new(project_budget_pda, false),    // 6. project_currency_budget
            AccountMeta::new_readonly(system_program::ID, false),  // 7. system_program
            AccountMeta::new_readonly(spl_token::ID, false),       // 8. token_program
        ],
        data,
    };

    // Capture before state for INV-B4
    let before_balance = state.get_project_budget(&project_id, &currency_id);

    let removal_fee = 0u64;
    let authority_receives = 1u64;

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&admin.pubkey()),
        &[&admin],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        let state = harness.state.get_or_insert_extension::<FullSvmState>();

        // Update budget state (NFTs are always 1 unit)
        let budget_key = (project_id, currency_id);
        if let Some(budget) = state.project_budgets.get_mut(&budget_key) {
            budget.available_balance = budget.available_balance.saturating_sub(1);
            debug_log!("Removed NFT {} from project {} budget", currency_id, project_id);
        }

        // INV-B4: Check remove decreases budget by full amount (1 for NFT)
        if let Err(violation) = check_remove_decreases_budget(
            state,
            &harness.svm,
            &project_id,
            &currency_id,
            1,  // NFTs always have amount = 1
            before_balance,
        ) {
            violation.dump_and_abort();
        }

        // INV-B6: Check conservation of funds during NFT remove
        // For NFTs: budget_decrease = 1, authority_receives = 1, fee = 0
        let after_balance = state.get_project_budget(&project_id, &currency_id);
        let budget_decrease = before_balance.saturating_sub(after_balance);

        if let Err(violation) = check_remove_conservation_of_funds(
            state,
            &harness.svm,
            &project_id,
            &currency_id,
            budget_decrease,
            authority_receives,
            removal_fee,
            before_balance,
        ) {
            violation.dump_and_abort();
        }

        // INV-B1: Check budget non-negativity after NFT removal
        if let Err(violation) = check_budget_non_negative(
            state,
            &harness.svm,
            "RemoveNonFungibleToken",
            Some(&project_id),
            Some(&currency_id)
        ) {
            violation.dump_and_abort();
        }
    });

    Ok(())
}

pub fn execute_system_program_transfer(
    harness: &mut HarnessBase,
    msg: &SystemProgramTransfer,
) -> Result<(), Box<dyn std::error::Error>> {
    use solana_sdk::system_instruction;

    let state = harness.state.get_or_insert_extension::<FullSvmState>();
    let from_keypair = state.get_random_authority(msg.authority_id as usize).insecure_clone();
    let to = state.get_random_user(msg.to_id as usize).pubkey();

    // Build system program transfer instruction - from must be the signer
    let instruction = system_instruction::transfer(&from_keypair.pubkey(), &to, msg.lamports);

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&from_keypair.pubkey()),
        &[&from_keypair],
        harness.svm.latest_blockhash(),
    );

    let _ = crate::execute_transaction!(harness, tx, on_success: || {
        debug_log!("System program transfer: {} lamports from {} to {}", msg.lamports, from_keypair.pubkey(), to);
    });

    Ok(())
}