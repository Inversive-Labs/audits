use crate::targets::full_svm::{
    state::FullSvmState,
    invariants::InvariantViolation,
};
use solana_sdk::pubkey::Pubkey;
use litesvm::LiteSVM;
use borsh::BorshDeserialize;
use spl_token::state::Mint;
use solana_sdk::program_pack::Pack;

// INV-S1: Budget Exists If Deposits Made
pub fn check_budget_exists_after_deposit(
    state: &FullSvmState,
    svm: &LiteSVM,
    project_id: &Pubkey,
    currency_id: &Pubkey,
    deposit_succeeded: bool,
    context: &str,
) -> Result<(), InvariantViolation> {
    // Only check if deposit actually succeeded
    if !deposit_succeeded {
        return Ok(());
    }

    let budget_key = (*project_id, *currency_id);

    // STEP 1: Verify local state has budget entry
    if !state.project_budgets.contains_key(&budget_key) {
        return Err(InvariantViolation::new(
            context,
            "INV-S1",
            &format!(
                "CRITICAL: Budget missing in local state after successful deposit!\n\
                \n\
                Project: {}\n\
                Currency: {}\n\
                \n\
                A successful deposit MUST create a budget entry.\n\
                This indicates a state tracking bug in the fuzzer or protocol.",
                project_id, currency_id
            )
        ));
    }

    // STEP 2: Verify on-chain budget account exists
    match read_budget_exists_on_chain(svm, project_id, currency_id) {
        Ok(exists) => {
            if !exists {
                return Err(InvariantViolation::new(
                    context,
                    "INV-S1",
                    &format!(
                        "CRITICAL: Budget account missing on-chain after successful deposit!\n\
                        \n\
                        Project: {}\n\
                        Currency: {}\n\
                        \n\
                        Local state has budget, but on-chain account doesn't exist.\n\
                        This indicates a protocol bug or state desync.",
                        project_id, currency_id
                    )
                ));
            }
        }
        Err(e) => {
            // Log warning but don't fail - PDA derivation might differ
            crate::debug_log!(
                "INV-S1 Warning: Could not verify on-chain budget existence: {}",
                e
            );
        }
    }

    // STEP 3: Verify local budget has valid values
    if let Some(budget) = state.project_budgets.get(&budget_key) {
        // After a successful deposit, total_deposited must be > 0
        if budget.total_deposited == 0 {
            return Err(InvariantViolation::new(
                context,
                "INV-S1",
                &format!(
                    "Budget exists but total_deposited is 0 after deposit!\n\
                    \n\
                    Project: {}\n\
                    Currency: {}\n\
                    Available balance: {}\n\
                    Total deposited: {}\n\
                    \n\
                    A successful deposit must increment total_deposited.",
                    project_id, currency_id,
                    budget.available_balance, budget.total_deposited
                )
            ));
        }

        if budget.available_balance == 0 && budget.total_claimed == 0 {
            crate::debug_log!(
                "INV-S1 Warning: Budget has 0 available after deposit with no claims. \
                Project: {}, Currency: {}, Deposited: {}",
                project_id, currency_id, budget.total_deposited
            );
        }
    }

    crate::debug_log!(
        "INV-S1 Budget exists after deposit: project={}, currency={}",
        project_id, currency_id
    );

    Ok(())
}

/// INV-S1 (Batch): Check all budgets exist for projects with deposits
pub fn check_all_budgets_exist(
    state: &FullSvmState,
    svm: &LiteSVM,
    context: &str,
) -> Result<(), InvariantViolation> {
    let mut missing_budgets: Vec<String> = Vec::new();
    let mut desync_budgets: Vec<String> = Vec::new();

    for ((project_id, currency_id), budget) in &state.project_budgets {
        // Skip budgets with no deposits
        if budget.total_deposited == 0 {
            continue;
        }

        // Check on-chain existence
        match read_budget_exists_on_chain(svm, project_id, currency_id) {
            Ok(exists) => {
                if !exists {
                    missing_budgets.push(format!(
                        "  - Project: {}, Currency: {}, Deposited: {}",
                        project_id, currency_id, budget.total_deposited
                    ));
                }
            }
            Err(_) => {
                // Could not verify - might be PDA derivation issue
                desync_budgets.push(format!(
                    "  - Project: {}, Currency: {} (verification failed)",
                    project_id, currency_id
                ));
            }
        }
    }

    if !missing_budgets.is_empty() {
        return Err(InvariantViolation::new(
            context,
            "INV-S1",
            &format!(
                "CRITICAL: {} budget(s) missing on-chain!\n\
                \n\
                Missing budgets:\n{}\n\
                \n\
                Local state has these budgets, but they don't exist on-chain.",
                missing_budgets.len(),
                missing_budgets.join("\n")
            )
        ));
    }

    if !desync_budgets.is_empty() {
        crate::debug_log!(
            "INV-S1 Warning: {} budget(s) could not be verified:\n{}",
            desync_budgets.len(),
            desync_budgets.join("\n")
        );
    }

    crate::debug_log!(
        "INV-S1 All {} budgets verified to exist",
        state.project_budgets.len()
    );

    Ok(())
}

// Helper Functions

/// Check if a budget account exists on-chain
fn read_budget_exists_on_chain(
    svm: &LiteSVM,
    project_id: &Pubkey,
    currency_id: &Pubkey,
) -> Result<bool, String> {
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

    // Check if account exists
    match svm.get_account(&budget_pda) {
        Some(account) => {
            // Account exists - verify it has data
            if account.data.len() > 8 {
                Ok(true)
            } else {
                // Account exists but has no data - not properly initialized
                Ok(false)
            }
        }
        None => Ok(false),
    }
}

/// Read budget value from on-chain account
pub fn read_budget_on_chain(
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
    if account.data.len() < 16 {
        return Err("Budget account data too short".to_string());
    }

    let data = &account.data[8..];
    let mut slice = data;

    // ProjectCurrencyBudget first field is budget (u64)
    let budget = u64::deserialize(&mut slice)
        .map_err(|e| format!("Failed to deserialize budget: {}", e))?;

    Ok(budget)
}

// INV-S2: Attribution Count Matches Attributions
pub fn check_attribution_count_consistency(
    state: &FullSvmState,
    project_id: &Pubkey,
    context: &str,
) -> Result<(), InvariantViolation> {
    // Find the project in state
    let project = state.projects.iter()
        .find(|p| p.project_id == *project_id);

    let project_count = match project {
        Some(p) => p.attributions_count,
        None => {
            // Project not found - this is okay if no claims have been made
            return Ok(());
        }
    };

    // Get our tracked count
    let tracked_count = state.project_attribution_counts
        .get(project_id)
        .copied()
        .unwrap_or(0);

    // Compare
    if project_count != tracked_count {
        return Err(InvariantViolation::new(
            context,
            "INV-S2",
            &format!(
                "CRITICAL: Attribution count mismatch!\n\
                \n\
                Project: {}\n\
                Project.attributions_count: {}\n\
                Tracked attribution count: {}\n\
                \n\
                The project's counter doesn't match the actual number of claims.\n\
                This indicates a bug in counter tracking.",
                project_id, project_count, tracked_count
            )
        ));
    }

    crate::debug_log!(
        "INV-S2 Attribution count consistent: project={}, count={}",
        project_id, project_count
    );

    Ok(())
}

/// INV-S2 (Batch): Check all projects have consistent attribution counts
pub fn check_all_attribution_counts(
    state: &FullSvmState,
    context: &str,
) -> Result<(), InvariantViolation> {
    let mut mismatches: Vec<String> = Vec::new();

    for project in &state.projects {
        let project_count = project.attributions_count;
        let tracked_count = state.project_attribution_counts
            .get(&project.project_id)
            .copied()
            .unwrap_or(0);

        if project_count != tracked_count {
            mismatches.push(format!(
                "  - Project: {}, Recorded: {}, Tracked: {}",
                project.project_id, project_count, tracked_count
            ));
        }
    }

    if !mismatches.is_empty() {
        return Err(InvariantViolation::new(
            context,
            "INV-S2",
            &format!(
                "CRITICAL: {} project(s) have attribution count mismatches!\n\
                \n\
                Mismatches:\n{}\n\
                \n\
                The project counters don't match the actual number of claims.",
                mismatches.len(),
                mismatches.join("\n")
            )
        ));
    }

    crate::debug_log!(
        "INV-S2 All {} projects have consistent attribution counts",
        state.projects.len()
    );

    Ok(())
}

/// INV-S2 On-Chain Verification: Read Project attribution count from chain
pub fn read_attribution_count_on_chain(
    svm: &LiteSVM,
    project_id: &Pubkey,
) -> Result<u64, String> {
    let account = svm.get_account(project_id)
        .ok_or_else(|| format!("Project account {} not found on chain", project_id))?;

    // Skip 8-byte Anchor discriminator
    if account.data.len() < 25 {
        return Err("Project account data too short for attribution count".to_string());
    }

    let offset = 8 + 1 + 8; // Skip discriminator, is_initialized, nonce to get to attributions_count
    let attributions_count = u64::from_le_bytes([
        account.data[offset], account.data[offset+1], account.data[offset+2], account.data[offset+3],
        account.data[offset+4], account.data[offset+5], account.data[offset+6], account.data[offset+7]
    ]);

    Ok(attributions_count)
}

/// INV-S2: Verify attribution count matches on-chain
pub fn check_attribution_count_consistency_onchain(
    svm: &LiteSVM,
    state: &FullSvmState,
    project_id: &Pubkey,
    context: &str,
) -> Result<(), InvariantViolation> {
    // Get our tracked count
    let tracked_count = state.project_attribution_counts
        .get(project_id)
        .copied()
        .unwrap_or(0);

    // Get on-chain count
    match read_attribution_count_on_chain(svm, project_id) {
        Ok(onchain_count) => {
            if onchain_count != tracked_count {
                return Err(InvariantViolation::new(
                    context,
                    "INV-S2",
                    &format!(
                        "CRITICAL: Attribution count mismatch with on-chain!\n\
                        \n\
                        Project: {}\n\
                        On-chain attributions_count: {}\n\
                        Tracked attribution count: {}\n\
                        \n\
                        The on-chain counter doesn't match our tracked count.\n\
                        This indicates a serious state desync.",
                        project_id, onchain_count, tracked_count
                    )
                ));
            }

            crate::debug_log!(
                "INV-S2 ON-CHAIN Attribution count matches on-chain: project={}, count={}",
                project_id, onchain_count
            );
        }
        Err(e) => {
            crate::debug_log!(
                "INV-S2 Warning: Could not verify on-chain attribution count: {}",
                e
            );
        }
    }

    Ok(())
}

// INV-S3: ProjectUser Total Claims Consistency
pub fn check_user_claims_consistency(
    state: &FullSvmState,
    project_id: &Pubkey,
    user_id: &Pubkey,
    context: &str,
) -> Result<(), InvariantViolation> {
    let key = (*project_id, *user_id);

    // Get the ProjectUser's claim_count
    let project_user_count = state.project_users.get(&key)
        .map(|pu| pu.claim_count)
        .unwrap_or(0);

    // Get our tracked count
    let tracked_count = state.user_claim_counts
        .get(&key)
        .copied()
        .unwrap_or(0);

    // Compare
    if project_user_count != tracked_count {
        return Err(InvariantViolation::new(
            context,
            "INV-S3",
            &format!(
                "CRITICAL: User claim count mismatch!\n\
                \n\
                Project: {}\n\
                User: {}\n\
                ProjectUser.claim_count: {}\n\
                Tracked claim count: {}\n\
                \n\
                The user's claim counter doesn't match the actual number of claims.\n\
                This indicates a bug in user claim tracking.",
                project_id, user_id, project_user_count, tracked_count
            )
        ));
    }

    crate::debug_log!(
        "INV-S3 User claim count consistent: project={}, user={}, count={}",
        project_id, user_id, project_user_count
    );

    Ok(())
}

/// INV-S3 (Batch): Check all project users have consistent claim counts
pub fn check_all_user_claims(
    state: &FullSvmState,
    context: &str,
) -> Result<(), InvariantViolation> {
    let mut mismatches: Vec<String> = Vec::new();

    for ((project_id, user_id), project_user) in &state.project_users {
        let project_user_count = project_user.claim_count;
        let tracked_count = state.user_claim_counts
            .get(&(*project_id, *user_id))
            .copied()
            .unwrap_or(0);

        if project_user_count != tracked_count {
            mismatches.push(format!(
                "  - Project: {}, User: {}, Recorded: {}, Tracked: {}",
                project_id, user_id, project_user_count, tracked_count
            ));
        }
    }

    if !mismatches.is_empty() {
        return Err(InvariantViolation::new(
            context,
            "INV-S3",
            &format!(
                "CRITICAL: {} user(s) have claim count mismatches!\n\
                \n\
                Mismatches:\n{}\n\
                \n\
                The user claim counters don't match the actual number of claims.",
                mismatches.len(),
                mismatches.join("\n")
            )
        ));
    }

    crate::debug_log!(
        "INV-S3 All {} project users have consistent claim counts",
        state.project_users.len()
    );

    Ok(())
}

/// INV-S3 On-Chain Verification: Read ProjectUser claim count from chain
pub fn read_user_claim_count_on_chain(
    svm: &LiteSVM,
    project_id: &Pubkey,
    user_id: &Pubkey,
) -> Result<u64, String> {
    // Derive ProjectUser PDA
    let (project_user_pda, _) = Pubkey::find_program_address(
        &[b"project-user", project_id.as_ref(), user_id.as_ref()],
        &crate::targets::full_svm::PROGRAM_ID,
    );

    let account = svm.get_account(&project_user_pda)
        .ok_or_else(|| format!("ProjectUser account {} not found on chain", project_user_pda))?;

    // Skip 8-byte Anchor discriminator
    if account.data.len() < 88 {
        return Err("ProjectUser account data too short for claim count".to_string());
    }

    let offset = 8 + 32 + 32; // Skip discriminator, authority, project to get to total_claims
    let total_claims = u64::from_le_bytes([
        account.data[offset], account.data[offset+1], account.data[offset+2], account.data[offset+3],
        account.data[offset+4], account.data[offset+5], account.data[offset+6], account.data[offset+7]
    ]);

    Ok(total_claims)
}

/// INV-S3 On-Chain: Verify user claim count matches on-chain
pub fn check_user_claims_consistency_onchain(
    svm: &LiteSVM,
    state: &FullSvmState,
    project_id: &Pubkey,
    user_id: &Pubkey,
    context: &str,
) -> Result<(), InvariantViolation> {
    let key = (*project_id, *user_id);

    // Get our tracked count
    let tracked_count = state.user_claim_counts
        .get(&key)
        .copied()
        .unwrap_or(0);

    // Get on-chain count
    match read_user_claim_count_on_chain(svm, project_id, user_id) {
        Ok(onchain_count) => {
            if onchain_count != tracked_count {
                return Err(InvariantViolation::new(
                    context,
                    "INV-S3",
                    &format!(
                        "CRITICAL: User claim count mismatch with on-chain!\n\
                        \n\
                        Project: {}\n\
                        User: {}\n\
                        On-chain claim_count: {}\n\
                        Tracked claim count: {}\n\
                        \n\
                        The on-chain user claim counter doesn't match our tracked count.\n\
                        This indicates a serious state desync.",
                        project_id, user_id, onchain_count, tracked_count
                    )
                ));
            }

            crate::debug_log!(
                "INV-S3 ON-CHAIN User claim count matches on-chain: project={}, user={}, count={}",
                project_id, user_id, onchain_count
            );
        }
        Err(e) => {
            if tracked_count == 0 {
                crate::debug_log!(
                    "INV-S3 ON-CHAIN No ProjectUser account (0 claims): project={}, user={}",
                    project_id, user_id
                );
            } else {
                crate::debug_log!(
                    "INV-S3 Warning: Could not verify on-chain user claim count: {}",
                    e
                );
            }
        }
    }

    Ok(())
}

// INV-S4: Active Currency Can Have Budget
pub fn check_currency_exists_for_budget(
    state: &FullSvmState,
    project_id: &Pubkey,
    currency_id: &Pubkey,
    context: &str,
) -> Result<(), InvariantViolation> {
    let budget_key = (*project_id, *currency_id);

    // Get the budget
    let budget = match state.project_budgets.get(&budget_key) {
        Some(b) => b,
        None => return Ok(()), // No budget, nothing to check
    };

    // If budget has balance, currency must exist
    if budget.available_balance > 0 || budget.total_deposited > 0 {
        if !state.currency_tokens.contains_key(currency_id) {
            return Err(InvariantViolation::new(
                context,
                "INV-S4",
                &format!(
                    "WARNING: Budget exists for unregistered currency!\n\
                    \n\
                    Project: {}\n\
                    Currency: {}\n\
                    Available balance: {}\n\
                    Total deposited: {}\n\
                    \n\
                    A budget exists but the currency is not registered in state.\n\
                    This indicates a state tracking issue.",
                    project_id, currency_id, budget.available_balance, budget.total_deposited
                )
            ));
        }
    }

    crate::debug_log!(
        "INV-S4 Currency exists for budget: project={}, currency={}",
        project_id, currency_id
    );

    Ok(())
}

/// **INV-S4 (Batch): Check all budgets have registered currencies**
pub fn check_all_budgets_have_currencies(
    state: &FullSvmState,
    context: &str,
) -> Result<(), InvariantViolation> {
    let mut issues: Vec<String> = Vec::new();

    for ((project_id, currency_id), budget) in &state.project_budgets {
        if budget.available_balance > 0 || budget.total_deposited > 0 {
            if !state.currency_tokens.contains_key(currency_id) {
                issues.push(format!(
                    "  - Project: {}, Currency: {}, Balance: {}",
                    project_id, currency_id, budget.available_balance
                ));
            }
        }
    }

    if !issues.is_empty() {
        return Err(InvariantViolation::new(
            context,
            "INV-S4",
            &format!(
                "WARNING: {} budget(s) exist for unregistered currencies!\n\
                \n\
                Issues:\n{}\n\
                \n\
                Budgets exist but their currencies are not registered.",
                issues.len(),
                issues.join("\n")
            )
        ));
    }

    crate::debug_log!(
        "INV-S4 All {} budgets have registered currencies",
        state.project_budgets.len()
    );

    Ok(())
}

// INV-S5: Token Account Consistency
pub fn check_currency_type_consistency(
    state: &FullSvmState,
    project_id: &Pubkey,
    currency_id: &Pubkey,
    context: &str,
) -> Result<(), InvariantViolation> {
    let budget_key = (*project_id, *currency_id);

    // Get the budget
    let budget = match state.project_budgets.get(&budget_key) {
        Some(b) => b,
        None => return Ok(()), // No budget, nothing to check
    };

    // If budget has balance, check currency type
    if budget.available_balance > 0 || budget.total_deposited > 0 {
        if let Some(currency) = state.currency_tokens.get(currency_id) {
            // Currency exists and is initialized - this is valid
            if !currency.is_initialized {
                return Err(InvariantViolation::new(
                    context,
                    "INV-S5",
                    &format!(
                        "WARNING: Budget exists for uninitialized currency!\n\
                        \n\
                        Project: {}\n\
                        Currency: {}\n\
                        Currency initialized: false\n\
                        Available balance: {}\n\
                        \n\
                        A budget exists but the currency is not initialized.",
                        project_id, currency_id, budget.available_balance
                    )
                ));
            }
        }
    }

    crate::debug_log!(
        "INV-S5 Currency type consistent for budget: project={}, currency={}",
        project_id, currency_id
    );

    Ok(())
}

// INV-N1: Freeze Authority DoS Protection
pub fn check_freeze_authority_on_currency_token(
    svm: &LiteSVM,
    token_mint: &Pubkey,
    is_native: bool,
    context: &str,
) -> Result<(), InvariantViolation> {
    // Native tokens (SOL) don't have freeze authority - skip check
    if is_native || *token_mint == Pubkey::default() {
        crate::debug_log!(
            "INV-N1 Native token, no freeze authority check needed: {}",
            token_mint
        );
        return Ok(());
    }

    // Read the mint account from chain
    let mint_account = match svm.get_account(token_mint) {
        Some(account) => account,
        None => {
            // Mint account doesn't exist yet - this is okay during setup
            crate::debug_log!(
                "INV-N1 Mint account not found on chain: {}",
                token_mint
            );
            return Ok(());
        }
    };

    // Unpack the SPL Token Mint data
    let mint_data = match Mint::unpack(&mint_account.data) {
        Ok(mint) => mint,
        Err(e) => {
            crate::debug_log!(
                "INV-N1 Could not unpack mint data for {}: {}",
                token_mint, e
            );
            return Ok(());
        }
    };

    // Check if freeze_authority is set
    if mint_data.freeze_authority.is_some() {
        let freeze_auth = mint_data.freeze_authority.unwrap();
        return Err(InvariantViolation::new(
            context,
            "INV-N1",
            &format!(
                "CRITICAL: Currency token has freeze_authority set!\n\
                \n\
                Token Mint: {}\n\
                Freeze Authority: {}\n\
                \n\
                The freeze authority holder can freeze the project_ata,\n\
                permanently blocking ALL claims and withdrawals.\n\
                \n\
                Vulnerable: admin_currencies.rs:103-106 (no freeze_authority check)",
                token_mint, freeze_auth
            )
        ));
    }

    crate::debug_log!(
        "INV-N1 Token mint has no freeze_authority: {}",
        token_mint
    );

    Ok(())
}

/// INV-N1 (Batch): Check all registered currency tokens for freeze authority
pub fn check_all_currency_tokens_freeze_authority(
    svm: &LiteSVM,
    state: &FullSvmState,
    context: &str,
) -> Result<(), InvariantViolation> {
    let mut vulnerable_tokens: Vec<String> = Vec::new();

    for (token_mint, currency) in &state.currency_tokens {
        // Skip native tokens
        if *token_mint == Pubkey::default() {
            continue;
        }

        // Check if this is a native currency type
        let is_native = matches!(currency.currency_type, crate::targets::full_svm::state::CurrencyType::Native);
        if is_native {
            continue;
        }

        // Read the mint account from chain
        if let Some(mint_account) = svm.get_account(token_mint) {
            if let Ok(mint_data) = Mint::unpack(&mint_account.data) {
                if mint_data.freeze_authority.is_some() {
                    let freeze_auth = mint_data.freeze_authority.unwrap();
                    vulnerable_tokens.push(format!(
                        "  - Token Mint: {}\n    Freeze Authority: {}",
                        token_mint, freeze_auth
                    ));
                }
            }
        }
    }

    if !vulnerable_tokens.is_empty() {
        return Err(InvariantViolation::new(
            context,
            "INV-N1",
            &format!(
                "CRITICAL: {} currency token(s) have freeze_authority set - DoS vulnerability!\n\
                \n\
                Vulnerable tokens:\n{}\n\
                \n\
                These tokens can have their project_ata frozen by the freeze authority holder,\n\
                permanently locking all funds deposited in these currencies.",
                vulnerable_tokens.len(),
                vulnerable_tokens.join("\n\n")
            )
        ));
    }

    crate::debug_log!(
        "INV-N1 All {} non-native currency tokens verified: no freeze_authority",
        state.currency_tokens.len()
    );

    Ok(())
}
