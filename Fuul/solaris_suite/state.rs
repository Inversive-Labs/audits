use std::collections::{HashMap, HashSet};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use crate::debug_log;
use solana_sdk::signer::Signer;
use crate::core::state::ProgramState;

/// Main state tracker for Fuul protocol fuzzing
#[derive(Debug)]
pub struct FullSvmState {
    // ========== Global Configuration ==========
    pub global_config: GlobalConfig,

    // ========== Currency Tokens ==========
    pub currency_tokens: HashMap<Pubkey, CurrencyToken>,

    // ========== Projects ==========
    pub projects: Vec<Project>,
    pub project_budgets: HashMap<(Pubkey, Pubkey), ProjectCurrencyBudget>, // (project, currency) -> budget

    // ========== User Tracking ==========
    pub project_users: HashMap<(Pubkey, Pubkey), ProjectUser>, // (project, user) -> stats
    pub project_attributions: HashSet<[u8; 32]>, // Used proofs (hash of project_id || proof)
    pub project_attribution_counts: HashMap<Pubkey, u64>, // project_id -> count of attributions (for INV-S2)
    pub user_claim_counts: HashMap<(Pubkey, Pubkey), u64>, // (project_id, user_id) -> claim count (for INV-S3)

    // ========== Keypairs for Fuzzing ==========
    pub authority_keypairs: Vec<Keypair>,
    pub user_keypairs: Vec<Keypair>,
    pub fee_collector_keypair: Keypair,

    // ========== SPL Token Mints ==========
    pub spl_token_mints: Vec<Pubkey>,  // Pre-created SPL token mints for testing

    // ========== Fuzzing Metadata ==========
    pub initialized: bool,
    pub current_timestamp: i64,
    pub transaction_count: u64,

    // ========== Crash Reproduction Data ==========
    /// Protobuf data of current test case (for crash reproduction)
    pub current_protobuf: Option<Vec<u8>>,
    /// RNG seed of current test case (for crash reproduction)
    pub current_seed: Option<u64>,
}

// ========== Global Configuration Structures ==========

#[derive(Debug, Clone)]
pub struct GlobalConfig {
    pub is_initialized: bool,
    pub paused: bool,
    pub project_nonce: u64,
    pub claim_cooldown: u64, // seconds
    pub required_signers_for_claim: u8,
    pub fee_management: FeeManagement,
    pub roles_mapping: GlobalRolesMapping,
}

#[derive(Debug, Clone)]
pub struct FeeManagement {
    pub fee_collector: Pubkey,
    pub no_claim_fee_whitelist: Vec<Pubkey>,
    pub user_native_claim_fee: u64, // lamports
    pub project_claim_fee: u16,     // basis points
    pub remove_fee: u16,             // basis points
}

#[derive(Debug, Clone)]
pub struct GlobalRolesMapping {
    pub roles: Vec<GlobalRoleEntry>,
}

#[derive(Debug, Clone)]
pub struct GlobalRoleEntry {
    pub account: Pubkey,
    pub role: GlobalRole,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GlobalRole {
    Admin,
    Pauser,
    Unpauser,
    Signer,
}

// ========== Currency Token Structures ==========

#[derive(Debug, Clone)]
pub struct CurrencyToken {
    pub is_initialized: bool,
    pub token_mint: Pubkey,
    pub currency_type: CurrencyType,
    pub enabled: bool,
    pub claim_limit_per_cooldown: u64,
    pub cumulative_claim_per_cooldown: u64,
    pub claim_cooldown_period_started: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TokenType {
    Native,
    FungibleSpl,
    NonFungibleSpl,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CurrencyType {
    Native,
    Fungible,
    NonFungible,
}

// ========== Project Structures ==========

#[derive(Debug, Clone)]
pub struct Project {
    pub is_initialized: bool,
    pub project_id: Pubkey,
    pub nonce: u64,
    pub metadata_uri: String,
    pub fee_management: ProjectFeeManagement,
    pub roles_mapping: ProjectRolesMapping,
    pub attributions_count: u64,
    pub default_fee_bps: u16,
    pub cooldown_seconds: u64,
    pub max_claims_per_user: u64,
}

#[derive(Debug, Clone)]
pub struct ProjectFeeManagement {
    pub user_native_claim_fee: Option<u64>,
    pub project_claim_fee: Option<u16>,
    pub remove_fee: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct ProjectRolesMapping {
    pub roles: Vec<ProjectRoleEntry>,
}

#[derive(Debug, Clone)]
pub struct ProjectRoleEntry {
    pub account: Pubkey,
    pub role: ProjectRole,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProjectRole {
    Admin,
    Operator,
}

#[derive(Debug, Clone)]
pub struct ProjectCurrencyBudget {
    pub project_id: Pubkey,
    pub currency_id: Pubkey,
    pub total_deposited: u64,
    pub total_claimed: u64,
    pub available_balance: u64,
}

#[derive(Debug, Clone)]
pub struct ProjectUser {
    pub project_id: Pubkey,
    pub user_id: Pubkey,
    pub total_claimed: u64,
    pub last_claim_timestamp: u64,
    pub claim_count: u64,
    pub total_native_claimed: u64,
}

// ========== Implementation ==========

impl FullSvmState {
    pub fn new() -> Self {
        // Generate keypairs for testing
        let authority_keypairs: Vec<Keypair> = (0..5).map(|_| Keypair::new()).collect();
        let user_keypairs: Vec<Keypair> = (0..10).map(|_| Keypair::new()).collect();
        let fee_collector_keypair = Keypair::new();

        Self {
            global_config: GlobalConfig {
                is_initialized: false,
                paused: false,
                project_nonce: 0,
                claim_cooldown: 86400, // 1 day default
                required_signers_for_claim: 1,
                fee_management: FeeManagement {
                    fee_collector: fee_collector_keypair.pubkey(),
                    no_claim_fee_whitelist: Vec::new(),
                    user_native_claim_fee: 0,
                    project_claim_fee: 0,
                    remove_fee: 0,
                },
                roles_mapping: GlobalRolesMapping { roles: Vec::new() },
            },
            currency_tokens: HashMap::new(),
            projects: Vec::new(),
            project_budgets: HashMap::new(),
            project_users: HashMap::new(),
            project_attributions: HashSet::new(),
            project_attribution_counts: HashMap::new(),
            user_claim_counts: HashMap::new(),
            authority_keypairs,
            user_keypairs,
            fee_collector_keypair,
            spl_token_mints: Vec::new(), // Will be populated when SPL tokens are created
            initialized: false,
            current_timestamp: 1700000000, // Some arbitrary starting timestamp
            transaction_count: 0,
            current_protobuf: None, // Will be set by harness for each test case
            current_seed: None, // Will be set by harness for each test case
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    // ========== Global Config Methods ==========

    pub fn is_paused(&self) -> bool {
        self.global_config.paused
    }

    pub fn has_global_role(&self, account: &Pubkey, role: GlobalRole) -> bool {
        self.global_config.roles_mapping.roles.iter()
            .any(|entry| entry.account == *account && entry.role == role)
    }

    pub fn grant_global_role(&mut self, account: Pubkey, role: GlobalRole) {
        if !self.has_global_role(&account, role.clone()) {
            self.global_config.roles_mapping.roles.push(GlobalRoleEntry {
                account,
                role,
            });
        }
    }

    pub fn revoke_global_role(&mut self, account: &Pubkey, role: &GlobalRole) {
        self.global_config.roles_mapping.roles
            .retain(|entry| !(entry.account == *account && entry.role == *role));
    }

    pub fn count_global_roles(&self, role: GlobalRole) -> usize {
        self.global_config.roles_mapping.roles.iter()
            .filter(|entry| entry.role == role)
            .count()
    }

    // ========== Currency Methods ==========

    pub fn add_currency_token(&mut self, mint: Pubkey, token_type: TokenType, limit: u64) {
        self.currency_tokens.insert(mint, CurrencyToken {
            is_initialized: true,
            token_mint: mint,
            currency_type: match token_type {
                TokenType::Native => CurrencyType::Native,
                TokenType::FungibleSpl => CurrencyType::Fungible,
                TokenType::NonFungibleSpl => CurrencyType::NonFungible,
            },
            enabled: true,
            claim_limit_per_cooldown: limit,
            cumulative_claim_per_cooldown: 0,
            claim_cooldown_period_started: 0,
        });
    }

    pub fn get_currency_token(&self, mint: &Pubkey) -> Option<&CurrencyToken> {
        self.currency_tokens.get(mint)
    }

    pub fn update_currency_token(&mut self, mint: &Pubkey, limit: Option<u64>, is_active: Option<bool>) {
        if let Some(token) = self.currency_tokens.get_mut(mint) {
            if let Some(l) = limit {
                token.claim_limit_per_cooldown = l;
            }
            if let Some(active) = is_active {
                token.enabled = active;
            }
        }
    }

    // ========== Project Methods ==========

    pub fn create_project(&mut self, admin: Pubkey, metadata_uri: String) -> u64 {
        let nonce = self.global_config.project_nonce;
        self.global_config.project_nonce += 1;

        // Derive project PDA
        let project_id = Pubkey::find_program_address(
            &[b"project", &nonce.to_le_bytes()],
            &crate::targets::full_svm::PROGRAM_ID,
        ).0;

        let mut project = Project {
            is_initialized: true,
            project_id,
            nonce,
            metadata_uri,
            default_fee_bps: 0,
            cooldown_seconds: 0,
            max_claims_per_user: 0,
            fee_management: ProjectFeeManagement {
                user_native_claim_fee: None,
                project_claim_fee: None,
                remove_fee: None,
            },
            roles_mapping: ProjectRolesMapping { roles: Vec::new() },
            attributions_count: 0,
        };

        // Grant admin role
        project.roles_mapping.roles.push(ProjectRoleEntry {
            account: admin,
            role: ProjectRole::Admin,
        });

        self.projects.push(project);
        nonce
    }

    pub fn get_project(&self, index: usize) -> Option<&Project> {
        self.projects.get(index)
    }

    pub fn get_project_mut(&mut self, index: usize) -> Option<&mut Project> {
        self.projects.get_mut(index)
    }

    pub fn has_project_role(&self, project_index: usize, account: &Pubkey, role: ProjectRole) -> bool {
        self.projects.get(project_index)
            .map(|p| p.roles_mapping.roles.iter()
                .any(|entry| entry.account == *account && entry.role == role))
            .unwrap_or(false)
    }

    pub fn grant_project_role(&mut self, project_index: usize, account: Pubkey, role: ProjectRole) {
        if let Some(project) = self.projects.get_mut(project_index) {
            if !project.roles_mapping.roles.iter().any(|e| e.account == account && e.role == role) {
                project.roles_mapping.roles.push(ProjectRoleEntry {
                    account,
                    role,
                });
            }
        }
    }

    pub fn revoke_project_role(&mut self, project_index: usize, account: &Pubkey, role: &ProjectRole) {
        if let Some(project) = self.projects.get_mut(project_index) {
            project.roles_mapping.roles
                .retain(|entry| !(entry.account == *account && entry.role == *role));
        }
    }

    // ========== Budget Methods ==========

    pub fn get_project_budget(&self, project: &Pubkey, currency: &Pubkey) -> u64 {
        self.project_budgets
            .get(&(*project, *currency))
            .map(|b| b.available_balance)
            .unwrap_or(0)
    }

    pub fn update_project_budget(&mut self, project: Pubkey, currency: Pubkey, amount: i64) {
        let key = (project, currency);
        let budget = self.project_budgets.entry(key).or_insert(ProjectCurrencyBudget {
            project_id: project,
            currency_id: currency,
            total_deposited: 0,
            total_claimed: 0,
            available_balance: 0,
        });

        if amount > 0 {
            budget.available_balance = budget.available_balance.saturating_add(amount as u64);
        } else {
            budget.available_balance = budget.available_balance.saturating_sub((-amount) as u64);
        }
    }

    // ========== Attribution Methods ==========

    pub fn is_proof_used(&self, proof: &[u8; 32]) -> bool {
        self.project_attributions.contains(proof)
    }

    pub fn mark_proof_used(&mut self, proof: [u8; 32]) {
        self.project_attributions.insert(proof);
    }

    // ========== User Tracking ==========

    pub fn update_user_stats(&mut self, project: Pubkey, user: Pubkey, amount: u64, is_native: bool) {
        let key = (project, user);
        let stats = self.project_users.entry(key).or_insert(ProjectUser {
            project_id: project,
            user_id: user,
            total_claimed: 0,
            last_claim_timestamp: 0,
            claim_count: 0,
            total_native_claimed: 0,
        });

        stats.claim_count += 1;
        stats.total_claimed = stats.total_claimed.saturating_add(amount);
        stats.last_claim_timestamp = self.current_timestamp as u64;
        if is_native {
            stats.total_native_claimed = stats.total_native_claimed.saturating_add(amount);
        }
    }

    // ========== Fee Calculations ==========

    pub fn get_project_claim_fee(&self, project_index: usize) -> u16 {
        self.projects.get(project_index)
            .and_then(|p| p.fee_management.project_claim_fee)
            .unwrap_or(self.global_config.fee_management.project_claim_fee)
    }

    pub fn get_remove_fee(&self, project_index: usize) -> u16 {
        self.projects.get(project_index)
            .and_then(|p| p.fee_management.remove_fee)
            .unwrap_or(self.global_config.fee_management.remove_fee)
    }

    pub fn get_user_native_claim_fee(&self, project_index: usize) -> u64 {
        self.projects.get(project_index)
            .and_then(|p| p.fee_management.user_native_claim_fee)
            .unwrap_or(self.global_config.fee_management.user_native_claim_fee)
    }

    pub fn is_fee_exempt(&self, account: &Pubkey) -> bool {
        self.global_config.fee_management.no_claim_fee_whitelist.contains(account)
    }

    // ========== Helper Methods ==========

    pub fn get_random_authority(&self, index: usize) -> &Keypair {
        &self.authority_keypairs[index % self.authority_keypairs.len()]
    }

    pub fn get_authority_with_role(&self, role: GlobalRole, fallback_index: usize) -> &Keypair {
        // First try to find an authority with the specific role
        for entry in &self.global_config.roles_mapping.roles {
            if entry.role == role {
                // Find the matching keypair
                for keypair in &self.authority_keypairs {
                    if keypair.pubkey() == entry.account {
                        debug_log!("Found authority with {:?} role: {}", role, keypair.pubkey());
                        return keypair;
                    }
                }
            }
        }
        debug_log!("WARNING: No authority with {:?} role found, using fallback", role);
        &self.authority_keypairs[fallback_index % self.authority_keypairs.len()]
    }

    pub fn get_random_user(&self, index: usize) -> &Keypair {
        &self.user_keypairs[index % self.user_keypairs.len()]
    }

    pub fn advance_time(&mut self, seconds: i64) {
        self.current_timestamp += seconds;
    }
}

impl Default for FullSvmState {
    fn default() -> Self {
        Self::new()
    }
}

// Implement ProgramState trait for integration with Solaris harness
impl ProgramState for FullSvmState {
    fn reset(&mut self) {
        *self = Self::new();
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}