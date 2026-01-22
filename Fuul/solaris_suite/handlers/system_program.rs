use crate::core::harness::HarnessBase;
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    system_instruction,
    system_program,
};

impl HarnessBase {
    /// Handle system program transfer
    pub fn handle_system_transfer(
        &mut self,
        from: &Pubkey,
        to: &Pubkey,
        lamports: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use solana_sdk::{transaction::Transaction, signature::{Keypair, Signer}};

        let instruction = system_instruction::transfer(from, to, lamports);

        let payer = Keypair::new();
        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&payer.pubkey()),
            &[&payer],
            self.svm.latest_blockhash(),
        );

        let _ = crate::execute_transaction!(self, tx);
        Ok(())
    }

    /// Handle system program create account
    pub fn handle_system_create_account(
        &mut self,
        from: &Pubkey,
        to: &Pubkey,
        lamports: u64,
        space: u64,
        owner: &Pubkey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use solana_sdk::{transaction::Transaction, signature::{Keypair, Signer}};

        let instruction = system_instruction::create_account(
            from,
            to,
            lamports,
            space,
            owner,
        );

        let payer = Keypair::new();
        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&payer.pubkey()),
            &[&payer],
            self.svm.latest_blockhash(),
        );

        let _ = crate::execute_transaction!(self, tx);
        Ok(())
    }
}