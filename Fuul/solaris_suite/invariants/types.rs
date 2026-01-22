use solana_sdk::pubkey::Pubkey;
use std::io::Write;

#[derive(Debug)]
pub struct InvariantViolation {
    /// Which operation triggered the violation (e.g., "DepositFungibleToken", "Claim")
    pub instruction: String,

    /// Invariant ID (e.g., "INV-B1", "INV-R1")
    pub invariant: String,

    /// Description of what went wrong
    pub details: String,

    /// Optional protobuf data for crash reproduction
    pub protobuf_data: Option<Vec<u8>>,

    /// Optional RNG seed for exact reproduction
    pub seed: Option<u64>,
}

impl InvariantViolation {
    /// Create a new invariant violation
    pub fn new(instruction: &str, invariant: &str, details: &str) -> Self {
        Self {
            instruction: instruction.to_string(),
            invariant: invariant.to_string(),
            details: details.to_string(),
            protobuf_data: None,
            seed: None,
        }
    }

    /// Attach protobuf data for reproduction
    pub fn with_protobuf(mut self, data: Vec<u8>) -> Self {
        self.protobuf_data = Some(data);
        self
    }

    /// Attach RNG seed for reproduction
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    pub fn dump_and_abort(&self) -> () {
        // Increment the crash counter for UI
        crate::core::hooks::increment_crash_count();

        // Skip dumping in reproduction mode to avoid duplicate crash files
        if !crate::core::is_repro_mode() {
            let _ = self.dump_to_file();
        }

        // Print violation details to stderr
        eprintln!("\n╔════════════════════════════════════════════════════════════╗");
        eprintln!("║         INVARIANT VIOLATION DETECTED                  ║");
        eprintln!("╠════════════════════════════════════════════════════════════╣");
        eprintln!("║ Instruction:  {:<45} ║", self.instruction);
        eprintln!("║ Invariant:    {:<45} ║", self.invariant);
        eprintln!("╠════════════════════════════════════════════════════════════╣");
        eprintln!("║ Details:                                                   ║");
        for line in self.details.lines() {
            eprintln!("║   {:<56} ║", line);
        }
        eprintln!("╚════════════════════════════════════════════════════════════╝\n");

    }

    /// Write violation details to corpus/crashes/ directory
    fn dump_to_file(&self) -> std::io::Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create crash directory structure: corpus/crashes/<invariant>/
        let crash_dir = std::path::PathBuf::from("corpus")
            .join("crashes")
            .join(&self.invariant);

        std::fs::create_dir_all(&crash_dir)?;

        // Generate unique filename
        let base_name = format!("crash_{}_{}", self.instruction, timestamp);

        // Save detailed report
        let report_path = crash_dir.join(format!("{}.txt", base_name));
        let mut report_file = std::fs::File::create(&report_path)?;

        writeln!(report_file, "═══════════════════════════════════════════════════════════")?;
        writeln!(report_file, "        FUUL PROTOCOL INVARIANT VIOLATION REPORT")?;
        writeln!(report_file, "═══════════════════════════════════════════════════════════")?;
        writeln!(report_file)?;
        writeln!(report_file, "Instruction:  {}", self.instruction)?;
        writeln!(report_file, "Invariant:    {}", self.invariant)?;
        writeln!(report_file, "Timestamp:    {}", timestamp)?;
        if let Some(seed) = self.seed {
            writeln!(report_file, "Seed:         {}", seed)?;
        }
        writeln!(report_file)?;
        writeln!(report_file, "═══ VIOLATION DETAILS ═══")?;
        writeln!(report_file, "{}", self.details)?;
        writeln!(report_file)?;

        // Save protobuf if available for exact reproduction
        if let Some(ref pb_data) = self.protobuf_data {
            use prost::Message as ProstMessage;
            use crate::targets::full_svm::proto::FullSvmChain;

            // Decode binary protobuf and re-serialize as JSON
            let chain = match FullSvmChain::decode(&pb_data[..]) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Warning: Failed to decode protobuf: {:?}", e);
                    writeln!(report_file, "Failed to decode protobuf: {:?}", e)?;
                    return Ok(());
                }
            };

            // Serialize to JSON with seed
            let mut json_value = serde_json::to_value(&chain)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            if let Some(seed) = self.seed {
                if let Some(obj) = json_value.as_object_mut() {
                    obj.insert("_seed".to_string(), serde_json::json!(seed));
                }
            }

            let text_content = serde_json::to_string_pretty(&json_value)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            let pb_path = crash_dir.join(format!("{}.textpb", base_name));
            std::fs::write(&pb_path, text_content)?;

            writeln!(report_file, "═══ REPRODUCTION ═══")?;
            writeln!(report_file, "Test case saved to: {}", pb_path.display())?;
            writeln!(report_file)?;
            writeln!(report_file, "To reproduce this violation, run:")?;
            writeln!(report_file, "  cargo run --bin solaris-fuzz -- full-svm --repro {}", pb_path.display())?;
            writeln!(report_file)?;
            writeln!(report_file, "This will replay the exact sequence that triggered the violation.")?;

            eprintln!("╔═══════════════════════════════════════════════════════════╗");
            eprintln!("║  REPRODUCIBLE TEST CASE SAVED                          ║");
            eprintln!("║  Report: {:<44} ║", report_path.display().to_string());
            eprintln!("║  Replay: {:<44} ║", pb_path.display().to_string());
            eprintln!("╚═══════════════════════════════════════════════════════════╝");
        } else {
            writeln!(report_file, "No protobuf data available for reproduction.")?;
            eprintln!("📄 Violation report saved to: {}", report_path.display());
        }

        // Update summary index
        let summary_path = std::path::PathBuf::from("corpus/crashes/SUMMARY.txt");
        let mut summary = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(summary_path)?;

        writeln!(summary, "[{}] {}/{} - {}",
            timestamp,
            self.instruction,
            self.invariant,
            crash_dir.display()
        )?;

        Ok(())
    }
}

pub fn is_valid_pda(pubkey: &Pubkey, program_id: &Pubkey, seeds: &[&[u8]]) -> bool {
    match Pubkey::find_program_address(seeds, program_id) {
        (expected_pubkey, _bump) => expected_pubkey == *pubkey,
    }
}
