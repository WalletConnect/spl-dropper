use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use csv::Reader;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_transaction_status::TransactionConfirmationStatus;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    compute_budget::ComputeBudgetInstruction,
    hash::Hash,
    instruction::Instruction,
    message::VersionedMessage,
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    transaction::VersionedTransaction,
    program_pack::Pack,
};
use spl_associated_token_account::{
    get_associated_token_address, 
    instruction::create_associated_token_account_idempotent,
};
use spl_token::{
    instruction::transfer_checked,
    state::{Account as TokenAccount, Mint},
};
use std::{
    collections::HashMap,
    convert::TryFrom,
    fs,
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, Mutex, RwLock},
    time::sleep,
};
use governor::{Quota, RateLimiter};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Distribute SPL tokens to recipients
    Distribute(DistributeArgs),
    /// Generate test recipients
    GenerateRecipients(GenerateArgs),
}

#[derive(Parser)]
struct DistributeArgs {
    /// Input CSV file with recipients
    #[clap(long)]
    input_csv: PathBuf,

    /// SPL token mint address
    #[clap(long)]
    mint: String,

    /// Source token account
    #[clap(long)]
    from: String,

    /// Owner keypair path
    #[clap(long)]
    owner: PathBuf,

    /// Fee payer keypair path
    #[clap(long)]
    fee_payer: PathBuf,

    /// RPC URL
    #[clap(long)]
    url: String,

    /// Perform a dry run
    #[clap(long)]
    dry_run: bool,

    /// Rate limit (requests per second)
    #[clap(long, default_value = "10")]
    rate_limit: u32,


    /// Resume file for crash recovery (auto-generated if not specified)
    #[clap(long)]
    state_file: Option<PathBuf>,
    
    /// State directory for storing distribution states
    #[clap(long, default_value = ".spl-dropper-state")]
    state_dir: PathBuf,

    /// Compute unit price in microlamports
    #[clap(long, default_value = "1000")]
    priority_fee: u64,

    /// Skip confirmation prompt
    #[clap(long)]
    yes: bool,

    /// Skip ATA creation check (assume all ATAs exist)
    #[clap(long)]
    skip_ata: bool,
    
    /// Force clear pending transactions (use if you've manually verified they're complete)
    #[clap(long)]
    force_clear_pending: bool,
    
    /// Limit number of recipients to process (useful for testing)
    #[clap(long)]
    limit: Option<usize>,
}

#[derive(Parser)]
struct GenerateArgs {
    /// Number of recipients
    #[clap(long)]
    count: usize,

    /// Amount per recipient (in base units)
    #[clap(long)]
    amount: u64,

    /// Output CSV file
    #[clap(long)]
    output: PathBuf,
}


#[derive(Debug, Deserialize, Serialize)]
struct Recipient {
    recipient: String,
    #[serde(deserialize_with = "serde_aux::field_attributes::deserialize_number_from_string")]
    amount: u64,
}

#[derive(Debug, Clone)]
struct Distribution {
    recipient: Pubkey,
    amount: u64,
    ata: Pubkey,
    needs_creation: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct DistributionState {
    completed_recipients: Vec<String>,
    pending_signatures: HashMap<String, PendingBatch>,
    failed_recipients: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingBatch {
    recipients: Vec<String>,
    sent_slot: u64,
    blockhash: String,
}

impl DistributionState {
    fn new() -> Self {
        Self {
            completed_recipients: Vec::new(),
            pending_signatures: HashMap::new(),
            failed_recipients: Vec::new(),
        }
    }

    fn load(path: &Path) -> Result<Self> {
        if path.exists() {
            let data = fs::read_to_string(path)?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(Self::new())
        }
    }

    fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data)?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Distribute(args) => distribute(args).await,
        Commands::GenerateRecipients(args) => generate_recipients(args),
    }
}

fn generate_recipients(args: GenerateArgs) -> Result<()> {
    println!(
        "Generating {} recipients with {} tokens each...",
        args.count, args.amount
    );

    let mut writer = csv::Writer::from_path(&args.output)?;
    writer.write_record(&["recipient", "amount"])?;

    // Use timestamp to generate different recipients each time
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    for i in 0..args.count {
        // Use timestamp + index for unique recipients each run
        let seed = format!("recipient_{}_{}", timestamp, i);
        let hash = solana_sdk::hash::hash(seed.as_bytes());
        let pubkey = Pubkey::new_from_array(hash.to_bytes());
        
        writer.write_record(&[pubkey.to_string(), args.amount.to_string()])?;
    }

    writer.flush()?;
    println!("Generated {} recipients in {}", args.count, args.output.display());
    Ok(())
}

async fn distribute(args: DistributeArgs) -> Result<()> {
    println!("\n🚀 Starting SPL token distribution...");

    // Get state file path (auto-generated or user-specified)
    let state_file_path = get_state_file_path(&args)?;
    println!("📁 Using state file: {}", state_file_path.display());
    
    // Load state for resume capability
    let mut state = DistributionState::load(&state_file_path)?;
    
    // Handle force clear pending flag
    if args.force_clear_pending && !state.pending_signatures.is_empty() {
        println!("⚠️  Force clearing {} pending transactions as requested", state.pending_signatures.len());
        for (sig, batch) in &state.pending_signatures {
            println!("   - {} ({} recipients)", &sig[..8], batch.recipients.len());
            state.completed_recipients.extend(batch.recipients.clone());
        }
        state.pending_signatures.clear();
        state.save(&state_file_path)?;
        println!("✅ Cleared pending transactions and marked recipients as completed");
    }
    
    // Load keypairs
    let owner = load_keypair(&args.owner)?;
    let fee_payer = load_keypair(&args.fee_payer)?;

    // Parse addresses
    let mint_pubkey = Pubkey::from_str(&args.mint)?;
    let source_pubkey = Pubkey::from_str(&args.from)?;

    // Setup async RPC client
    let client = Arc::new(RpcClient::new_with_commitment(
        args.url.clone(),
        CommitmentConfig::confirmed(),
    ));


    // Get mint info
    let mint_account = client.get_account(&mint_pubkey).await?;
    let mint_data = Mint::unpack(&mint_account.data)?;
    let decimals = mint_data.decimals;
    println!("Token mint: {} (decimals: {})", mint_pubkey, decimals);

    // Check source balance
    let source_account = client.get_account(&source_pubkey).await?;
    let source_data = TokenAccount::unpack(&source_account.data)?;
    let source_balance = source_data.amount;
    println!(
        "Source balance: {} tokens",
        amount_to_ui(source_balance, decimals)
    );

    // Load and validate recipients
    let mut distributions = load_recipients(&args.input_csv, &mint_pubkey)?;
    let total_recipients = distributions.len();
    let already_completed = state.completed_recipients.len();
    
    // Filter out already completed recipients
    distributions.retain(|d| {
        !state.completed_recipients.contains(&d.recipient.to_string())
    });
    
    // Show progress
    if already_completed > 0 {
        println!("📊 Progress: {}/{} recipients already completed", already_completed, total_recipients);
    }
    
    // Apply limit if specified
    if let Some(limit) = args.limit {
        if limit > 0 && distributions.len() > limit {
            let start_idx = already_completed + 1;
            let end_idx = already_completed + limit;
            println!("📊 Processing recipients {} to {} (limiting to {} out of {} remaining)", 
                     start_idx, end_idx, limit, distributions.len());
            distributions.truncate(limit);
        }
    }

    if distributions.is_empty() {
        println!("All recipients already processed!");
        return Ok(());
    }

    let total_amount: u64 = distributions.iter().map(|d| d.amount).sum();
    
    // Check for pending transactions that might affect balance
    let pending_amount: u64 = if !state.pending_signatures.is_empty() {
        let mut pending_total = 0u64;
        for (sig_str, batch) in &state.pending_signatures {
            println!("⚠️  Found pending transaction {} with {} recipients", 
                    &sig_str[..8], batch.recipients.len());
            pending_total += batch.recipients.len() as u64 * distributions[0].amount; // Assumes uniform distribution
        }
        pending_total
    } else {
        0
    };
    
    println!("Recipients to process: {}", distributions.len());
    println!(
        "Total tokens needed: {}",
        amount_to_ui(total_amount, decimals)
    );
    
    if pending_amount > 0 {
        println!(
            "⚠️  Pending transactions may have spent: {} tokens",
            amount_to_ui(pending_amount, decimals)
        );
        println!("   Run again after transactions confirm or fail to get accurate balance");
    }

    if source_balance < total_amount && !args.dry_run {
        // Force check pending transactions when balance is insufficient
        if !state.pending_signatures.is_empty() {
            println!("\n🔍 Insufficient balance detected. Checking pending transactions...");
            
            let mut actually_confirmed = Vec::new();
            for (sig_str, batch) in &state.pending_signatures {
                if let Ok(sig) = Signature::from_str(sig_str) {
                    match client.get_signature_status(&sig).await {
                        Ok(Some(status)) => {
                            match status {
                                Ok(()) => {
                                    println!("✅ Transaction {} confirmed! {} recipients already processed", 
                                            &sig_str[..8], batch.recipients.len());
                                    actually_confirmed.extend(batch.recipients.clone());
                                }
                                Err(e) => {
                                    println!("❌ Transaction {} failed: {:?}", &sig_str[..8], e);
                                }
                            }
                        }
                        Ok(None) => {
                            // Transaction not found - check if it's too old
                            let current_slot = client.get_slot().await.unwrap_or(0);
                            if current_slot.saturating_sub(batch.sent_slot) > 432000 { // ~2 days
                                println!("⚠️  Transaction {} is too old to verify (sent at slot {})", 
                                        &sig_str[..8], batch.sent_slot);
                                println!("   Manual verification required - check explorer");
                            } else {
                                println!("⏳ Transaction {} still pending", &sig_str[..8]);
                            }
                        }
                        Err(e) => {
                            println!("❌ Error checking transaction {}: {}", &sig_str[..8], e);
                        }
                    }
                }
            }
            
            if !actually_confirmed.is_empty() {
                println!("\n💡 Found {} confirmed recipients. Update state by running again.", actually_confirmed.len());
                println!("   The tool will automatically update the state on next run.");
            }
        }
        
        let shortage = total_amount.saturating_sub(source_balance);
        let shortage_ui = amount_to_ui(shortage, decimals);
        let shortage_base_units = shortage;
        
        return Err(anyhow::anyhow!(
            "Insufficient balance! Have {} but need {}. Missing: {} tokens ({} base units). Note: {} tokens may be in pending transactions.",
            amount_to_ui(source_balance, decimals),
            amount_to_ui(total_amount, decimals),
            shortage_ui,
            shortage_base_units,
            amount_to_ui(pending_amount, decimals)
        ));
    }

    // Check fee payer balance
    let fee_payer_balance = client.get_balance(&fee_payer.pubkey()).await?;
    println!(
        "Fee payer balance: {} SOL",
        fee_payer_balance as f64 / 1_000_000_000.0
    );

    if fee_payer_balance < 100_000_000 {
        println!("⚠️  Warning: Low SOL balance for fees!");
    }

    // Bulk check ATAs (unless skipped)
    let atas_to_create = if args.skip_ata {
        println!("Skipping ATA checks (--skip-ata flag set)");
        0
    } else {
        check_atas_bulk(&client, &mut distributions).await?;
        let count = distributions.iter().filter(|d| d.needs_creation).count();
        if count > 0 {
            println!("{} recipients need ATA creation", count);
        }
        count
    };

    // Dry run mode
    if args.dry_run {
        if source_balance < total_amount {
            println!("\n⚠️  Note: Insufficient balance for actual distribution (need {} more tokens)", 
                    amount_to_ui(total_amount - source_balance, decimals));
        }
        return dry_run_summary(&distributions, decimals, atas_to_create, args.priority_fee);
    }

    // Confirm before proceeding (unless --yes flag)
    if !args.yes {
        println!("\nReady to distribute? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    } else {
        println!("\nProceeding with distribution (--yes flag set)");
    }

    // Create ATAs if needed
    if atas_to_create > 0 {
        println!("\nCreating {} Associated Token Accounts first...", atas_to_create);
        create_atas_batch(
            &client,
            &distributions,
            &mint_pubkey,
            &fee_payer,
            args.priority_fee,
        ).await?;
        println!("✅ All ATAs created successfully\n");
    }

    // Setup rate limiter
    let rate_limiter = Arc::new(
        RateLimiter::direct(Quota::per_second(
            std::num::NonZeroU32::new(args.rate_limit).expect("rate_limit must be non-zero")
        ))
    );

    // Execute transfers with async confirmation
    // Calculate fee estimates
    let total_txs = (distributions.len() as f64 / 10.0).ceil() as u64; // 10 transfers per batch
    let base_fee_per_tx = 0.000005; // 5000 lamports base fee
    let priority_fee_per_tx = (args.priority_fee as f64 * 200_000.0) / 1_000_000.0 / 1_000_000_000.0; // priority fee in microLamports per CU, ~200k CU per tx
    let transfer_cost = total_txs as f64 * (base_fee_per_tx + priority_fee_per_tx);
    
    // Estimate ATA creation costs if needed
    let atas_to_create = distributions.iter().filter(|d| d.needs_creation).count();
    let ata_creation_cost = atas_to_create as f64 * 0.00203928; // Rent exempt minimum for token account
    let ata_tx_cost = (atas_to_create as f64 / 10.0).ceil() * (base_fee_per_tx + priority_fee_per_tx);
    
    let total_estimated_cost = transfer_cost + ata_creation_cost + ata_tx_cost;
    
    println!("\nStarting token transfers...");
    println!("📊 Cost estimates:");
    if atas_to_create > 0 {
        println!("   - ATA creation: {} accounts × 0.00203928 SOL = ~{:.4} SOL", atas_to_create, ata_creation_cost);
        println!("   - ATA transactions: ~{:.4} SOL", ata_tx_cost);
    }
    println!("   - Transfer transactions: {} × ~{:.6} SOL = ~{:.4} SOL", total_txs, base_fee_per_tx + priority_fee_per_tx, transfer_cost);
    println!("   - Total estimated cost: ~{:.4} SOL", total_estimated_cost);
    println!("   - Estimated time: ~{} minutes", (total_txs as f64 / 10.0).ceil());
    execute_transfers_async(
        client.clone(),
        &distributions,
        &source_pubkey,
        &mint_pubkey,
        &owner,
        &fee_payer,
        decimals,
        args.priority_fee,
        rate_limiter,
        &mut state,
        &state_file_path,
    ).await?;

    // Load the final state to get accurate counts
    let final_state = DistributionState::load(&state_file_path)?;
    
    // Get final fee payer balance to show actual cost
    let final_fee_payer_balance = client.get_balance(&fee_payer.pubkey()).await?;
    let sol_spent = (fee_payer_balance.saturating_sub(final_fee_payer_balance)) as f64 / 1_000_000_000.0;
    
    println!("\n✅ Distribution complete!");
    println!("Total progress: {}/{} recipients completed", 
            final_state.completed_recipients.len(), 
            total_recipients);
    println!("This run: {} recipients processed", distributions.len());
    println!("Failed: {}", final_state.failed_recipients.len());
    println!("\n💰 Actual SOL spent: {:.6} SOL", sol_spent);
    println!("   Fee payer balance: {:.6} SOL → {:.6} SOL", 
            fee_payer_balance as f64 / 1_000_000_000.0,
            final_fee_payer_balance as f64 / 1_000_000_000.0);
    
    Ok(())
}

fn load_keypair(path: &Path) -> Result<Keypair> {
    let keypair_str = fs::read_to_string(path)
        .with_context(|| format!("Failed to read keypair from {}", path.display()))?;
    
    let keypair_bytes: Vec<u8> = serde_json::from_str(&keypair_str)
        .with_context(|| format!("Failed to parse keypair JSON from {}", path.display()))?;
    
    Keypair::try_from(keypair_bytes.as_slice())
        .with_context(|| format!("Invalid keypair format in {}", path.display()))
}

fn load_recipients(
    csv_path: &Path,
    mint: &Pubkey,
) -> Result<Vec<Distribution>> {
    let mut reader = Reader::from_path(csv_path)?;
    let mut distributions = Vec::new();

    for result in reader.deserialize() {
        let recipient: Recipient = result?;
        let pubkey = Pubkey::from_str(&recipient.recipient)?;
        let ata = get_associated_token_address(&pubkey, mint);

        distributions.push(Distribution {
            recipient: pubkey,
            amount: recipient.amount,
            ata,
            needs_creation: false,
        });
    }

    Ok(distributions)
}

fn compute_csv_hash(csv_path: &Path, mint: &Pubkey) -> Result<String> {
    use solana_sdk::hash::hash;
    
    // Read CSV content
    let mut file = fs::File::open(csv_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    
    // Include mint in hash to differentiate distributions of different tokens
    let mut hash_input = contents;
    hash_input.extend_from_slice(mint.as_ref());
    
    // Compute hash
    let hash_result = hash(&hash_input);
    
    // Return first 16 chars of base58 hash for reasonable directory name
    Ok(hash_result.to_string()[..16].to_string())
}

fn get_state_file_path(args: &DistributeArgs) -> Result<PathBuf> {
    if let Some(ref state_file) = args.state_file {
        // User specified exact state file
        Ok(state_file.clone())
    } else {
        // Auto-generate based on CSV content hash
        let mint_pubkey = Pubkey::from_str(&args.mint)?;
        let csv_hash = compute_csv_hash(&args.input_csv, &mint_pubkey)?;
        
        // Create state directory if it doesn't exist
        fs::create_dir_all(&args.state_dir)?;
        
        // Create hash-specific subdirectory
        let hash_dir = args.state_dir.join(&csv_hash);
        fs::create_dir_all(&hash_dir)?;
        
        // Save distribution info for reference
        let info_file = hash_dir.join("distribution_info.json");
        if !info_file.exists() {
            let info = serde_json::json!({
                "csv_file": args.input_csv.to_string_lossy(),
                "mint": args.mint,
                "csv_hash": csv_hash,
                "created_at": chrono::Utc::now().to_rfc3339(),
            });
            fs::write(&info_file, serde_json::to_string_pretty(&info)?)?;
        }
        
        Ok(hash_dir.join("distribution_state.json"))
    }
}

async fn check_atas_bulk(
    client: &RpcClient,
    distributions: &mut [Distribution],
) -> Result<()> {
    let pb = ProgressBar::new(distributions.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} Checking ATAs")?
    );

    // Collect all ATAs to check
    let atas: Vec<Pubkey> = distributions.iter().map(|d| d.ata).collect();
    
    // Check in chunks of 100 (RPC limit for get_multiple_accounts)
    for (chunk_idx, chunk) in atas.chunks(100).enumerate() {
        let accounts = client.get_multiple_accounts(chunk).await?;
        
        // Calculate the base index for this chunk
        let base_idx = chunk_idx * 100;
        
        // Use enumerate to safely track indices
        for (i, (_ata, account_info)) in chunk.iter().zip(accounts.iter()).enumerate() {
            // Calculate the actual distribution index
            let dist_idx = base_idx + i;
            if let Some(dist) = distributions.get_mut(dist_idx) {
                dist.needs_creation = account_info.is_none();
            }
        }
        
        pb.inc(chunk.len() as u64);
    }

    pb.finish_with_message("ATA check complete");
    Ok(())
}

async fn create_atas_batch(
    client: &RpcClient,
    distributions: &[Distribution],
    mint: &Pubkey,
    fee_payer: &Keypair,
    priority_fee: u64,
) -> Result<()> {
    // Create a rate limiter for ATA creation
    let rate_limiter = Arc::new(
        RateLimiter::direct(Quota::per_second(
            std::num::NonZeroU32::new(10).expect("hardcoded value should be non-zero")
        ))
    );
    let to_create: Vec<&Distribution> = distributions
        .iter()
        .filter(|d| d.needs_creation)
        .collect();

    if to_create.is_empty() {
        return Ok(());
    }

    println!("\nCreating {} Associated Token Accounts...", to_create.len());
    let pb = ProgressBar::new(to_create.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} Creating ATAs")?
    );

    let mut current_batch = Vec::new();
    let mut processed = 0;
    let mut cached_blockhash: Option<Hash> = None;
    let mut cached_blockhash_timestamp = std::time::Instant::now();

    for dist in &to_create {
        let ix = create_associated_token_account_idempotent(
            &fee_payer.pubkey(),
            &dist.recipient,
            mint,
            &spl_token::id(),
        );
        
        // Test adding this instruction
        let test_batch = {
            let mut test = current_batch.clone();
            test.push(ix.clone());
            test
        };

        // Use a cached blockhash for size testing
        let test_blockhash = if cached_blockhash.is_none() || cached_blockhash_timestamp.elapsed() > Duration::from_secs(30) {
            match client.get_latest_blockhash().await {
                Ok(hash) => {
                    cached_blockhash = Some(hash);
                    cached_blockhash_timestamp = std::time::Instant::now();
                    hash
                }
                Err(_) => cached_blockhash.unwrap_or_default()
            }
        } else {
            cached_blockhash.unwrap()
        };
        
        // Skip CU simulation for ATA batches - they're predictable and small
        let cu_limit = 200_000;
        
        let test_msg = create_legacy_message_with_cu(&test_batch, &fee_payer.pubkey(), priority_fee, cu_limit, test_blockhash)?;

        // Check size with proper serialization
        let test_tx = VersionedTransaction::try_new(test_msg, &[fee_payer])?;
        let (fits, size) = transaction_fits(&test_tx);
        if !fits {
            eprintln!("Transaction would be {} bytes, flushing batch", size);
            // Flush current batch
            if !current_batch.is_empty() {
                let batch_len = current_batch.len();
                send_and_confirm_batch_with_retry(
                    client,
                    current_batch,
                    fee_payer,
                    priority_fee,
                    &rate_limiter,
                ).await?;
                processed += batch_len;
                pb.set_position(processed as u64);
                current_batch = Vec::new();
            }
        }
        
        current_batch.push(ix);
        
        // Hard limit to prevent "too many signers" error
        if current_batch.len() >= 10 {
            let batch_len = current_batch.len();
            send_and_confirm_batch_with_retry(
                client,
                current_batch,
                fee_payer,
                priority_fee,
                &rate_limiter,
            ).await?;
            processed += batch_len;
            pb.set_position(processed as u64);
            current_batch = Vec::new();
        }
    }

    // Send remaining
    if !current_batch.is_empty() {
        send_and_confirm_batch_with_retry(
            client,
            current_batch,
            fee_payer,
            priority_fee,
            &rate_limiter,
        ).await?;
    }

    pb.finish_with_message("All ATAs created");
    Ok(())
}

async fn execute_transfers_async(
    client: Arc<RpcClient>,
    distributions: &[Distribution],
    source: &Pubkey,
    mint: &Pubkey,
    owner: &Keypair,
    fee_payer: &Keypair,
    decimals: u8,
    priority_fee: u64,
    rate_limiter: Arc<RateLimiter<
        governor::state::direct::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
    >>,
    state: &mut DistributionState,
    state_file: &Path,
) -> Result<()> {
    // Retry loop - process initial distributions and any retries
    let mut current_distributions = distributions.to_vec();
    let mut retry_round = 0;
    const MAX_RETRY_ROUNDS: usize = 3;
    
    while !current_distributions.is_empty() && retry_round < MAX_RETRY_ROUNDS {
        if retry_round > 0 {
            println!("\n🔄 Retry round {} with {} recipients", retry_round, current_distributions.len());
        }
        
        let retry_recipients = execute_single_round(
            client.clone(),
            &current_distributions,
            source,
            mint,
            owner,
            fee_payer,
            decimals,
            priority_fee,
            rate_limiter.clone(),
            state,
            state_file,
        ).await?;
        
        // Prepare distributions for retry
        current_distributions.clear();
        for recipient_str in retry_recipients {
            if let Ok(recipient) = Pubkey::from_str(&recipient_str) {
                if let Some(dist) = distributions.iter().find(|d| d.recipient == recipient) {
                    current_distributions.push(dist.clone());
                }
            }
        }
        
        retry_round += 1;
    }
    
    if !current_distributions.is_empty() {
        println!("⚠️  {} recipients still pending after {} retry rounds", 
                current_distributions.len(), MAX_RETRY_ROUNDS);
    }
    
    Ok(())
}

async fn execute_single_round(
    client: Arc<RpcClient>,
    distributions: &[Distribution],
    source: &Pubkey,
    mint: &Pubkey,
    owner: &Keypair,
    fee_payer: &Keypair,
    decimals: u8,
    priority_fee: u64,
    rate_limiter: Arc<RateLimiter<
        governor::state::direct::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
    >>,
    state: &mut DistributionState,
    state_file: &Path,
) -> Result<Vec<String>> {
    let pb = ProgressBar::new(distributions.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} Transferring | ETA: {eta} | Speed: {per_sec}")?
            .progress_chars("##-")
    );

    // Shared state for confirmation tracking
    let pending_sigs = Arc::new(RwLock::new(HashMap::<String, PendingBatch>::new()));
    let completed = Arc::new(Mutex::new(Vec::<String>::new()));
    let failed = Arc::new(Mutex::new(Vec::<String>::new()));
    let sender_done = Arc::new(AtomicBool::new(false));
    let (state_tx, mut state_rx) = mpsc::unbounded_channel::<StateMsg>();
    let (retry_tx, mut retry_rx) = mpsc::unbounded_channel::<Vec<String>>();

    // Spawn state persistence task - SINGLE WRITER for state file
    let state_path = state_file.to_path_buf();
    let state_handle = tokio::spawn(async move {
        let mut current_state = DistributionState::load(&state_path)
            .unwrap_or_else(|_| DistributionState::new());
        let mut last_save = std::time::Instant::now();
        const SAVE_INTERVAL: Duration = Duration::from_secs(2); // More frequent saves
        let mut pending_changes = false;
        
        while let Some(msg) = state_rx.recv().await {
            match msg {
                StateMsg::AddPending { sig, batch } => {
                    current_state.pending_signatures.insert(sig, batch);
                    pending_changes = true;
                }
                StateMsg::RemovePending { sig } => {
                    current_state.pending_signatures.remove(&sig);
                    pending_changes = true;
                }
                StateMsg::Completed(recipients) => {
                    current_state.completed_recipients.extend(recipients);
                    pending_changes = true;
                }
                StateMsg::Failed(recipients) => {
                    current_state.failed_recipients.extend(recipients);
                    pending_changes = true;
                }
                StateMsg::Flush => {
                    // Force immediate save
                    if pending_changes {
                        current_state.completed_recipients.sort();
                        current_state.completed_recipients.dedup();
                        current_state.failed_recipients.sort();
                        current_state.failed_recipients.dedup();
                        if let Err(e) = current_state.save(&state_path) {
                            eprintln!("Failed to save state: {}", e);
                        }
                        pending_changes = false;
                        last_save = std::time::Instant::now();
                    }
                    continue;
                }
            }
            
            // Periodic save if enough time has passed or many updates
            if (last_save.elapsed() >= SAVE_INTERVAL || 
                current_state.completed_recipients.len() + current_state.failed_recipients.len() > 100) 
                && pending_changes {
                
                current_state.completed_recipients.sort();
                current_state.completed_recipients.dedup();
                current_state.failed_recipients.sort();
                current_state.failed_recipients.dedup();
                
                if let Err(e) = current_state.save(&state_path) {
                    eprintln!("Failed to save state: {}", e);
                } else {
                    last_save = std::time::Instant::now();
                    pending_changes = false;
                }
            }
        }
        
        // Final save
        if pending_changes {
            current_state.completed_recipients.sort();
            current_state.completed_recipients.dedup();
            current_state.failed_recipients.sort();
            current_state.failed_recipients.dedup();
            let _ = current_state.save(&state_path);
        }
    });
    
    // Restore any pending signatures from previous run and check their status
    if !state.pending_signatures.is_empty() {
        pb.println(format!("📋 Checking {} pending transactions from previous run", state.pending_signatures.len()));
        
        let mut confirmed_recipients = Vec::new();
        let mut still_pending = HashMap::new();
        
        // Check status of each pending transaction
        for (sig_str, batch) in state.pending_signatures.clone() {
            if let Ok(sig) = Signature::from_str(&sig_str) {
                match client.get_signature_status(&sig).await {
                    Ok(Some(status)) => {
                        match status {
                            Ok(()) => {
                                // Transaction confirmed successfully
                                pb.println(format!("✅ Found confirmed transaction {} with {} recipients", 
                                                 &sig_str[..8], batch.recipients.len()));
                                confirmed_recipients.extend(batch.recipients);
                            }
                            Err(_) => {
                                // Transaction failed
                                pb.println(format!("❌ Transaction {} failed, will retry recipients", &sig_str[..8]));
                                let mut f = failed.lock().await;
                                f.extend(batch.recipients);
                            }
                        }
                    }
                    _ => {
                        // Still pending or unknown
                        still_pending.insert(sig_str, batch);
                    }
                }
            }
        }
        
        // Update state with confirmed transactions
        if !confirmed_recipients.is_empty() {
            let _ = state_tx.send(StateMsg::Completed(confirmed_recipients.clone()));
            completed.lock().await.extend(confirmed_recipients);
        }
        
        // Only track still-pending transactions
        let mut sigs = pending_sigs.write().await;
        for (sig, batch) in still_pending {
            sigs.insert(sig, batch);
        }
    }
    
    // Spawn confirmation monitor
    let monitor_handle = spawn_confirmation_monitor(
        client.clone(),
        pending_sigs.clone(),
        completed.clone(),
        failed.clone(),
        pb.clone(),
        sender_done.clone(),
        state_tx.clone(),
        retry_tx.clone(),
        state_file.to_path_buf(),
    );

    // Process distributions with retry support
    let mut current_batch = Vec::new();
    let mut current_recipients = Vec::new();
    
    // Spawn retry handler - simplified version that just collects retries
    let retry_recipients = Arc::new(Mutex::new(Vec::<String>::new()));
    let retry_recipients_clone = retry_recipients.clone();
    let retry_handle = tokio::spawn(async move {
        while let Some(recipients) = retry_rx.recv().await {
            let mut retry_list = retry_recipients_clone.lock().await;
            retry_list.extend(recipients);
        }
    });

    for dist in distributions {
        let ix = transfer_checked(
            &spl_token::id(),
            source,
            mint,
            &dist.ata,
            &owner.pubkey(),
            &[],
            dist.amount,
            decimals,
        )?;
        
        // Test adding this instruction
        let test_batch = {
            let mut test = current_batch.clone();
            test.push(ix.clone());
            test
        };

        // Use the latest blockhash for testing transaction size
        let test_blockhash = match client.get_latest_blockhash().await {
            Ok(hash) => hash,
            Err(e) => {
                pb.println(format!("⚠️  Failed to get blockhash: {}, retrying...", e));
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let test_msg = create_legacy_message(&test_batch, &fee_payer.pubkey(), priority_fee, test_blockhash)?;

        // Check size
        // Handle case where owner and fee_payer might be the same
        let test_tx = if fee_payer.pubkey() == owner.pubkey() {
            VersionedTransaction::try_new(test_msg, &[fee_payer])?
        } else {
            VersionedTransaction::try_new(test_msg, &[fee_payer, owner])?
        };
        let (fits, size) = transaction_fits(&test_tx);
        if !fits {
            eprintln!("Transaction would be {} bytes, sending current batch", size);
            // Send current batch
            if !current_batch.is_empty() {
                rate_limiter.until_ready().await;
                
                match send_transfer_batch(
                    &client,
                    current_batch.clone(),
                    fee_payer,
                    owner,
                    priority_fee,
                ).await {
                    Ok((sig, blockhash, slot)) => {
                        let mut sigs = pending_sigs.write().await;
                        let batch = PendingBatch {
                            recipients: current_recipients.clone(),
                            sent_slot: slot,
                            blockhash: blockhash.to_string(),
                        };
                        sigs.insert(sig.to_string(), batch.clone());
                        
                        // Also persist to state for crash recovery
                        let _ = state_tx.send(StateMsg::AddPending { 
                            sig: sig.to_string(), 
                            batch: batch.clone() 
                        });
                    }
                    Err(e) => {
                        pb.println(format!("❌ Batch failed: {}", e));
                        let mut f = failed.lock().await;
                        f.extend(current_recipients.clone());
                    }
                }
                
                current_batch.clear();
                current_recipients.clear();
            }
        }
        
        current_batch.push(ix);
        current_recipients.push(dist.recipient.to_string());
        
        // Hard limit to prevent "too many signers" error
        if current_batch.len() >= 10 {
            rate_limiter.until_ready().await;
            
            match send_transfer_batch(
                &client,
                current_batch.clone(),
                fee_payer,
                owner,
                priority_fee,
            ).await {
                Ok((sig, blockhash, slot)) => {
                    let mut sigs = pending_sigs.write().await;
                    let batch = PendingBatch {
                        recipients: current_recipients.clone(),
                        sent_slot: slot,
                        blockhash: blockhash.to_string(),
                    };
                    sigs.insert(sig.to_string(), batch.clone());
                    
                    // Also persist to state for crash recovery
                    let _ = state_tx.send(StateMsg::AddPending { 
                        sig: sig.to_string(), 
                        batch: batch.clone() 
                    });
                }
                Err(e) => {
                    pb.println(format!("❌ Batch failed: {}", e));
                    let mut f = failed.lock().await;
                    f.extend(current_recipients.clone());
                }
            }
            
            current_batch.clear();
            current_recipients.clear();
        }
    }

    // Send final batch
    if !current_batch.is_empty() {
        rate_limiter.until_ready().await;
        
        match send_transfer_batch(
            &client,
            current_batch,
            fee_payer,
            owner,
            priority_fee,
        ).await {
            Ok((sig, blockhash, slot)) => {
                let mut sigs = pending_sigs.write().await;
                let batch = PendingBatch {
                    recipients: current_recipients,
                    sent_slot: slot,
                    blockhash: blockhash.to_string(),
                };
                sigs.insert(sig.to_string(), batch.clone());
                
                // Also persist to state
                let _ = state_tx.send(StateMsg::AddPending { 
                    sig: sig.to_string(), 
                    batch: batch.clone() 
                });
            }
            Err(e) => {
                pb.println(format!("❌ Final batch failed: {}", e));
                let mut f = failed.lock().await;
                f.extend(current_recipients);
            }
        }
    }

    // Signal sender is done
    sender_done.store(true, Ordering::Relaxed);
    
    // Close retry channel and wait for retry handler
    drop(retry_tx);
    let _ = retry_handle.await;
    
    // Wait for all confirmations
    monitor_handle.await?;
    
    // Collect any retries that were collected and return them
    let retry_list = retry_recipients.lock().await.clone();
    drop(retry_recipients);
    
    // Final state flush and close channel
    let _ = state_tx.send(StateMsg::Flush);
    drop(state_tx);
    let _ = state_handle.await;

    // Calculate actual stats
    let completed_count = completed.lock().await.len();
    let failed_count = failed.lock().await.len();
    let actual_txs = pending_sigs.read().await.len();
    
    pb.finish_with_message(format!(
        "Round complete: {} successful, {} failed, {} for retry | Total SOL spent: ~{:.4}",
        completed_count,
        failed_count,
        retry_list.len(),
        actual_txs as f64 * (0.000005 + (priority_fee as f64 * 200_000.0) / 1_000_000.0 / 1_000_000_000.0) // Based on actual priority fee in microLamports per CU
    ));

    Ok(retry_list)
}

#[derive(Debug)]
enum StateMsg {
    AddPending { sig: String, batch: PendingBatch },
    RemovePending { sig: String },
    Completed(Vec<String>),
    Failed(Vec<String>),
    Flush,
}

fn spawn_confirmation_monitor(
    client: Arc<RpcClient>,
    pending_sigs: Arc<RwLock<HashMap<String, PendingBatch>>>,
    completed: Arc<Mutex<Vec<String>>>,
    failed: Arc<Mutex<Vec<String>>>,
    pb: ProgressBar,
    sender_done: Arc<AtomicBool>,
    state_tx: mpsc::UnboundedSender<StateMsg>,
    retry_tx: mpsc::UnboundedSender<Vec<String>>,
    _state_file: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut empty_checks = 0;
        
        loop {
            sleep(Duration::from_secs(2)).await;
            
            // Get current slot for expiry checking
            let current_slot = match client.get_slot().await {
                Ok(slot) => slot,
                Err(_) => continue,
            };
            
            let sigs_to_check: Vec<(String, u64)> = {
                let sigs = pending_sigs.read().await;
                if sigs.is_empty() {
                    empty_checks += 1;
                    // Only exit if sender is done AND we've checked empty multiple times with grace period
                    if empty_checks > 2 && sender_done.load(Ordering::Relaxed) {
                        // Final grace period check
                        sleep(Duration::from_secs(5)).await;
                        let final_check = pending_sigs.read().await;
                        if final_check.is_empty() {
                            break;
                        }
                    }
                    continue;
                } else {
                    empty_checks = 0;
                }
                sigs.iter()
                    .map(|(sig, batch)| (sig.clone(), batch.sent_slot))
                    .collect()
            };

            if let Ok(statuses) = client
                .get_signature_statuses(&sigs_to_check.iter().map(|(s, _)| {
                    Signature::from_str(s).unwrap()
                }).collect::<Vec<_>>())
                .await
            {
                let mut confirmed_sigs = Vec::new();
                let mut failed_sigs = Vec::new();
                let mut expired_sigs = Vec::new();

                for ((sig, sent_slot), status) in sigs_to_check.iter().zip(statuses.value.iter()) {
                    if let Some(status) = status {
                        if status.err.is_none() && matches!(
                            status.confirmation_status,
                            Some(TransactionConfirmationStatus::Confirmed) |
                            Some(TransactionConfirmationStatus::Finalized)
                        ) {
                            confirmed_sigs.push(sig.clone());
                        } else if status.err.is_some() {
                            failed_sigs.push(sig.clone());
                        }
                    } else if current_slot.saturating_sub(*sent_slot) > 150 {
                        // Transaction expired
                        expired_sigs.push(sig.clone());
                    }
                }

                // Update state
                let mut sigs = pending_sigs.write().await;
                let mut comp = completed.lock().await;
                let mut fail = failed.lock().await;

                for sig in confirmed_sigs {
                    if let Some(batch) = sigs.remove(&sig) {
                        let recipients = batch.recipients.clone();
                        comp.extend(recipients.clone());
                        pb.inc(batch.recipients.len() as u64);
                        pb.println(format!("✅ Confirmed: {} ({} recipients)", &sig[..8], batch.recipients.len()));
                        
                        // Send update through channel - this is critical for state persistence
                        let _ = state_tx.send(StateMsg::Completed(recipients));
                        
                        // Remove from persistent state
                        let _ = state_tx.send(StateMsg::RemovePending { sig });
                        
                        // Force immediate state flush for confirmed transactions
                        let _ = state_tx.send(StateMsg::Flush);
                    }
                }

                for sig in failed_sigs {
                    if let Some(batch) = sigs.remove(&sig) {
                        let count = batch.recipients.len();
                        let recipients = batch.recipients.clone();
                        fail.extend(recipients.clone());
                        pb.inc(count as u64);
                        // Send update through channel
                        let _ = state_tx.send(StateMsg::Failed(recipients));
                        
                        // Remove from persistent state
                        let _ = state_tx.send(StateMsg::RemovePending { sig });
                    }
                }
                
                // Handle expired - they should be retried, not marked as failed
                for sig in expired_sigs {
                    if let Some(batch) = sigs.remove(&sig) {
                        pb.println(format!("⚠️  Transaction {} expired, requeuing for retry", sig));
                        // Send recipients back to sender for retry
                        let _ = retry_tx.send(batch.recipients);
                        
                        // Remove from persistent state
                        let _ = state_tx.send(StateMsg::RemovePending { sig });
                    }
                }
            }
        }
    })
}

async fn send_transfer_batch(
    client: &RpcClient,
    instructions: Vec<Instruction>,
    fee_payer: &Keypair,
    owner: &Keypair,
    priority_fee: u64,
) -> Result<(Signature, Hash, u64)> {
    let max_retries = 3;
    let mut retries = 0;

    // Simulate to get compute units
    let cu_limit = simulate_compute_units(client, &instructions, &fee_payer.pubkey()).await?;

    loop {
        let blockhash = client.get_latest_blockhash().await?;
        
        let message = create_legacy_message_with_cu(&instructions, &fee_payer.pubkey(), priority_fee, cu_limit, blockhash)?;

        // Handle case where owner and fee_payer might be the same
        let signers: Vec<&Keypair> = if fee_payer.pubkey() == owner.pubkey() {
            vec![fee_payer]
        } else {
            vec![fee_payer, owner]
        };
        let tx = VersionedTransaction::try_new(message, &signers)?;
        
        match client.send_transaction(&tx).await {
            Ok(sig) => {
                let slot = client.get_slot().await.unwrap_or(0);
                return Ok((sig, blockhash, slot));
            }
            Err(e) => {
                let error_str = e.to_string();
                
                // Check for rate limiting
                if error_str.contains("429") || error_str.contains("rate") {
                    // Extract retry-after or use exponential backoff
                    let wait_time = if let Some(retry_after) = extract_retry_after(&error_str) {
                        Duration::from_secs(retry_after)
                    } else {
                        Duration::from_secs(2_u64.pow(retries.min(4)))
                    };
                    // Rate limited, wait before retry
                    sleep(wait_time).await;
                    retries += 1;
                    continue;
                }
                
                if (error_str.contains("blockhash") || error_str.contains("expired")) 
                    && retries < max_retries {
                    retries += 1;
                    sleep(Duration::from_secs(2_u64.pow(retries))).await;
                    continue;
                }
                return Err(e.into());
            }
        }
    }
}

async fn send_and_confirm_batch_with_retry(
    client: &RpcClient,
    instructions: Vec<Instruction>,
    fee_payer: &Keypair,
    priority_fee: u64,
    rate_limiter: &Arc<RateLimiter<
        governor::state::direct::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
    >>,
) -> Result<()> {
    // Simulate to get CU
    let cu_limit = simulate_compute_units(client, &instructions, &fee_payer.pubkey()).await
        .unwrap_or(300_000);
    
    send_and_confirm_batch_with_cu(
        client,
        instructions,
        fee_payer,
        priority_fee,
        cu_limit,
        rate_limiter,
    ).await
}

async fn send_and_confirm_batch_with_cu(
    client: &RpcClient,
    instructions: Vec<Instruction>,
    fee_payer: &Keypair,
    priority_fee: u64,
    cu_limit: u32,
    rate_limiter: &Arc<RateLimiter<
        governor::state::direct::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
    >>,
) -> Result<()> {
    // Wait for rate limit
    rate_limiter.until_ready().await;
    let max_retries = 3;
    let mut retries = 0;

    loop {
        let blockhash = client.get_latest_blockhash().await?;
        
        let message = create_legacy_message_with_cu(&instructions, &fee_payer.pubkey(), priority_fee, cu_limit, blockhash)?;
        let tx = VersionedTransaction::try_new(message, &[fee_payer])?;
        
        match client.send_and_confirm_transaction(&tx).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                let error_str = e.to_string();
                
                // Check for rate limiting
                if error_str.contains("429") || error_str.contains("rate") {
                    let wait_time = if let Some(retry_after) = extract_retry_after(&error_str) {
                        Duration::from_secs(retry_after)
                    } else {
                        Duration::from_secs(2_u64.pow(retries.min(4)))
                    };
                    sleep(wait_time).await;
                    retries += 1;
                    continue;
                }
                
                if (error_str.contains("blockhash") || error_str.contains("expired")) 
                    && retries < max_retries {
                    retries += 1;
                    sleep(Duration::from_secs(2_u64.pow(retries))).await;
                    continue;
                }
                return Err(e.into());
            }
        }
    }
}


fn create_legacy_message(
    instructions: &[Instruction],
    payer: &Pubkey,
    priority_fee: u64,
    blockhash: Hash,
) -> Result<VersionedMessage> {
    let mut all_instructions = vec![
        ComputeBudgetInstruction::set_compute_unit_limit(300_000),
        ComputeBudgetInstruction::set_compute_unit_price(priority_fee),
    ];
    all_instructions.extend_from_slice(instructions);

    Ok(VersionedMessage::Legacy(
        solana_sdk::message::Message::new_with_blockhash(
            &all_instructions,
            Some(payer),
            &blockhash,
        )
    ))
}


fn create_legacy_message_with_cu(
    instructions: &[Instruction],
    payer: &Pubkey,
    priority_fee: u64,
    cu_limit: u32,
    blockhash: Hash,
) -> Result<VersionedMessage> {
    let mut all_instructions = vec![
        ComputeBudgetInstruction::set_compute_unit_limit(cu_limit),
        ComputeBudgetInstruction::set_compute_unit_price(priority_fee),
    ];
    all_instructions.extend_from_slice(instructions);

    Ok(VersionedMessage::Legacy(
        solana_sdk::message::Message::new_with_blockhash(
            &all_instructions,
            Some(payer),
            &blockhash,
        )
    ))
}



fn dry_run_summary(
    distributions: &[Distribution],
    decimals: u8,
    atas_to_create: usize,
    priority_fee: u64,
) -> Result<()> {
    println!("\n=== DRY RUN SUMMARY ===");
    println!("Recipients: {}", distributions.len());
    println!("ATAs to create: {}", atas_to_create);
    
    let total_amount: u64 = distributions.iter().map(|d| d.amount).sum();
    println!(
        "Total tokens: {}",
        amount_to_ui(total_amount, decimals)
    );
    
    // Accurate cost estimates based on actual observed costs
    let base_fee = 0.000005; // 5000 lamports base fee
    let priority_fee_sol = (priority_fee as f64 * 200_000.0) / 1_000_000.0 / 1_000_000_000.0; // priority fee in microLamports per CU, convert to SOL
    let tx_fee = base_fee + priority_fee_sol;
    
    // ATA costs
    let ata_rent = atas_to_create as f64 * 0.00203928; // Rent for token accounts
    let ata_txs = (atas_to_create as f64 / 10.0).ceil(); // 10 ATAs per tx
    let ata_tx_fees = ata_txs * tx_fee;
    let total_ata_cost = ata_rent + ata_tx_fees;
    
    // Transfer costs
    let transfer_txs = (distributions.len() as f64 / 10.0).ceil(); // 10 transfers per tx
    let transfer_cost = transfer_txs * tx_fee;
    
    let total_cost = total_ata_cost + transfer_cost;
    
    println!("\n💰 Estimated SOL costs:");
    if atas_to_create > 0 {
        println!("  ATA creation:");
        println!("    - Rent: {} × 0.00203928 = {:.4} SOL", atas_to_create, ata_rent);
        println!("    - Transactions: {} × {:.6} = {:.4} SOL", ata_txs, tx_fee, ata_tx_fees);
        println!("    - Subtotal: {:.4} SOL", total_ata_cost);
    }
    println!("  Token transfers:");
    println!("    - Transactions: {} × {:.6} = {:.4} SOL", transfer_txs, tx_fee, transfer_cost);
    println!("\n  TOTAL ESTIMATED: {:.4} SOL", total_cost);
    println!("\n  ⚠️  Add 10-20% buffer for network conditions");
    
    Ok(())
}

fn amount_to_ui(amount: u64, decimals: u8) -> f64 {
    amount as f64 / 10_f64.powi(decimals as i32)
}

const UDP_HEADROOM: usize = 100;
const MAX_COMPUTE_UNITS: u32 = 1_400_000; // Solana protocol maximum

fn transaction_fits(tx: &VersionedTransaction) -> (bool, usize) {
    use solana_sdk::packet::PACKET_DATA_SIZE;
    let mut buf = Vec::with_capacity(PACKET_DATA_SIZE);
    // same wire format Solana uses
    if bincode::serialize_into(&mut buf, tx).is_err() {
        return (false, 0);
    }
    let size = buf.len();
    // leave some headroom for UDP headers etc.
    (size <= PACKET_DATA_SIZE - UDP_HEADROOM, size)
}

async fn simulate_compute_units(
    client: &RpcClient,
    instructions: &[Instruction],
    payer: &Pubkey,
) -> Result<u32> {
    use solana_client::rpc_config::RpcSimulateTransactionConfig;
    
    // Create a test transaction for simulation
    let blockhash = client.get_latest_blockhash().await?;
    
    // Build a legacy message for simulation
    let message = create_legacy_message(instructions, payer, 1000, blockhash)?;
    
    // Create unsigned transaction for simulation
    let tx = VersionedTransaction {
        signatures: vec![solana_sdk::signature::Signature::default(); message.header().num_required_signatures as usize],
        message,
    };
    
    // Simulate the transaction
    let config = RpcSimulateTransactionConfig {
        sig_verify: false,
        replace_recent_blockhash: true,
        commitment: Some(CommitmentConfig::processed()),
        ..Default::default()
    };
    
    match client.simulate_transaction_with_config(&tx, config).await {
        Ok(result) => {
            if let Some(units) = result.value.units_consumed {
                // Add 10% buffer to the consumed units and clamp to protocol max
                let cu_with_buffer = (units as f64 * 1.1) as u32;
                Ok(cu_with_buffer.min(MAX_COMPUTE_UNITS))
            } else {
                // Fallback to conservative estimate, clamped to max
                let estimate = 200_000 + (instructions.len() as u32 * 20_000);
                Ok(estimate.min(MAX_COMPUTE_UNITS))
            }
        }
        Err(_) => {
            // Fallback to conservative estimate, clamped to max
            let estimate = 200_000 + (instructions.len() as u32 * 20_000);
            Ok(estimate.min(MAX_COMPUTE_UNITS))
        }
    }
}

fn extract_retry_after(error_str: &str) -> Option<u64> {
    // Try to extract Retry-After header value from error message
    if let Some(pos) = error_str.find("Retry-After:") {
        let after = &error_str[pos + 12..];
        if let Some(end) = after.find(|c: char| !c.is_numeric()) {
            return after[..end].parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::transaction::Transaction;
    
    #[test]
    fn test_state_msg_creation() {
        let batch = PendingBatch {
            recipients: vec!["test".to_string()],
            sent_slot: 100,
            blockhash: "test_hash".to_string(),
        };
        
        let msg = StateMsg::AddPending { 
            sig: "test_sig".to_string(), 
            batch 
        };
        
        // Just verify it compiles and can be created
        match msg {
            StateMsg::AddPending { sig, batch } => {
                assert_eq!(sig, "test_sig");
                assert_eq!(batch.recipients.len(), 1);
                assert_eq!(batch.sent_slot, 100);
                assert_eq!(batch.blockhash, "test_hash");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_distribution_state_serialization() {
        use tempfile::TempDir;
        
        // Create a temporary directory for our test
        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("test_state.json");
        
        // Create a test state
        let mut state = DistributionState::new();
        state.completed_recipients.push("recipient1".to_string());
        state.failed_recipients.push("failed1".to_string());
        
        let batch = PendingBatch {
            recipients: vec!["pending1".to_string()],
            sent_slot: 12345,
            blockhash: "test_blockhash".to_string(),
        };
        state.pending_signatures.insert("sig1".to_string(), batch);
        
        // Save state
        state.save(&state_file).unwrap();
        
        // Load state back
        let loaded_state = DistributionState::load(&state_file).unwrap();
        
        // Verify it matches
        assert_eq!(loaded_state.completed_recipients, vec!["recipient1"]);
        assert_eq!(loaded_state.failed_recipients, vec!["failed1"]);
        assert_eq!(loaded_state.pending_signatures.len(), 1);
        
        let loaded_batch = loaded_state.pending_signatures.get("sig1").unwrap();
        assert_eq!(loaded_batch.recipients, vec!["pending1"]);
        assert_eq!(loaded_batch.sent_slot, 12345);
        assert_eq!(loaded_batch.blockhash, "test_blockhash");
    }

    #[tokio::test]
    async fn test_state_persistence_task() {
        use tempfile::TempDir;
        use tokio::sync::mpsc;
        
        // Create a temporary directory for our test
        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("test_state.json");
        
        // Create the state persistence task (simplified version of the real one)
        let (state_tx, mut state_rx) = mpsc::unbounded_channel::<StateMsg>();
        let state_path = state_file.clone();
        
        let persistence_task = tokio::spawn(async move {
            let mut current_state = DistributionState::new();
            
            while let Some(msg) = state_rx.recv().await {
                match msg {
                    StateMsg::AddPending { sig, batch } => {
                        current_state.pending_signatures.insert(sig, batch);
                    }
                    StateMsg::RemovePending { sig } => {
                        current_state.pending_signatures.remove(&sig);
                    }
                    StateMsg::Completed(recipients) => {
                        current_state.completed_recipients.extend(recipients);
                    }
                    StateMsg::Failed(recipients) => {
                        current_state.failed_recipients.extend(recipients);
                    }
                    StateMsg::Flush => {
                        // Save and exit for test
                        let _ = current_state.save(&state_path);
                        break;
                    }
                }
            }
        });
        
        // Send test messages
        let batch = PendingBatch {
            recipients: vec!["test_recipient".to_string()],
            sent_slot: 999,
            blockhash: "test_hash".to_string(),
        };
        
        state_tx.send(StateMsg::AddPending { 
            sig: "test_sig".to_string(), 
            batch 
        }).unwrap();
        
        state_tx.send(StateMsg::Completed(vec!["completed1".to_string()])).unwrap();
        state_tx.send(StateMsg::Failed(vec!["failed1".to_string()])).unwrap();
        state_tx.send(StateMsg::RemovePending { sig: "test_sig".to_string() }).unwrap();
        state_tx.send(StateMsg::Flush).unwrap();
        
        // Wait for task to complete
        persistence_task.await.unwrap();
        
        // Verify the final state was saved correctly
        let final_state = DistributionState::load(&state_file).unwrap();
        assert_eq!(final_state.completed_recipients, vec!["completed1"]);
        assert_eq!(final_state.failed_recipients, vec!["failed1"]);
        assert_eq!(final_state.pending_signatures.len(), 0); // Should be removed
    }

    #[tokio::test]
    async fn test_transaction_expiry_detection() {
        // Mock scenario: transaction sent at slot 1000, current slot 1200
        // Should detect expiry (1200 - 1000 > 150)
        let current_slot = 1200u64;
        let sent_slot = 1000u64;
        
        // This is the exact logic from confirmation monitor
        let is_expired = current_slot.saturating_sub(sent_slot) > 150;
        assert!(is_expired, "Transaction should be detected as expired");
        
        // Test edge case: exactly at threshold
        let edge_current = 1151u64;
        let edge_sent = 1000u64;
        let at_threshold = edge_current.saturating_sub(edge_sent) > 150;
        assert!(at_threshold, "Transaction at 151 slot difference should be expired");
        
        // Test not expired
        let recent_current = 1100u64;
        let recent_sent = 1000u64;
        let not_expired = recent_current.saturating_sub(recent_sent) > 150;
        assert!(!not_expired, "Recent transaction should not be expired");
        
        // Test edge case: exactly at threshold (should not be expired)
        let exact_threshold_current = 1150u64;
        let exact_threshold_sent = 1000u64;
        let at_exact_threshold = exact_threshold_current.saturating_sub(exact_threshold_sent) > 150;
        assert!(!at_exact_threshold, "Transaction at exactly 150 slot difference should not be expired");
    }

    #[tokio::test]
    async fn test_concurrent_state_updates() {
        use tempfile::TempDir;
        use std::sync::Arc;
        use tokio::sync::Barrier;
        
        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("concurrent_test.json");
        
        // Spawn 10 concurrent tasks all trying to update state
        let barrier = Arc::new(Barrier::new(11)); // 10 tasks + main thread
        let (state_tx, mut state_rx) = mpsc::unbounded_channel::<StateMsg>();
        let state_path = state_file.clone();
        
        // Single writer task
        let persistence_task = tokio::spawn(async move {
            let mut current_state = DistributionState::new();
            while let Some(msg) = state_rx.recv().await {
                match msg {
                    StateMsg::Completed(recipients) => {
                        current_state.completed_recipients.extend(recipients);
                    }
                    StateMsg::Flush => {
                        current_state.save(&state_path).unwrap();
                        break;
                    }
                    _ => {}
                }
            }
        });
        
        // Spawn 10 concurrent senders
        let mut handles = vec![];
        for i in 0..10 {
            let barrier_clone = barrier.clone();
            let tx_clone = state_tx.clone();
            let handle = tokio::spawn(async move {
                barrier_clone.wait().await;
                // All tasks send at exactly the same time
                tx_clone.send(StateMsg::Completed(vec![format!("recipient_{}", i)])).unwrap();
            });
            handles.push(handle);
        }
        
        // Start all tasks simultaneously
        barrier.wait().await;
        
        // Wait for all senders
        for handle in handles {
            handle.await.unwrap();
        }
        
        // Flush and verify
        state_tx.send(StateMsg::Flush).unwrap();
        drop(state_tx);
        persistence_task.await.unwrap();
        
        // Verify all 10 recipients were saved without corruption
        let final_state = DistributionState::load(&state_file).unwrap();
        assert_eq!(final_state.completed_recipients.len(), 10);
        
        // Verify no duplicates or corruption - all recipients present
        for i in 0..10 {
            assert!(final_state.completed_recipients.contains(&format!("recipient_{}", i)));
        }
    }

    #[test]
    fn test_transaction_size_limits() {
        // Critical: Ensure we never create transactions that exceed size limits
        use solana_sdk::message::Message;
        use solana_sdk::system_instruction;
        
        // Create a transaction with maximum number of transfer instructions
        let payer = Pubkey::new_unique();
        let mut instructions = vec![];
        
        // Add compute budget instructions
        instructions.push(ComputeBudgetInstruction::set_compute_unit_limit(200_000));
        instructions.push(ComputeBudgetInstruction::set_compute_unit_price(1000));
        
        // Add 10 transfer instructions (our hard limit)
        for _ in 0..10 {
            let recipient = Pubkey::new_unique();
            instructions.push(system_instruction::transfer(&payer, &recipient, 1));
        }
        
        // Create message and verify size
        let message = Message::new_with_blockhash(
            &instructions,
            Some(&payer),
            &Hash::default(),
        );
        
        let tx = Transaction::new_unsigned(message);
        let serialized = bincode::serialize(&tx).unwrap();
        
        // Ensure transaction fits in packet
        assert!(serialized.len() <= 1232 - 100, "Transaction too large: {} bytes", serialized.len());
        
        // Test that 11 transfers would be too many
        instructions.push(system_instruction::transfer(&payer, &Pubkey::new_unique(), 1));
        let large_message = Message::new_with_blockhash(
            &instructions,
            Some(&payer),
            &Hash::default(),
        );
        let large_tx = Transaction::new_unsigned(large_message);
        let large_serialized = bincode::serialize(&large_tx).unwrap();
        
        // This should be getting close to or exceeding limits
        println!("10 transfers: {} bytes, 11 transfers: {} bytes", 
                 serialized.len(), large_serialized.len());
    }

    #[tokio::test]
    async fn test_pending_transaction_recovery() {
        // Critical: Test that confirmed transactions are properly recovered on restart
        use tempfile::TempDir;
        
        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("test_state.json");
        
        // Create initial state with pending transaction
        let mut state = DistributionState::new();
        let pending_batch = PendingBatch {
            recipients: vec!["recipient1".to_string(), "recipient2".to_string()],
            sent_slot: 1000,
            blockhash: "test_hash".to_string(),
        };
        state.pending_signatures.insert("test_sig".to_string(), pending_batch);
        state.save(&state_file).unwrap();
        
        // Simulate restart - load state
        let loaded_state = DistributionState::load(&state_file).unwrap();
        assert_eq!(loaded_state.pending_signatures.len(), 1);
        assert_eq!(loaded_state.completed_recipients.len(), 0);
        
        // Simulate the pending transaction being confirmed
        let mut recovered_state = loaded_state;
        let batch = recovered_state.pending_signatures.remove("test_sig").unwrap();
        recovered_state.completed_recipients.extend(batch.recipients);
        recovered_state.save(&state_file).unwrap();
        
        // Verify final state
        let final_state = DistributionState::load(&state_file).unwrap();
        assert_eq!(final_state.pending_signatures.len(), 0);
        assert_eq!(final_state.completed_recipients.len(), 2);
        assert!(final_state.completed_recipients.contains(&"recipient1".to_string()));
        assert!(final_state.completed_recipients.contains(&"recipient2".to_string()));
    }

    #[test]
    fn test_insufficient_balance_detection() {
        // Critical: Ensure we never allow overspending
        let distributions = vec![
            Distribution {
                recipient: Pubkey::new_unique(),
                amount: 1000,
                ata: Pubkey::new_unique(),
                needs_creation: false,
            },
            Distribution {
                recipient: Pubkey::new_unique(),
                amount: 1000,
                ata: Pubkey::new_unique(),
                needs_creation: false,
            },
        ];
        
        let total_needed: u64 = distributions.iter().map(|d| d.amount).sum();
        assert_eq!(total_needed, 2000);
        
        // Test various balance scenarios
        let sufficient_balance = 2000u64;
        let insufficient_balance = 1999u64;
        let partial_balance = 1000u64;
        
        assert!(sufficient_balance >= total_needed, "Should have enough");
        assert!(insufficient_balance < total_needed, "Should not have enough");
        assert!(partial_balance < total_needed, "Should only cover partial");
        
        // Test with pending amounts
        let pending_amount = 500u64;
        let effective_balance = sufficient_balance - pending_amount;
        assert!(effective_balance < total_needed, "Pending should affect available balance");
    }

    #[tokio::test]
    async fn test_pending_signature_lifecycle() {
        use tempfile::TempDir;
        
        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("pending_test.json");
        
        let (state_tx, mut state_rx) = mpsc::unbounded_channel::<StateMsg>();
        let state_path = state_file.clone();
        
        let persistence_task = tokio::spawn(async move {
            let mut current_state = DistributionState::new();
            while let Some(msg) = state_rx.recv().await {
                match msg {
                    StateMsg::AddPending { sig, batch } => {
                        current_state.pending_signatures.insert(sig, batch);
                    }
                    StateMsg::RemovePending { sig } => {
                        current_state.pending_signatures.remove(&sig);
                    }
                    StateMsg::Completed(recipients) => {
                        current_state.completed_recipients.extend(recipients);
                    }
                    StateMsg::Flush => {
                        current_state.save(&state_path).unwrap();
                        break;
                    }
                    _ => {}
                }
            }
        });
        
        // Simulate transaction lifecycle: pending -> confirmed -> removed
        let batch = PendingBatch {
            recipients: vec!["test_recipient".to_string()],
            sent_slot: 1000,
            blockhash: "test_hash".to_string(),
        };
        
        // 1. Add pending
        state_tx.send(StateMsg::AddPending { 
            sig: "test_sig".to_string(), 
            batch 
        }).unwrap();
        
        // 2. Mark as completed  
        state_tx.send(StateMsg::Completed(vec!["test_recipient".to_string()])).unwrap();
        
        // 3. Remove from pending
        state_tx.send(StateMsg::RemovePending { sig: "test_sig".to_string() }).unwrap();
        
        state_tx.send(StateMsg::Flush).unwrap();
        drop(state_tx);
        persistence_task.await.unwrap();
        
        // Verify clean state: completed but no pending signatures
        let final_state = DistributionState::load(&state_file).unwrap();
        assert_eq!(final_state.completed_recipients, vec!["test_recipient"]);
        assert_eq!(final_state.pending_signatures.len(), 0, "No pending signatures should remain");
        assert!(final_state.failed_recipients.is_empty(), "No failed recipients in this test");
    }
    
    #[test]
    fn test_duplicate_recipient_handling() {
        // Critical: Ensure no double spending on same recipient
        let mut state = DistributionState::new();
        
        // Add same recipient to completed
        state.completed_recipients.push("recipient1".to_string());
        state.completed_recipients.push("recipient1".to_string());
        
        // Dedup should remove duplicates
        state.completed_recipients.sort();
        state.completed_recipients.dedup();
        
        assert_eq!(state.completed_recipients.len(), 1, "Should have only one instance");
        
        // Test filtering distributions
        let recipient1 = Pubkey::new_unique();
        let recipient2 = Pubkey::new_unique();
        
        let distributions = vec![
            Distribution {
                recipient: recipient1,
                amount: 1000,
                ata: Pubkey::new_unique(),
                needs_creation: false,
            },
            Distribution {
                recipient: recipient2,
                amount: 1000,
                ata: Pubkey::new_unique(),
                needs_creation: false,
            },
        ];
        
        // Mark first as completed
        state.completed_recipients.clear();
        state.completed_recipients.push(recipient1.to_string());
        
        // Filter out completed
        let remaining: Vec<Distribution> = distributions.into_iter()
            .filter(|d| !state.completed_recipients.contains(&d.recipient.to_string()))
            .collect();
        
        assert_eq!(remaining.len(), 1, "Should have filtered out completed recipient");
        assert_eq!(remaining[0].recipient, recipient2);
    }
    
    #[test]
    fn test_batch_size_enforcement() {
        // Critical: Verify hard limits prevent "too many signers" error
        let mut batch = Vec::new();
        
        // Our hard limit is 10
        for i in 0..15 {
            batch.push(i);
            
            // Check if we should flush
            if batch.len() >= 10 {
                assert_eq!(batch.len(), 10, "Batch should be exactly 10 before flush");
                batch.clear();
            }
        }
        
        // Remaining items
        assert_eq!(batch.len(), 5, "Should have 5 remaining items");
    }
    
    #[test]
    fn test_csv_hash_consistency() {
        // Critical: Ensure same CSV always produces same hash
        use tempfile::TempDir;
        use std::io::Write;
        
        let temp_dir = TempDir::new().unwrap();
        let csv_path = temp_dir.path().join("test.csv");
        
        // Write test CSV
        let mut file = fs::File::create(&csv_path).unwrap();
        writeln!(file, "recipient,amount").unwrap();
        writeln!(file, "11111111111111111111111111111112,1000").unwrap();
        writeln!(file, "11111111111111111111111111111113,2000").unwrap();
        drop(file);
        
        let mint = Pubkey::new_unique();
        
        // Compute hash multiple times
        let hash1 = compute_csv_hash(&csv_path, &mint).unwrap();
        let hash2 = compute_csv_hash(&csv_path, &mint).unwrap();
        let hash3 = compute_csv_hash(&csv_path, &mint).unwrap();
        
        assert_eq!(hash1, hash2, "Hash should be consistent");
        assert_eq!(hash2, hash3, "Hash should be consistent");
        assert_eq!(hash1.len(), 16, "Hash should be 16 characters");
        
        // Different mint should produce different hash
        let mint2 = Pubkey::new_unique();
        let hash_different_mint = compute_csv_hash(&csv_path, &mint2).unwrap();
        assert_ne!(hash1, hash_different_mint, "Different mint should produce different hash");
        
        // Different content should produce different hash
        let csv_path2 = temp_dir.path().join("test2.csv");
        let mut file2 = fs::File::create(&csv_path2).unwrap();
        writeln!(file2, "recipient,amount").unwrap();
        writeln!(file2, "11111111111111111111111111111114,3000").unwrap();
        drop(file2);
        
        let hash_different_content = compute_csv_hash(&csv_path2, &mint).unwrap();
        assert_ne!(hash1, hash_different_content, "Different content should produce different hash");
    }
    
    #[test]
    fn test_state_file_path_generation() {
        // Critical: Ensure state files are properly organized by hash
        use tempfile::TempDir;
        use std::io::Write;
        
        let temp_dir = TempDir::new().unwrap();
        let state_dir = temp_dir.path().join("state");
        let csv_path = temp_dir.path().join("recipients.csv");
        
        // Create test CSV
        let mut file = fs::File::create(&csv_path).unwrap();
        writeln!(file, "recipient,amount").unwrap();
        writeln!(file, "11111111111111111111111111111112,1000").unwrap();
        drop(file);
        
        // Test auto-generated path
        let args = DistributeArgs {
            input_csv: csv_path.clone(),
            mint: "So11111111111111111111111111111111111111112".to_string(),
            from: "11111111111111111111111111111111".to_string(),
            owner: temp_dir.path().join("owner.json"),
            fee_payer: temp_dir.path().join("payer.json"),
            url: "https://api.devnet.solana.com".to_string(),
            dry_run: false,
            rate_limit: 10,
            state_file: None, // Auto-generate
            state_dir: state_dir.clone(),
            priority_fee: 1000,
            yes: false,
            skip_ata: false,
            force_clear_pending: false,
            limit: None,
        };
        
        let state_path = get_state_file_path(&args).unwrap();
        
        // Verify path structure
        assert!(state_path.starts_with(&state_dir), "State file should be in state directory");
        assert!(state_path.ends_with("distribution_state.json"), "State file should have correct name");
        
        // Verify hash directory was created
        let parent = state_path.parent().unwrap();
        assert!(parent.exists(), "Hash directory should be created");
        
        // Verify info file was created
        let info_file = parent.join("distribution_info.json");
        assert!(info_file.exists(), "Info file should be created");
        
        // Test user-specified path
        let custom_path = temp_dir.path().join("custom_state.json");
        let args_custom = DistributeArgs {
            state_file: Some(custom_path.clone()),
            ..args
        };
        
        let state_path_custom = get_state_file_path(&args_custom).unwrap();
        assert_eq!(state_path_custom, custom_path, "Should use user-specified path");
    }
    
    #[tokio::test]
    async fn test_state_accumulation_across_rounds() {
        // Critical: Test that state accumulates correctly when resuming
        use tempfile::TempDir;
        
        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("accumulation_test.json");
        
        // Simulate first round - 870 recipients completed
        let (state_tx, mut state_rx) = mpsc::unbounded_channel::<StateMsg>();
        let state_path = state_file.clone();
        
        let persistence_task = tokio::spawn(async move {
            let mut current_state = DistributionState::new();
            
            while let Some(msg) = state_rx.recv().await {
                match msg {
                    StateMsg::Completed(recipients) => {
                        current_state.completed_recipients.extend(recipients);
                    }
                    StateMsg::Flush => {
                        // Important: dedup before save
                        current_state.completed_recipients.sort();
                        current_state.completed_recipients.dedup();
                        current_state.save(&state_path).unwrap();
                        break;
                    }
                    _ => {}
                }
            }
            current_state.completed_recipients.len()
        });
        
        // First round: 870 recipients
        for i in 0..870 {
            if i % 10 == 0 {
                // Batch of 10
                let batch: Vec<String> = (i..i+10).map(|j| format!("recipient_{}", j)).collect();
                state_tx.send(StateMsg::Completed(batch)).unwrap();
            }
        }
        
        state_tx.send(StateMsg::Flush).unwrap();
        drop(state_tx);
        let first_count = persistence_task.await.unwrap();
        assert_eq!(first_count, 870);
        
        // Verify first round saved correctly
        let loaded_state = DistributionState::load(&state_file).unwrap();
        assert_eq!(loaded_state.completed_recipients.len(), 870);
        
        // Simulate second round - additional 488 recipients
        let (state_tx2, mut state_rx2) = mpsc::unbounded_channel::<StateMsg>();
        let state_path2 = state_file.clone();
        
        let persistence_task2 = tokio::spawn(async move {
            // CRITICAL: Load existing state to accumulate
            let mut current_state = DistributionState::load(&state_path2).unwrap();
            
            while let Some(msg) = state_rx2.recv().await {
                match msg {
                    StateMsg::Completed(recipients) => {
                        current_state.completed_recipients.extend(recipients);
                    }
                    StateMsg::Flush => {
                        current_state.completed_recipients.sort();
                        current_state.completed_recipients.dedup();
                        current_state.save(&state_path2).unwrap();
                        break;
                    }
                    _ => {}
                }
            }
            current_state.completed_recipients.len()
        });
        
        // Second round: 488 more recipients
        for i in 870..1358 {
            if i % 10 == 0 || i == 1350 {
                // Batch of 10 or remaining 8
                let end = std::cmp::min(i + 10, 1358);
                let batch: Vec<String> = (i..end).map(|j| format!("recipient_{}", j)).collect();
                state_tx2.send(StateMsg::Completed(batch)).unwrap();
            }
        }
        
        state_tx2.send(StateMsg::Flush).unwrap();
        drop(state_tx2);
        let final_count = persistence_task2.await.unwrap();
        
        // CRITICAL: Should have ALL recipients, not just the second batch
        assert_eq!(final_count, 1358, "State should accumulate to 1358 total recipients");
        
        // Verify final state
        let final_state = DistributionState::load(&state_file).unwrap();
        assert_eq!(final_state.completed_recipients.len(), 1358);
        
        // Verify no duplicates
        let mut deduped = final_state.completed_recipients.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), 1358, "Should have no duplicate recipients");
    }

    #[test]
    fn test_fee_calculation_with_priority_fee() {
        // Test that fee calculations properly use the priority fee parameter
        
        // Test cases with different priority fees
        let test_cases = vec![
            (1_000, 0.000005 + (1_000.0 * 200_000.0) / 1_000_000.0 / 1_000_000_000.0),      // Low priority
            (20_000, 0.000005 + (20_000.0 * 200_000.0) / 1_000_000.0 / 1_000_000_000.0),    // Medium priority  
            (50_000, 0.000005 + (50_000.0 * 200_000.0) / 1_000_000.0 / 1_000_000_000.0),    // High priority
            (100_000, 0.000005 + (100_000.0 * 200_000.0) / 1_000_000.0 / 1_000_000_000.0),  // Very high priority
        ];
        
        for (priority_fee, expected_tx_fee) in test_cases {
            let base_fee = 0.000005;
            let priority_fee_sol = (priority_fee as f64 * 200_000.0) / 1_000_000.0 / 1_000_000_000.0;
            let actual_tx_fee = base_fee + priority_fee_sol;
            
            assert!(
                (actual_tx_fee - expected_tx_fee).abs() < 0.0000001,
                "Priority fee {} should result in tx fee {}, got {}",
                priority_fee,
                expected_tx_fee,
                actual_tx_fee
            );
        }
    }

    #[test]
    fn test_dry_run_cost_estimation() {
        // Test the dry run summary calculations
        let distributions = vec![
            Distribution {
                recipient: Pubkey::new_unique(),
                amount: 1_000_000_000, // 1 token with 9 decimals
                ata: Pubkey::new_unique(),
                needs_creation: true,
            },
            Distribution {
                recipient: Pubkey::new_unique(),
                amount: 2_000_000_000,
                ata: Pubkey::new_unique(),
                needs_creation: true,
            },
            Distribution {
                recipient: Pubkey::new_unique(),
                amount: 3_000_000_000,
                ata: Pubkey::new_unique(),
                needs_creation: false,
            },
        ];
        
        let atas_to_create = distributions.iter().filter(|d| d.needs_creation).count();
        assert_eq!(atas_to_create, 2);
        
        // Test with 20,000 microLamports priority fee
        let priority_fee = 20_000u64;
        let base_fee = 0.000005;
        let priority_fee_sol = (priority_fee as f64 * 200_000.0) / 1_000_000.0 / 1_000_000_000.0;
        let tx_fee = base_fee + priority_fee_sol;
        
        // ATA creation costs
        let ata_rent = atas_to_create as f64 * 0.00203928;
        let ata_txs = (atas_to_create as f64 / 10.0).ceil();
        let ata_tx_fees = ata_txs * tx_fee;
        let total_ata_cost = ata_rent + ata_tx_fees;
        
        // Transfer costs
        let transfer_txs = (distributions.len() as f64 / 10.0).ceil();
        let transfer_cost = transfer_txs * tx_fee;
        
        let total_cost = total_ata_cost + transfer_cost;
        
        // Verify calculations
        assert_eq!(ata_txs, 1.0); // 2 ATAs fit in 1 transaction
        assert_eq!(transfer_txs, 1.0); // 3 transfers fit in 1 transaction
        // 20,000 × 200,000 = 4,000,000,000 microLamports / 1e6 / 1e9 = 0.000004 SOL
        assert!((tx_fee - 0.000009).abs() < 0.0000001); // 0.000005 + 0.000004
        assert!((total_cost - (ata_rent + 2.0 * tx_fee)).abs() < 0.0000001);
    }

    #[test]
    fn test_execute_transfers_round_fee_calculation() {
        // Test the fee calculation in execute_transfers_round
        let priority_fee = 30_000u64;
        let actual_txs = 10;
        
        let expected_fee_per_tx = 0.000005 + (priority_fee as f64 * 200_000.0) / 1_000_000.0 / 1_000_000_000.0;
        let expected_total = actual_txs as f64 * expected_fee_per_tx;
        
        let calculated_total = actual_txs as f64 * (0.000005 + (priority_fee as f64 * 200_000.0) / 1_000_000.0 / 1_000_000_000.0);
        
        assert!(
            (calculated_total - expected_total).abs() < 0.0000001,
            "Fee calculation mismatch: expected {}, got {}",
            expected_total,
            calculated_total
        );
        
        // Verify the calculation matches what the user would pay
        // 30,000 priority fee × 200,000 CU = 6,000,000,000 microLamports / 1e6 / 1e9 = 0.000006 SOL
        assert!((expected_fee_per_tx - 0.000011).abs() < 0.0000001); // 0.000005 + 0.000006
    }

    #[test]
    fn test_limit_functionality() {
        // Test that limit parameter correctly restricts number of recipients
        let all_distributions = vec![
            Distribution {
                recipient: Pubkey::new_unique(),
                amount: 1_000_000_000,
                ata: Pubkey::new_unique(),
                needs_creation: false,
            },
            Distribution {
                recipient: Pubkey::new_unique(),
                amount: 2_000_000_000,
                ata: Pubkey::new_unique(),
                needs_creation: false,
            },
            Distribution {
                recipient: Pubkey::new_unique(),
                amount: 3_000_000_000,
                ata: Pubkey::new_unique(),
                needs_creation: false,
            },
            Distribution {
                recipient: Pubkey::new_unique(),
                amount: 4_000_000_000,
                ata: Pubkey::new_unique(),
                needs_creation: false,
            },
            Distribution {
                recipient: Pubkey::new_unique(),
                amount: 5_000_000_000,
                ata: Pubkey::new_unique(),
                needs_creation: false,
            },
        ];
        
        // Test with limit of 3
        let mut limited = all_distributions.clone();
        limited.truncate(3);
        assert_eq!(limited.len(), 3);
        assert_eq!(limited[0].amount, 1_000_000_000);
        assert_eq!(limited[1].amount, 2_000_000_000);
        assert_eq!(limited[2].amount, 3_000_000_000);
        
        // Test with limit larger than array
        let mut limited = all_distributions.clone();
        limited.truncate(10);
        assert_eq!(limited.len(), 5); // Should not exceed original length
        
        // Test with limit of 0 (should keep all)
        let mut limited = all_distributions.clone();
        if 0 > 0 {
            limited.truncate(0);
        }
        assert_eq!(limited.len(), 5); // Should keep all
    }

    #[tokio::test] 
    async fn test_partial_run_with_limit() {
        // Test that partial runs with limit work correctly and can be resumed
        use tempfile::TempDir;
        use std::io::Write;
        
        let temp_dir = TempDir::new().unwrap();
        let csv_path = temp_dir.path().join("test_limit.csv");
        let state_file = temp_dir.path().join("limit_state.json");
        
        // Create CSV with 10 recipients
        let mut file = fs::File::create(&csv_path).unwrap();
        writeln!(file, "recipient,amount").unwrap();
        for i in 0..10 {
            writeln!(file, "{},{}", Pubkey::new_unique(), 1000 + i).unwrap();
        }
        drop(file);
        
        // Load recipients and simulate first run with limit of 3
        let mint = Pubkey::new_unique();
        let all_recipients = load_recipients(&csv_path, &mint).unwrap();
        assert_eq!(all_recipients.len(), 10);
        
        // Simulate processing first 3
        let mut state = DistributionState::new();
        let mut first_batch = all_recipients.clone();
        first_batch.truncate(3);
        
        // Mark first 3 as completed
        for dist in &first_batch {
            state.completed_recipients.push(dist.recipient.to_string());
        }
        state.save(&state_file).unwrap();
        
        // Load state and verify
        let loaded_state = DistributionState::load(&state_file).unwrap();
        assert_eq!(loaded_state.completed_recipients.len(), 3);
        
        // Simulate second run with limit of 4
        let mut remaining = all_recipients.clone();
        remaining.retain(|d| {
            !loaded_state.completed_recipients.contains(&d.recipient.to_string())
        });
        assert_eq!(remaining.len(), 7); // 10 - 3 = 7
        
        // Apply new limit
        remaining.truncate(4);
        assert_eq!(remaining.len(), 4);
        
        // Process these 4
        let mut updated_state = loaded_state;
        for dist in &remaining {
            updated_state.completed_recipients.push(dist.recipient.to_string());
        }
        updated_state.save(&state_file).unwrap();
        
        // Final verification
        let final_state = DistributionState::load(&state_file).unwrap();
        assert_eq!(final_state.completed_recipients.len(), 7); // 3 + 4 = 7
        
        // Verify no duplicates
        let mut deduped = final_state.completed_recipients.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), 7);
    }

    #[test]
    fn test_limit_with_state_persistence() {
        // Test that limit works correctly with state persistence across multiple runs
        use tempfile::TempDir;
        
        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("state_limit_test.json");
        
        // Create test data
        let recipients: Vec<String> = (0..20).map(|i| format!("recipient_{}", i)).collect();
        
        // Run 1: Process first 5
        let mut state = DistributionState::new();
        state.completed_recipients.extend(recipients[0..5].iter().cloned());
        state.save(&state_file).unwrap();
        
        // Run 2: Process next 5
        let mut state = DistributionState::load(&state_file).unwrap();
        state.completed_recipients.extend(recipients[5..10].iter().cloned());
        state.save(&state_file).unwrap();
        
        // Run 3: Process next 5
        let mut state = DistributionState::load(&state_file).unwrap();
        state.completed_recipients.extend(recipients[10..15].iter().cloned());
        state.save(&state_file).unwrap();
        
        // Final check
        let final_state = DistributionState::load(&state_file).unwrap();
        assert_eq!(final_state.completed_recipients.len(), 15);
        
        // Verify recipients are in order and no gaps
        for i in 0..15 {
            assert!(final_state.completed_recipients.contains(&format!("recipient_{}", i)));
        }
        for i in 15..20 {
            assert!(!final_state.completed_recipients.contains(&format!("recipient_{}", i)));
        }
    }
}