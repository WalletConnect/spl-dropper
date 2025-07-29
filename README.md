# SPL Token Dropper

A high-performance, production-ready SPL token distribution tool for Solana. Handles massive airdrops with automatic retry, state persistence, and crash recovery.

## Features

- 🚀 **High Performance**: Batch processing with configurable rate limiting
- 💾 **State Persistence**: Automatic resume from interruptions
- 🔄 **Smart Retries**: Handles expired transactions automatically
- 📊 **Progress Tracking**: Real-time distribution progress
- 💰 **Cost Estimation**: Accurate SOL cost predictions
- 🔒 **Safe**: Prevents double-spending and tracks all operations
- 📁 **CSV-based**: Simple recipient list management

## Installation

```bash
cargo build --release
```

## Quick Start

1. **Prepare your recipient list** (CSV format):
```csv
recipient,amount
EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v,1000000000
So11111111111111111111111111111111111111112,2000000000
```

2. **Run distribution**:
```bash
./target/release/spl-dropper distribute \
  --input-csv recipients.csv \
  --mint <TOKEN_MINT> \
  --from <SOURCE_TOKEN_ACCOUNT> \
  --owner owner.json \
  --fee-payer payer.json \
  --url https://api.mainnet-beta.solana.com
```

3. **Monitor progress**: The tool shows real-time progress and saves state automatically.

## Key Commands

### Distribute Tokens
```bash
spl-dropper distribute [OPTIONS]
```

Options:
- `--input-csv`: Path to CSV with recipients
- `--mint`: SPL token mint address
- `--from`: Source token account
- `--owner`: Owner keypair (controls source account)
- `--fee-payer`: Fee payer keypair
- `--url`: RPC URL
- `--rate-limit`: Requests per second (default: 10)
- `--priority-fee`: Priority fee in microlamports (default: 1000)
- `--dry-run`: Preview distribution without executing
- `--skip-ata`: Skip ATA creation checks

### Generate Test Recipients
```bash
spl-dropper generate-recipients \
  --count 1000 \
  --amount 1000000000 \
  --output test_recipients.csv
```

### Create Address Lookup Table
For distributions over 256 unique addresses:
```bash
spl-dropper create-alt \
  --fee-payer payer.json \
  --url <RPC_URL> \
  --recipients-csv recipients.csv
```

## State Management

The tool automatically tracks distribution state in `.spl-dropper-state/<hash>/` directories:
- Each unique CSV+mint combination gets its own state
- Automatic resume on interruption
- Prevents accidental re-processing

## Safety Features

- **Balance Checks**: Prevents starting distributions without sufficient tokens
- **Duplicate Prevention**: Tracks completed recipients
- **Transaction Monitoring**: Handles confirmations and expirations
- **Atomic State Updates**: Single-writer pattern prevents corruption

## Cost Estimation

Run with `--dry-run` to see detailed cost breakdown:
- ATA creation costs (one-time)
- Transaction fees
- Priority fees

## Performance

- Processes in batches of 10 transfers per transaction
- Configurable rate limiting
- Automatic retry for failed/expired transactions
- Typical throughput: 100-500 recipients/minute

## Development

Run tests:
```bash
cargo test
```

## License

MIT
