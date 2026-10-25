//! `verdict` — drive a verdict escrow by hand.
//!
//! The three roles are separate commands on purpose. `sign` needs the verdict
//! signer's key and nothing else: no RPC write, no fee, no transaction. It
//! prints a signature that anyone can carry to the chain with `settle`, which
//! is exactly the split the program enforces on-chain.
//!
//!   verdict create  --keypair buyer.json --mint <MINT> --seller <PK> \
//!                   --verdict-signer <PK> --amount 1000000 --escrow-id 1
//!   verdict show    --escrow <ESCROW>
//!   verdict sign    --keypair verdict-signer.json --escrow <ESCROW> --verdict release
//!   verdict settle  --keypair any-payer.json --escrow <ESCROW> --verdict release \
//!                   --expires-at <UNIX> --signature <HEX>
//!   verdict reclaim --keypair buyer.json --escrow <ESCROW>

mod rpc;

use anchor_lang::prelude::Pubkey;
use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rpc::Rpc;
use solana_instruction::Instruction;
use solana_keypair::{read_keypair_file, Keypair};
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::path::PathBuf;
use verdict_escrow::state::{Escrow, ESCROW_SEED};
use verdict_escrow::verdict::{build_message, Verdict, MESSAGE_LEN};

const TOKEN_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const TOKEN_2022_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");
const ED25519_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("Ed25519SigVerify111111111111111111111111111");
const INSTRUCTIONS_SYSVAR_ID: Pubkey =
    Pubkey::from_str_const("Sysvar1nstructions1111111111111111111111111");

#[derive(Parser)]
#[command(name = "verdict", about = "Open, sign and settle verdict escrows")]
struct Cli {
    /// JSON-RPC endpoint.
    #[arg(long, default_value = "https://api.devnet.solana.com", global = true)]
    rpc: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Open an escrow and fund it from the buyer's token account.
    Create {
        /// The buyer's keypair; pays for the accounts and signs.
        #[arg(long)]
        keypair: PathBuf,
        #[arg(long)]
        mint: Pubkey,
        #[arg(long)]
        seller: Pubkey,
        #[arg(long)]
        verdict_signer: Pubkey,
        /// Amount in the mint's base units.
        #[arg(long)]
        amount: u64,
        /// Part of the escrow address. Use a fresh one for every deal.
        #[arg(long)]
        escrow_id: u64,
        /// Seconds from now until the buyer can reclaim.
        #[arg(long, default_value_t = 3_600)]
        deadline_in: i64,
    },
    /// Print an escrow's stored state.
    Show {
        #[arg(long)]
        escrow: Pubkey,
    },
    /// Sign a verdict. Needs the verdict signer's key and nothing else.
    Sign {
        #[arg(long)]
        keypair: PathBuf,
        #[arg(long)]
        escrow: Pubkey,
        #[arg(long)]
        verdict: VerdictArg,
        /// Seconds from now after which this verdict stops working.
        #[arg(long, default_value_t = 600)]
        expires_in: i64,
    },
    /// Carry a signed verdict to the chain. Anyone can run this.
    Settle {
        /// Pays the fee. Holds no authority over the escrow.
        #[arg(long)]
        keypair: PathBuf,
        #[arg(long)]
        escrow: Pubkey,
        #[arg(long)]
        verdict: VerdictArg,
        /// From `verdict sign`.
        #[arg(long)]
        expires_at: i64,
        /// From `verdict sign`, as hex.
        #[arg(long)]
        signature: String,
    },
    /// Take the money back, once the deadline has passed.
    Reclaim {
        /// The buyer's keypair.
        #[arg(long)]
        keypair: PathBuf,
        #[arg(long)]
        escrow: Pubkey,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum VerdictArg {
    Release,
    Refund,
}

impl From<VerdictArg> for Verdict {
    fn from(arg: VerdictArg) -> Self {
        match arg {
            VerdictArg::Release => Verdict::Release,
            VerdictArg::Refund => Verdict::Refund,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rpc = Rpc::new(&cli.rpc);

    match cli.command {
        Command::Create {
            keypair,
            mint,
            seller,
            verdict_signer,
            amount,
            escrow_id,
            deadline_in,
        } => create(
            &rpc,
            &load_keypair(&keypair)?,
            mint,
            seller,
            verdict_signer,
            amount,
            escrow_id,
            deadline_in,
        ),
        Command::Show { escrow } => show(&rpc, escrow),
        Command::Sign {
            keypair,
            escrow,
            verdict,
            expires_in,
        } => sign(
            &rpc,
            &load_keypair(&keypair)?,
            escrow,
            verdict.into(),
            expires_in,
        ),
        Command::Settle {
            keypair,
            escrow,
            verdict,
            expires_at,
            signature,
        } => settle(
            &rpc,
            &load_keypair(&keypair)?,
            escrow,
            verdict.into(),
            expires_at,
            &signature,
        ),
        Command::Reclaim { keypair, escrow } => reclaim(&rpc, &load_keypair(&keypair)?, escrow),
    }
}

#[allow(clippy::too_many_arguments)]
fn create(
    rpc: &Rpc,
    buyer: &Keypair,
    mint: Pubkey,
    seller: Pubkey,
    verdict_signer: Pubkey,
    amount: u64,
    escrow_id: u64,
    deadline_in: i64,
) -> Result<()> {
    let token_program = token_program_of(rpc, &mint)?;
    let escrow = escrow_address(&buyer.pubkey(), escrow_id);
    let deadline = rpc.chain_time()? + deadline_in;

    let instruction = Instruction {
        program_id: verdict_escrow::ID,
        accounts: verdict_escrow::accounts::CreateEscrow {
            buyer: buyer.pubkey(),
            mint,
            escrow,
            vault: associated_token_address(&escrow, &mint, &token_program),
            buyer_token_account: associated_token_address(&buyer.pubkey(), &mint, &token_program),
            token_program,
            associated_token_program: ASSOCIATED_TOKEN_PROGRAM_ID,
            system_program: SYSTEM_PROGRAM_ID,
        }
        .to_account_metas(None),
        data: verdict_escrow::instruction::CreateEscrow {
            escrow_id,
            amount,
            deadline,
            seller,
            verdict_signer,
        }
        .data(),
    };

    let signature = send(rpc, &[instruction], &[buyer])?;
    println!("escrow    {escrow}");
    println!(
        "vault     {}",
        associated_token_address(&escrow, &mint, &token_program)
    );
    println!("deadline  {deadline}");
    println!("signature {signature}");
    Ok(())
}

fn show(rpc: &Rpc, escrow: Pubkey) -> Result<()> {
    let state = read_escrow(rpc, &escrow)?;
    println!("escrow         {escrow}");
    println!("buyer          {}", state.buyer);
    println!("seller         {}", state.seller);
    println!("mint           {}", state.mint);
    println!("verdict signer {}", state.verdict_signer);
    println!("amount         {}", state.amount);
    println!("deadline       {}", state.deadline);
    println!("created slot   {}", state.created_slot);
    println!("escrow id      {}", state.escrow_id);
    Ok(())
}

fn sign(
    rpc: &Rpc,
    verdict_signer: &Keypair,
    escrow: Pubkey,
    verdict: Verdict,
    expires_in: i64,
) -> Result<()> {
    let state = read_escrow(rpc, &escrow)?;
    if verdict_signer.pubkey() != state.verdict_signer {
        bail!(
            "this key is {}, but the escrow's verdict signer is {}",
            verdict_signer.pubkey(),
            state.verdict_signer
        );
    }
    let expires_at = rpc.chain_time()? + expires_in;
    let message = build_message(&verdict_escrow::ID, &escrow, &state, verdict, expires_at);
    let signature = verdict_signer.sign_message(&message);

    println!("message    {}", hex(&message));
    println!("signature  {}", hex(signature.as_ref()));
    println!("expires at {expires_at}");
    println!();
    println!("Anyone can now run:");
    println!(
        "  verdict settle --keypair <any-payer.json> --escrow {escrow} \\\n    --verdict {} --expires-at {expires_at} --signature {}",
        match verdict {
            Verdict::Release => "release",
            Verdict::Refund => "refund",
        },
        hex(signature.as_ref())
    );
    Ok(())
}

fn settle(
    rpc: &Rpc,
    payer: &Keypair,
    escrow: Pubkey,
    verdict: Verdict,
    expires_at: i64,
    signature_hex: &str,
) -> Result<()> {
    let state = read_escrow(rpc, &escrow)?;
    let token_program = token_program_of(rpc, &state.mint)?;
    let message = build_message(&verdict_escrow::ID, &escrow, &state, verdict, expires_at);
    let signature = unhex(signature_hex)?;
    if signature.len() != 64 {
        bail!("a signature is 64 bytes; got {}", signature.len());
    }

    let settle_ix = Instruction {
        program_id: verdict_escrow::ID,
        accounts: verdict_escrow::accounts::Settle {
            escrow,
            buyer: state.buyer,
            mint: state.mint,
            vault: associated_token_address(&escrow, &state.mint, &token_program),
            seller_token_account: associated_token_address(
                &state.seller,
                &state.mint,
                &token_program,
            ),
            buyer_token_account: associated_token_address(
                &state.buyer,
                &state.mint,
                &token_program,
            ),
            instructions_sysvar: INSTRUCTIONS_SYSVAR_ID,
            token_program,
        }
        .to_account_metas(None),
        data: verdict_escrow::instruction::Settle {
            verdict,
            expires_at,
        }
        .data(),
    };

    let verdict_ix = ed25519_instruction(&state.verdict_signer, &signature, &message);
    let signature = send(rpc, &[verdict_ix, settle_ix], &[payer])?;
    println!("signature {signature}");
    Ok(())
}

fn reclaim(rpc: &Rpc, buyer: &Keypair, escrow: Pubkey) -> Result<()> {
    let state = read_escrow(rpc, &escrow)?;
    let token_program = token_program_of(rpc, &state.mint)?;
    let instruction = Instruction {
        program_id: verdict_escrow::ID,
        accounts: verdict_escrow::accounts::Reclaim {
            escrow,
            buyer: buyer.pubkey(),
            mint: state.mint,
            vault: associated_token_address(&escrow, &state.mint, &token_program),
            buyer_token_account: associated_token_address(
                &state.buyer,
                &state.mint,
                &token_program,
            ),
            token_program,
        }
        .to_account_metas(None),
        data: verdict_escrow::instruction::Reclaim {}.data(),
    };
    let signature = send(rpc, &[instruction], &[buyer])?;
    println!("signature {signature}");
    Ok(())
}

/// The Ed25519 instruction in the one layout the program accepts: key at 16,
/// signature at 48, message at 112, every index field saying "this
/// instruction".
fn ed25519_instruction(
    signer: &Pubkey,
    signature: &[u8],
    message: &[u8; MESSAGE_LEN],
) -> Instruction {
    const THIS_INSTRUCTION: u16 = u16::MAX;
    let mut data = Vec::with_capacity(16 + 32 + 64 + MESSAGE_LEN);
    data.push(1); // one signature
    data.push(0); // padding
    for field in [
        48u16,
        THIS_INSTRUCTION,
        16,
        THIS_INSTRUCTION,
        112,
        MESSAGE_LEN as u16,
        THIS_INSTRUCTION,
    ] {
        data.extend_from_slice(&field.to_le_bytes());
    }
    data.extend_from_slice(&signer.to_bytes());
    data.extend_from_slice(signature);
    data.extend_from_slice(message);

    Instruction {
        program_id: ED25519_PROGRAM_ID,
        accounts: vec![],
        data,
    }
}

fn send(rpc: &Rpc, instructions: &[Instruction], signers: &[&Keypair]) -> Result<String> {
    let blockhash = rpc.latest_blockhash()?;
    let payer = signers[0].pubkey();
    let message = Message::new_with_blockhash(instructions, Some(&payer), &blockhash);
    let transaction = Transaction::new(signers, message, blockhash);
    let signature = rpc.send_transaction(&transaction)?;
    rpc.confirm(&signature)?;
    Ok(signature)
}

fn read_escrow(rpc: &Rpc, escrow: &Pubkey) -> Result<Escrow> {
    let account = rpc
        .account(escrow)?
        .ok_or_else(|| anyhow!("no escrow at {escrow}; it may already have been settled"))?;
    if account.owner != verdict_escrow::ID {
        bail!("{escrow} is owned by {}, not this program", account.owner);
    }
    Escrow::try_deserialize(&mut account.data.as_slice())
        .map_err(|err| anyhow!("{escrow} is not an escrow account: {err}"))
}

/// Which token program a mint belongs to, read from the chain rather than
/// taken as a flag.
fn token_program_of(rpc: &Rpc, mint: &Pubkey) -> Result<Pubkey> {
    let account = rpc
        .account(mint)?
        .ok_or_else(|| anyhow!("no mint at {mint}"))?;
    match account.owner {
        owner if owner == TOKEN_PROGRAM_ID || owner == TOKEN_2022_PROGRAM_ID => Ok(owner),
        other => bail!("{mint} is owned by {other}, which is not a token program"),
    }
}

fn escrow_address(buyer: &Pubkey, escrow_id: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[ESCROW_SEED, buyer.as_ref(), &escrow_id.to_le_bytes()],
        &verdict_escrow::ID,
    )
    .0
}

fn associated_token_address(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ASSOCIATED_TOKEN_PROGRAM_ID,
    )
    .0
}

fn load_keypair(path: &PathBuf) -> Result<Keypair> {
    read_keypair_file(path).map_err(|err| anyhow!("could not read {}: {err}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        bail!("hex needs an even number of characters");
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).context("not valid hex"))
        .collect()
}
