//! # Verdict escrow
//!
//! A buyer locks tokens in a vault this program owns. The money moves only
//! when an outside signer's signed verdict says to release it to the seller or
//! refund it to the buyer. If no verdict arrives before the deadline, the buyer
//! takes it back.
//!
//! The lifecycle is short and has no middle: `create_escrow`, then exactly one
//! of `settle` (before the deadline, against a verdict) or `reclaim` (at or
//! after the deadline, by the buyer). Both exits pay out the whole vault and
//! close both accounts, so there is nothing left for a second call to act on.

use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token_interface::{
    close_account, transfer_checked, CloseAccount, Mint, TokenAccount, TokenInterface,
    TransferChecked,
};

pub mod errors;
pub mod events;
pub mod state;
pub mod verdict;

use errors::EscrowError;
use events::{EscrowCreated, EscrowReclaimed, EscrowSettled};
use state::{Escrow, ESCROW_SEED};
use verdict::{build_message, verify_verdict, Verdict};

declare_id!("DhXqHjZuT3ZJoUXzj3XmeBUMmLAwiHV4VKPZcvntTfba");

/// Size of a mint account with no extensions, under either token program.
/// Anything longer carries at least one extension — a transfer fee, a transfer
/// hook, a permanent delegate, confidential transfers — whose effect on a
/// transfer this program does not model, so it refuses the mint outright.
const BASE_MINT_LEN: usize = 82;

#[program]
pub mod verdict_escrow {
    use super::*;

    /// Open an escrow and fund it. The buyer signs, and chooses the seller,
    /// the verdict signer and the deadline here; none of the three can change
    /// afterwards.
    pub fn create_escrow(
        ctx: Context<CreateEscrow>,
        escrow_id: u64,
        amount: u64,
        deadline: i64,
        seller: Pubkey,
        verdict_signer: Pubkey,
    ) -> Result<()> {
        let clock = Clock::get()?;

        require!(amount > 0, EscrowError::ZeroAmount);
        require!(
            deadline > clock.unix_timestamp,
            EscrowError::DeadlineNotInFuture
        );
        require_keys_neq!(seller, Pubkey::default(), EscrowError::SellerNotSet);
        require_keys_neq!(
            verdict_signer,
            Pubkey::default(),
            EscrowError::VerdictSignerNotSet
        );
        require!(
            ctx.accounts.mint.to_account_info().data_len() == BASE_MINT_LEN,
            EscrowError::UnsupportedMintExtensions
        );

        // The vault can already exist and can already hold tokens — anyone may
        // create an associated token account for any owner, and anyone may send
        // tokens to one. So the check below is on the delta, not the balance.
        let balance_before = ctx.accounts.vault.amount;

        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferChecked {
                    from: ctx.accounts.buyer_token_account.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                    authority: ctx.accounts.buyer.to_account_info(),
                },
            ),
            amount,
            ctx.accounts.mint.decimals,
        )?;

        // What the vault actually received is the only number worth storing. A
        // mint that takes a cut on transfer would land less than `amount` here;
        // rejecting extensions above should already have stopped that, and this
        // is the check that proves it rather than assuming it.
        let expected = balance_before
            .checked_add(amount)
            .ok_or(EscrowError::VaultBalanceOverflow)?;
        ctx.accounts.vault.reload()?;
        require!(
            ctx.accounts.vault.amount == expected,
            EscrowError::VaultAmountMismatch
        );

        ctx.accounts.escrow.set_inner(Escrow {
            buyer: ctx.accounts.buyer.key(),
            seller,
            mint: ctx.accounts.mint.key(),
            verdict_signer,
            amount,
            deadline,
            created_slot: clock.slot,
            escrow_id,
            bump: ctx.bumps.escrow,
        });

        emit!(EscrowCreated {
            escrow: ctx.accounts.escrow.key(),
            buyer: ctx.accounts.buyer.key(),
            seller,
            mint: ctx.accounts.mint.key(),
            verdict_signer,
            amount,
            deadline,
            created_slot: clock.slot,
            escrow_id,
        });

        Ok(())
    }

    /// Pay out against a signed verdict, before the deadline.
    ///
    /// Anyone may send this instruction — a relayer can pay the fee — because
    /// the authority is the signature, not the sender. The destination comes
    /// from the verdict and the escrow's own state; no argument names a
    /// destination or an amount.
    pub fn settle(ctx: Context<Settle>, verdict: Verdict, expires_at: i64) -> Result<()> {
        let clock = Clock::get()?;
        require!(
            clock.unix_timestamp < ctx.accounts.escrow.deadline,
            EscrowError::DeadlinePassed
        );
        require!(
            clock.unix_timestamp <= expires_at,
            EscrowError::VerdictExpired
        );

        let escrow_key = ctx.accounts.escrow.key();
        let expected_message = build_message(
            ctx.program_id,
            &escrow_key,
            &ctx.accounts.escrow,
            verdict,
            expires_at,
        );
        verify_verdict(
            &ctx.accounts.instructions_sysvar.to_account_info(),
            &ctx.accounts.escrow.verdict_signer,
            &expected_message,
        )?;

        let destination = match verdict {
            Verdict::Release => ctx.accounts.seller_token_account.to_account_info(),
            Verdict::Refund => ctx.accounts.buyer_token_account.to_account_info(),
        };

        let buyer_key = ctx.accounts.escrow.buyer;
        let id_bytes = ctx.accounts.escrow.escrow_id.to_le_bytes();
        let bump = [ctx.accounts.escrow.bump];
        let seeds: &[&[u8]] = &[ESCROW_SEED, buyer_key.as_ref(), id_bytes.as_ref(), &bump];
        let signer_seeds = &[seeds];

        // Pay the whole vault, not the recorded amount: if anyone donated
        // tokens to the vault, they leave with the payout instead of making
        // the close below fail on a non-empty account.
        let amount = ctx.accounts.vault.amount;
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.key(),
                TransferChecked {
                    from: ctx.accounts.vault.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: destination.clone(),
                    authority: ctx.accounts.escrow.to_account_info(),
                },
                signer_seeds,
            ),
            amount,
            ctx.accounts.mint.decimals,
        )?;

        close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            CloseAccount {
                account: ctx.accounts.vault.to_account_info(),
                destination: ctx.accounts.buyer.to_account_info(),
                authority: ctx.accounts.escrow.to_account_info(),
            },
            signer_seeds,
        ))?;

        emit!(EscrowSettled {
            escrow: escrow_key,
            buyer: ctx.accounts.escrow.buyer,
            seller: ctx.accounts.escrow.seller,
            mint: ctx.accounts.escrow.mint,
            verdict_signer: ctx.accounts.escrow.verdict_signer,
            verdict: verdict.message_code(),
            destination: destination.key(),
            amount,
        });

        Ok(())
    }

    /// Take the money back once the deadline has passed. Only the buyer can,
    /// and only then — which is what keeps this from racing `settle`.
    pub fn reclaim(ctx: Context<Reclaim>) -> Result<()> {
        let clock = Clock::get()?;
        require!(
            clock.unix_timestamp >= ctx.accounts.escrow.deadline,
            EscrowError::DeadlineNotReached
        );

        let escrow_key = ctx.accounts.escrow.key();
        let buyer_key = ctx.accounts.escrow.buyer;
        let id_bytes = ctx.accounts.escrow.escrow_id.to_le_bytes();
        let bump = [ctx.accounts.escrow.bump];
        let seeds: &[&[u8]] = &[ESCROW_SEED, buyer_key.as_ref(), id_bytes.as_ref(), &bump];
        let signer_seeds = &[seeds];

        let amount = ctx.accounts.vault.amount;
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.key(),
                TransferChecked {
                    from: ctx.accounts.vault.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.buyer_token_account.to_account_info(),
                    authority: ctx.accounts.escrow.to_account_info(),
                },
                signer_seeds,
            ),
            amount,
            ctx.accounts.mint.decimals,
        )?;

        close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            CloseAccount {
                account: ctx.accounts.vault.to_account_info(),
                destination: ctx.accounts.buyer.to_account_info(),
                authority: ctx.accounts.escrow.to_account_info(),
            },
            signer_seeds,
        ))?;

        emit!(EscrowReclaimed {
            escrow: escrow_key,
            buyer: buyer_key,
            mint: ctx.accounts.escrow.mint,
            amount,
        });

        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(escrow_id: u64)]
pub struct CreateEscrow<'info> {
    #[account(mut)]
    pub buyer: Signer<'info>,

    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        init,
        payer = buyer,
        space = 8 + Escrow::INIT_SPACE,
        seeds = [ESCROW_SEED, buyer.key().as_ref(), escrow_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub escrow: Account<'info, Escrow>,

    /// The vault is the escrow's associated token account, so its address
    /// follows from the escrow and the mint and the caller cannot choose it.
    ///
    /// `init_if_needed` rather than `init`, because anyone can create an
    /// associated token account for any owner, and the escrow's address is
    /// public before the escrow exists. With plain `init`, a stranger could
    /// create this vault first for the price of its rent and make a given
    /// `(buyer, escrow_id, mint)` permanently unusable. Accepting an existing
    /// account is safe here: its address is derived, not passed, so the
    /// constraints below still pin its mint, authority and token program; the
    /// escrow account above is `init`, so no escrow can be re-opened on top of
    /// a live one; only this program, signing as the escrow, can move anything
    /// out of the vault or delegate it; and any balance a stranger left in it
    /// is covered by the deposit check, which looks at the delta.
    #[account(
        init_if_needed,
        payer = buyer,
        associated_token::mint = mint,
        associated_token::authority = escrow,
        associated_token::token_program = token_program,
    )]
    pub vault: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = buyer,
        associated_token::token_program = token_program,
    )]
    pub buyer_token_account: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Settle<'info> {
    #[account(
        mut,
        close = buyer,
        has_one = buyer,
        has_one = mint,
        seeds = [ESCROW_SEED, escrow.buyer.as_ref(), escrow.escrow_id.to_le_bytes().as_ref()],
        bump = escrow.bump,
    )]
    pub escrow: Account<'info, Escrow>,

    /// Receives the rent from both closed accounts, whichever way the verdict
    /// goes. It does not sign: `settle` has no privileged signer at all.
    #[account(mut)]
    pub buyer: SystemAccount<'info>,

    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = escrow,
        associated_token::token_program = token_program,
    )]
    pub vault: InterfaceAccount<'info, TokenAccount>,

    /// Both payout destinations are pinned to the stored seller and buyer and
    /// to the stored mint. The verdict picks which one is paid.
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = escrow.seller,
        associated_token::token_program = token_program,
    )]
    pub seller_token_account: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = escrow.buyer,
        associated_token::token_program = token_program,
    )]
    pub buyer_token_account: InterfaceAccount<'info, TokenAccount>,

    /// CHECK: pinned to the instructions sysvar address and read only through
    /// the typed helpers in `verdict.rs`.
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct Reclaim<'info> {
    #[account(
        mut,
        close = buyer,
        has_one = buyer,
        has_one = mint,
        seeds = [ESCROW_SEED, escrow.buyer.as_ref(), escrow.escrow_id.to_le_bytes().as_ref()],
        bump = escrow.bump,
    )]
    pub escrow: Account<'info, Escrow>,

    #[account(mut)]
    pub buyer: Signer<'info>,

    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = escrow,
        associated_token::token_program = token_program,
    )]
    pub vault: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = escrow.buyer,
        associated_token::token_program = token_program,
    )]
    pub buyer_token_account: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Interface<'info, TokenInterface>,
}
