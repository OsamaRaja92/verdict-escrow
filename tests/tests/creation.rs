//! What `create_escrow` refuses to open in the first place.

use escrow_harness::*;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use verdict_escrow::errors::EscrowError;
use verdict_escrow::verdict::Verdict;

#[test]
fn a_zero_amount_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let deadline = h.now() + HOUR;
        let (_, result) = h.create_escrow_with(1, 0, deadline);
        assert_error(&result, EscrowError::ZeroAmount);
    });
}

#[test]
fn a_deadline_in_the_past_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let deadline = h.now() - 1;
        let (_, result) = h.create_escrow_with(1, ESCROW_AMOUNT, deadline);
        assert_error(&result, EscrowError::DeadlineNotInFuture);
    });
}

#[test]
fn a_deadline_of_right_now_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        // An escrow that is already past its deadline could be reclaimed in
        // the same breath, so the deadline has to be strictly ahead.
        let deadline = h.now();
        let (_, result) = h.create_escrow_with(1, ESCROW_AMOUNT, deadline);
        assert_error(&result, EscrowError::DeadlineNotInFuture);
    });
}

#[test]
fn an_unset_seller_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let deadline = h.now() + HOUR;
        let ix = h.create_escrow_ix(
            &buyer,
            1,
            ESCROW_AMOUNT,
            deadline,
            anchor_lang::prelude::Pubkey::default(),
            h.verdict_signer.pubkey(),
        );
        let signer = h.buyer.insecure_clone();
        let result = h.send(&[ix], &[&signer]);
        assert_error(&result, EscrowError::SellerNotSet);
    });
}

#[test]
fn an_unset_verdict_signer_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let deadline = h.now() + HOUR;
        let ix = h.create_escrow_ix(
            &buyer,
            1,
            ESCROW_AMOUNT,
            deadline,
            h.seller.pubkey(),
            anchor_lang::prelude::Pubkey::default(),
        );
        let signer = h.buyer.insecure_clone();
        let result = h.send(&[ix], &[&signer]);
        assert_error(&result, EscrowError::VerdictSignerNotSet);
    });
}

#[test]
fn more_than_the_buyer_holds_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let deadline = h.now() + HOUR;
        let (escrow, result) = h.create_escrow_with(1, BUYER_START + 1, deadline);
        // The token program refuses the transfer; no escrow is left behind.
        assert!(result.is_err());
        assert!(!h.account_exists(&escrow));
    });
}

/// A Token-2022 mint with a transfer fee attached.
///
/// This program does not model what extensions do to a transfer, so it refuses
/// any mint that carries one. The rule it enforces is simply that the mint
/// account is the bare 82 bytes of a mint with nothing appended.
#[test]
fn a_mint_with_extensions_is_refused() {
    let mut h = Harness::new(TokenKind::Token2022);

    let mint = Keypair::new();
    let buyer = h.buyer.insecure_clone();
    let authority = buyer.pubkey();

    // Base mint (82) padded to 165, the account-type byte, then one TLV entry
    // for TransferFeeConfig (4 byte header + 108 bytes).
    const EXTENDED_MINT_LEN: usize = 166 + 4 + 108;
    let lamports = h.svm.minimum_balance_for_rent_exemption(EXTENDED_MINT_LEN);

    let mut create_data = Vec::new();
    create_data.extend_from_slice(&0u32.to_le_bytes()); // SystemInstruction::CreateAccount
    create_data.extend_from_slice(&lamports.to_le_bytes());
    create_data.extend_from_slice(&(EXTENDED_MINT_LEN as u64).to_le_bytes());
    create_data.extend_from_slice(&TOKEN_2022_PROGRAM_ID.to_bytes());
    let create_account = Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(mint.pubkey(), true),
        ],
        data: create_data,
    };

    // TransferFeeExtension (26) / InitializeTransferFeeConfig (0), with no
    // authorities, 1% fee, no cap.
    let mut fee_data = vec![26u8, 0u8, 0u8, 0u8];
    fee_data.extend_from_slice(&100u16.to_le_bytes());
    fee_data.extend_from_slice(&u64::MAX.to_le_bytes());
    let init_transfer_fee = Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![AccountMeta::new(mint.pubkey(), false)],
        data: fee_data,
    };

    // InitializeMint2 (20).
    let mut init_data = vec![20u8, DECIMALS];
    init_data.extend_from_slice(&authority.to_bytes());
    init_data.push(0); // no freeze authority
    let init_mint = Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![AccountMeta::new(mint.pubkey(), false)],
        data: init_data,
    };

    let result = h.send(
        &[create_account, init_transfer_fee, init_mint],
        &[&buyer, &mint],
    );
    assert_ok(&result);
    let mint_len = h.svm.get_account(&mint.pubkey()).unwrap().data.len();
    assert!(
        mint_len > 82,
        "the point of this test is a mint longer than the bare 82 bytes"
    );

    // Give the buyer an account for it and some balance, so the escrow fails
    // on the mint itself rather than for want of tokens.
    h.mint = mint.pubkey();
    let buyer_ata = h.create_ata(&authority);
    let mut mint_to = vec![7u8]; // MintTo
    mint_to.extend_from_slice(&BUYER_START.to_le_bytes());
    assert_ok(&h.send(
        &[Instruction {
            program_id: TOKEN_2022_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(mint.pubkey(), false),
                AccountMeta::new(buyer_ata, false),
                AccountMeta::new_readonly(authority, true),
            ],
            data: mint_to,
        }],
        &[&buyer],
    ));
    h.create_ata(&h.seller.pubkey());

    let deadline = h.now() + HOUR;
    let (_, result) = h.create_escrow_with(1, ESCROW_AMOUNT, deadline);
    assert_error(&result, EscrowError::UnsupportedMintExtensions);
}

/// A stranger can create the escrow's vault before the escrow exists — the
/// address is derivable from the buyer and the id alone — and can put tokens
/// in it. Neither may stop the buyer from opening the escrow, or the vault
/// would be a cheap way to make any `(buyer, escrow_id, mint)` unusable.
#[test]
fn a_vault_created_and_funded_in_advance_does_not_block_the_escrow() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let escrow = h.escrow_pda(&buyer, 1);

        // A stranger gets there first, and leaves a donation behind.
        let vault = h.create_ata(&escrow);
        const DONATION: u64 = 7;
        let payer = h.buyer.insecure_clone();
        let mint = h.mint;
        let token_program = h.token_program;
        litesvm_token::MintTo::new(&mut h.svm, &payer, &mint, &vault, DONATION)
            .token_program_id(&token_program)
            .send()
            .expect("fund the vault in advance");

        let (opened, result) = h.create_escrow(1);
        assert_ok(&result);
        assert_eq!(opened, escrow);

        // The escrow records what the buyer escrowed, and the vault holds that
        // plus whatever was already there.
        assert_eq!(h.escrow_state(&escrow).amount, ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT + DONATION);

        // The donation leaves with the payout rather than stranding the close.
        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
        assert_eq!(
            h.token_balance(&h.ata(&h.seller.pubkey())),
            ESCROW_AMOUNT + DONATION
        );
        assert!(!h.account_exists(&vault));
    });
}
