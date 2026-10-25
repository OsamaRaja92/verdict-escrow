//! Four JSON-RPC calls, by hand.
//!
//! The full Solana client stack would pull in a web server's worth of
//! dependencies to do this much.

use anchor_lang::prelude::Pubkey;
use anyhow::{anyhow, bail, Context, Result};
use base64::prelude::{Engine, BASE64_STANDARD};
use serde_json::{json, Value};
use solana_hash::Hash;
use solana_transaction::Transaction;
use std::time::Duration;

pub struct Account {
    pub owner: Pubkey,
    pub data: Vec<u8>,
}

pub struct Rpc {
    url: String,
    agent: ureq::Agent,
}

impl Rpc {
    pub fn new(url: impl Into<String>) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Self {
            url: url.into(),
            agent,
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let mut response = self
            .agent
            .post(&self.url)
            .send_json(&body)
            .with_context(|| format!("{method} request failed"))?;
        let payload: Value = response
            .body_mut()
            .read_json()
            .with_context(|| format!("{method} returned something that is not JSON"))?;
        if let Some(error) = payload.get("error") {
            bail!("{method} failed: {error}");
        }
        payload
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow!("{method} returned no result"))
    }

    /// An account, or `None` if it does not exist.
    pub fn account(&self, address: &Pubkey) -> Result<Option<Account>> {
        let result = self.call(
            "getAccountInfo",
            json!([address.to_string(), {"encoding": "base64", "commitment": "confirmed"}]),
        )?;
        let value = &result["value"];
        if value.is_null() {
            return Ok(None);
        }
        let encoded = value["data"][0]
            .as_str()
            .ok_or_else(|| anyhow!("account data was not base64"))?;
        let owner = value["owner"]
            .as_str()
            .ok_or_else(|| anyhow!("account had no owner"))?
            .parse()
            .context("could not parse the account owner")?;
        Ok(Some(Account {
            owner,
            data: BASE64_STANDARD.decode(encoded)?,
        }))
    }

    /// The chain's own clock, so deadlines are set against it rather than
    /// against whatever time this machine thinks it is.
    pub fn chain_time(&self) -> Result<i64> {
        const CLOCK_SYSVAR: Pubkey =
            Pubkey::from_str_const("SysvarC1ock11111111111111111111111111111111");
        let account = self
            .account(&CLOCK_SYSVAR)?
            .ok_or_else(|| anyhow!("the clock sysvar is missing"))?;
        // slot, epoch_start_timestamp, epoch, leader_schedule_epoch, then the
        // wall clock at byte 32.
        let bytes: [u8; 8] = account.data[32..40]
            .try_into()
            .context("clock sysvar was too short")?;
        Ok(i64::from_le_bytes(bytes))
    }

    pub fn latest_blockhash(&self) -> Result<Hash> {
        let result = self.call("getLatestBlockhash", json!([{"commitment": "confirmed"}]))?;
        let blockhash = result["value"]["blockhash"]
            .as_str()
            .ok_or_else(|| anyhow!("no blockhash in response"))?;
        blockhash.parse().context("could not parse the blockhash")
    }

    pub fn send_transaction(&self, transaction: &Transaction) -> Result<String> {
        let wire = bincode_serialize(transaction)?;
        let encoded = BASE64_STANDARD.encode(wire);
        let result = self.call(
            "sendTransaction",
            json!([encoded, {"encoding": "base64", "preflightCommitment": "confirmed"}]),
        )?;
        result
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("sendTransaction returned no signature"))
    }

    /// Poll until the transaction is confirmed, or give up.
    pub fn confirm(&self, signature: &str) -> Result<()> {
        for _ in 0..30 {
            let result = self.call(
                "getSignatureStatuses",
                json!([[signature], {"searchTransactionHistory": false}]),
            )?;
            let status = &result["value"][0];
            if !status.is_null() {
                if let Some(error) = status.get("err").filter(|err| !err.is_null()) {
                    bail!("the transaction landed but failed: {error}");
                }
                let confirmation = status["confirmationStatus"].as_str().unwrap_or_default();
                if confirmation == "confirmed" || confirmation == "finalized" {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        bail!("timed out waiting for {signature} to confirm")
    }
}

/// The wire format a Solana transaction goes out in: a shortvec-prefixed list
/// of 64-byte signatures, then the serialized message.
fn bincode_serialize(transaction: &Transaction) -> Result<Vec<u8>> {
    let mut wire = Vec::new();
    write_shortvec_len(&mut wire, transaction.signatures.len());
    for signature in &transaction.signatures {
        wire.extend_from_slice(signature.as_ref());
    }
    wire.extend_from_slice(&transaction.message.serialize());
    Ok(wire)
}

fn write_shortvec_len(buffer: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            buffer.push(byte);
            return;
        }
        byte |= 0x80;
        buffer.push(byte);
    }
}
