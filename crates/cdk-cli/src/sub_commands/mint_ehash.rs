use anyhow::{anyhow, Result};
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::hashes::{sha256, Hash};
use cdk::amount::SplitTarget;
use cdk::mint_url::MintUrl;
use cdk::nuts::nut00::ProofsMethods;
use cdk::wallet::MultiMintWallet;
use cdk::{Amount, StreamExt};
use clap::Args;
use serde::{Deserialize, Serialize};

use crate::utils::get_or_create_wallet;

/// Hardcoded eHash derivation index (matches show-hpub)
/// This separates eHash keys from normal Cashu wallet operations
const EHASH_DERIVATION_INDEX: u32 = 0;

/// Derive an eHash keypair from seed (same logic as show_hpub)
fn derive_ehash_key_from_seed(seed: &[u8], index: u32) -> Result<SecretKey> {
    use bitcoin::hashes::{sha256, Hash, HashEngine};

    // Create a deterministic key using HMAC-SHA256
    // Domain: "ehash-mining-key"
    // Data: seed || index
    let mut engine = sha256::Hash::engine();
    engine.input(b"ehash-mining-key");
    engine.input(seed);
    engine.input(&index.to_le_bytes());
    let hash = sha256::Hash::from_engine(engine);

    // Use the hash as the secret key
    let secret_key = SecretKey::from_slice(hash.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to derive key: {}", e))?;

    Ok(secret_key)
}

#[derive(Args, Serialize, Deserialize)]
pub struct MintEHashSubCommand {
    /// Mint URL
    mint_url: MintUrl,
    /// Quote ID from a PAID mint quote
    #[arg(short, long)]
    quote_id: String,
}

pub async fn mint_ehash(
    seed: &[u8; 64],
    multi_mint_wallet: &MultiMintWallet,
    sub_command_args: &MintEHashSubCommand,
) -> Result<()> {
    let mint_url = sub_command_args.mint_url.clone();
    let wallet = get_or_create_wallet(multi_mint_wallet, &mint_url).await?;

    let secp = Secp256k1::new();

    // Derive eHash key from wallet seed using hardcoded index
    let secret_key = derive_ehash_key_from_seed(seed, EHASH_DERIVATION_INDEX)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let pubkey_hex = public_key.to_string();

    // eHash quotes are created server-side by the pool, so we need to fetch them from the mint
    println!("Fetching quote from mint server...");

    let client = reqwest::Client::new();

    // Create signature for get_quotes request
    let message_str = format!("get_quotes:{}", pubkey_hex);
    let message_hash = sha256::Hash::hash(message_str.as_bytes());
    let message = Message::from_digest(message_hash.to_byte_array());
    let signature = secp.sign_schnorr(&message, &secret_key.keypair(&secp));

    // Fetch quote from server via get-quotes-by-pubkey endpoint
    #[derive(Serialize)]
    struct QuotesRequest {
        pubkey: String,
        signature: String,
    }

    #[derive(Deserialize)]
    struct QuotesResponse {
        quotes: Vec<ServerQuote>,
    }

    #[derive(Deserialize)]
    struct ServerQuote {
        quote_id: String,
        amount: u64,
        unit: String,
        state: String,
    }

    let url = format!("{}/v1/mint/quotes/by-pubkey", mint_url);
    let response = client
        .post(&url)
        .json(&QuotesRequest {
            pubkey: pubkey_hex.clone(),
            signature: signature.to_string(),
        })
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow!("Failed to fetch quotes: {}", response.status()));
    }

    let quotes_response: QuotesResponse = response.json().await?;

    // Find our specific quote
    let server_quote = quotes_response
        .quotes
        .iter()
        .find(|q| q.quote_id == sub_command_args.quote_id)
        .ok_or_else(|| anyhow!("Quote {} not found on server", sub_command_args.quote_id))?;

    println!("Found quote: {} {} (state: {})", server_quote.amount, server_quote.unit, server_quote.state);

    // Create a MintQuote for proof_stream with Custom payment method
    use cdk::nuts::{CurrencyUnit, MintQuoteState, PaymentMethod};
    use std::str::FromStr;

    let quote = cdk::wallet::MintQuote {
        id: sub_command_args.quote_id.clone(),
        mint_url: mint_url.clone(),
        payment_method: PaymentMethod::Custom("HASH".to_string()),
        amount: Some(Amount::from(server_quote.amount)),
        unit: CurrencyUnit::from_str(&server_quote.unit)?,
        request: "eHash mining quote".to_string(),
        state: MintQuoteState::Paid,
        expiry: unix_time() + 86400,
        secret_key: None,
        amount_issued: Amount::ZERO,
        amount_paid: Amount::from(server_quote.amount),
    };

    println!("Minting {} {} from quote...", server_quote.amount, server_quote.unit);

    // Use proof_stream which now supports Custom payment methods
    let mut amount_minted = Amount::ZERO;
    let mut proof_streams = wallet.proof_stream(quote, SplitTarget::default(), None);

    while let Some(proofs) = proof_streams.next().await {
        let proofs = match proofs {
            Ok(proofs) => proofs,
            Err(err) => {
                tracing::error!("Proof streams ended with {:?}", err);
                break;
            }
        };
        amount_minted += proofs.total_amount()?;
    }

    println!("\n✅ Successfully minted {} HASH tokens!", amount_minted);
    println!("Tokens have been added to your wallet.");

    Ok(())
}

fn unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
