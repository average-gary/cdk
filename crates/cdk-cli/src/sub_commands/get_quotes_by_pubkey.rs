use anyhow::Result;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::hashes::{sha256, Hash};
use cdk::mint_url::MintUrl;
use clap::Args;
use reqwest::Client;
use serde::{Deserialize, Serialize};

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
pub struct GetQuotesByPubkeySubCommand {
    /// Mint URL
    mint_url: MintUrl,
}

#[derive(Debug, Serialize, Deserialize)]
struct QuotesByPubkeyRequest {
    pubkey: String,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EHashQuoteSummary {
    quote_id: String,
    amount: u64,
    unit: String,
    state: String,
    expiry: Option<u64>,
    created_time: u64,
    request: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct QuotesByPubkeyResponse {
    quotes: Vec<EHashQuoteSummary>,
}

pub async fn get_quotes_by_pubkey(seed: &[u8; 64], sub_command_args: &GetQuotesByPubkeySubCommand) -> Result<()> {
    let secp = Secp256k1::new();

    // Derive eHash key from wallet seed using hardcoded index
    let secret_key = derive_ehash_key_from_seed(seed, EHASH_DERIVATION_INDEX)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let pubkey_hex = public_key.to_string();

    // Create signature message: "get_quotes:{pubkey_hex}"
    let message_str = format!("get_quotes:{}", pubkey_hex);
    let message_hash = sha256::Hash::hash(message_str.as_bytes());
    let message = Message::from_digest(message_hash.to_byte_array());

    // Sign the message
    let signature = secp.sign_schnorr(&message, &secret_key.keypair(&secp));
    let signature_hex = signature.to_string();

    // Create request
    let request = QuotesByPubkeyRequest {
        pubkey: pubkey_hex.clone(),
        signature: signature_hex,
    };

    // Send request to mint
    let client = Client::new();
    let url = format!("{}/v1/mint/quotes/by-pubkey", sub_command_args.mint_url);

    println!("Requesting quotes for pubkey: {}", pubkey_hex);
    println!("Sending request to: {}", url);

    let response = client
        .post(&url)
        .json(&request)
        .send()
        .await?;

    let status = response.status();
    println!("Response status: {}", status);

    if status.is_success() {
        let response_body: QuotesByPubkeyResponse = response.json().await?;

        println!("\nFound {} quote(s):", response_body.quotes.len());
        for quote in response_body.quotes {
            println!("\n  Quote ID: {}", quote.quote_id);
            println!("  Amount: {} {}", quote.amount, quote.unit);
            println!("  State: {}", quote.state);
            if let Some(expiry) = quote.expiry {
                println!("  Expiry: {}", expiry);
            }
            println!("  Created: {}", quote.created_time);
            println!("  Request: {}", quote.request);
        }
    } else {
        let error_text = response.text().await?;
        println!("Error: {}", error_text);
    }

    Ok(())
}
