use std::str::FromStr;

use anyhow::Result;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::hashes::{sha256, Hash};
use cdk::mint_url::MintUrl;
use clap::Args;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Args, Serialize, Deserialize)]
pub struct GetQuotesByPubkeySubCommand {
    /// Mint URL
    mint_url: MintUrl,
    /// Private key (hex) to sign the request
    #[arg(short, long)]
    private_key: String,
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

pub async fn get_quotes_by_pubkey(sub_command_args: &GetQuotesByPubkeySubCommand) -> Result<()> {
    let secp = Secp256k1::new();

    // Parse private key
    let secret_key = SecretKey::from_str(&sub_command_args.private_key)?;
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
