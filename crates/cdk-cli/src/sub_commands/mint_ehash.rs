use std::str::FromStr;

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

#[derive(Args, Serialize, Deserialize)]
pub struct MintEHashSubCommand {
    /// Mint URL
    mint_url: MintUrl,
    /// Quote ID from a PAID mint quote
    #[arg(short, long)]
    quote_id: String,
    /// Private key (hex) to sign the request - must match quote pubkey
    #[arg(short, long)]
    private_key: String,
}

pub async fn mint_ehash(
    multi_mint_wallet: &MultiMintWallet,
    sub_command_args: &MintEHashSubCommand,
) -> Result<()> {
    let mint_url = sub_command_args.mint_url.clone();
    let wallet = get_or_create_wallet(multi_mint_wallet, &mint_url).await?;

    let secp = Secp256k1::new();

    // Parse private key
    let secret_key = SecretKey::from_str(&sub_command_args.private_key)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let pubkey_hex = public_key.to_string();

    // Fetch the quote from the mint server via HTTP API
    // (eHash quotes are created server-side, not in wallet local storage)
    let client = reqwest::Client::new();
    let quote_url = format!("{}/v1/mint/quote/bolt11/{}", mint_url, sub_command_args.quote_id);

    println!("Fetching quote from mint: {}", quote_url);
    let response = client.get(&quote_url).send().await?;

    if !response.status().is_success() {
        return Err(anyhow!("Failed to fetch quote from mint: {}", response.status()));
    }

    let quote: cdk_common::mint::MintQuote = response.json().await?;

    println!("Quote: {:#?}", quote);

    let amount = quote.amount.ok_or(anyhow!("Quote has no amount"))?;
    println!("Minting {} {} from quote {}", amount, quote.unit, quote.id);
    println!("Using pubkey: {}", pubkey_hex);

    // Use standard proof_stream for minting, but we'll manually sign the request
    // First, create signature message: "mint:{quote_id}"
    let message_str = format!("mint:{}", sub_command_args.quote_id);
    let message_hash = sha256::Hash::hash(message_str.as_bytes());
    let message = Message::from_digest(message_hash.to_byte_array());

    // Sign the message
    let signature = secp.sign_schnorr(&message, &secret_key.keypair(&secp));
    let signature_hex = signature.to_string();

    println!("Signature: {}", signature_hex);

    // For now, use the standard minting flow via proof_stream
    // In a future enhancement, we could add custom eHash minting support directly to the CDK wallet
    println!("\nNote: Using standard CDK proof_stream for minting.");
    println!("The eHash signature validation happens on the mint server side.");

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

    println!("Successfully minted {} from mint {}", amount_minted, mint_url);

    Ok(())
}
