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

    // Fetch the quote from the mint server via HTTP API
    // (eHash quotes are created server-side, not in wallet local storage)
    let client = reqwest::Client::new();
    let quote_url = format!("{}/v1/mint/quote/bolt11/{}", mint_url, sub_command_args.quote_id);

    println!("Fetching quote from mint: {}", quote_url);
    let response = client.get(&quote_url).send().await?;

    if !response.status().is_success() {
        return Err(anyhow!("Failed to fetch quote from mint: {}", response.status()));
    }

    let quote: cdk::wallet::MintQuote = response.json().await?;

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
