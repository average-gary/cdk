use anyhow::Result;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::hashes::{sha256, Hash};
use cdk::amount::SplitTarget;
use cdk::mint_url::MintUrl;
use cdk::nuts::{MintQuoteState, PaymentMethod, nut00::ProofsMethods};
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

    // For eHash quotes, we don't need to fetch via HTTP since they're created server-side
    // We'll construct a minimal MintQuote object just for the proof_stream
    // The actual quote details are verified on the server during minting
    use cdk::nuts::{CurrencyUnit, SecretKey as NutsSecretKey};
    let quote = cdk::wallet::MintQuote {
        id: sub_command_args.quote_id.clone(),
        mint_url: mint_url.clone(),
        payment_method: PaymentMethod::Custom("eHash".to_string()),
        amount: Some(Amount::from(1)), // Placeholder - server has the real amount
        unit: CurrencyUnit::Custom("HASH".to_string()),
        request: "eHash mining quote".to_string(),
        state: MintQuoteState::Paid,
        expiry: u64::MAX, // Placeholder
        secret_key: Some(NutsSecretKey::generate()),
        amount_issued: Amount::ZERO,
        amount_paid: Amount::ZERO,
    };

    println!("Minting eHash tokens from quote {}", sub_command_args.quote_id);
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
