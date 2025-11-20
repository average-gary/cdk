use anyhow::Result;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use cdk::amount::SplitTarget;
use cdk::mint_url::MintUrl;
use cdk::wallet::MultiMintWallet;
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

    println!("Minting eHash tokens from quote {}", sub_command_args.quote_id);
    println!("Using pubkey: {}", pubkey_hex);

    // For eHash minting, we need to:
    // 1. Get the quote amount from the mint
    // 2. Create blinded messages for that amount
    // 3. Submit to the /v1/mint/ehash endpoint with signature

    // Since eHash quotes are already PAID, we can mint immediately
    // Use wallet.mint() which handles PAID quotes
    use cdk::nuts::nut00::ProofsMethods;
    let proofs = wallet
        .mint(&sub_command_args.quote_id, SplitTarget::default(), None)
        .await?;

    let amount_minted = proofs.total_amount()?;

    println!("\n✅ Successfully minted {} HASH tokens!", amount_minted);
    println!("Received {} proof(s)", proofs.len());
    println!("Tokens have been added to your wallet.");

    Ok(())
}
