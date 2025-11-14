use anyhow::Result;
use bitcoin::bech32::{self, Bech32m, Hrp};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use clap::Args;

#[derive(Args)]
pub struct ShowHpubSubCommand {
    // No arguments - uses hardcoded eHash derivation index
}

/// Hardcoded eHash derivation index
/// This separates eHash keys from normal Cashu wallet operations
const EHASH_DERIVATION_INDEX: u32 = 0;

/// Encode a secp256k1 public key to hpub format (bech32m)
fn encode_hpub(pubkey: &PublicKey) -> Result<String> {
    // Serialize pubkey to compressed SEC1 format (33 bytes)
    let pubkey_bytes = pubkey.serialize();

    // Create HRP
    let hrp = Hrp::parse("hpub")?;

    // Encode to bech32m
    let hpub = bech32::encode::<Bech32m>(hrp, &pubkey_bytes)?;

    Ok(hpub)
}

/// Derive an eHash keypair from seed using a simple derivation
///
/// Uses derivation path: m/purpose'/coin_type'/account'/change/address_index
/// Where purpose=84 (native segwit), coin_type=0 (Bitcoin), account=sub_command_args.index
///
/// Note: This is a simplified derivation. For production, consider using proper BIP32 HD derivation.
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

pub async fn show_hpub(seed: &[u8; 64], _sub_command_args: &ShowHpubSubCommand) -> Result<()> {
    let secp = Secp256k1::new();

    // Derive secret key from wallet seed using hardcoded eHash index
    let secret_key = derive_ehash_key_from_seed(seed, EHASH_DERIVATION_INDEX)?;

    // Derive public key
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    // Encode as hpub
    let hpub = encode_hpub(&public_key)?;

    // Print results
    println!("═══════════════════════════════════════════════");
    println!("  eHash Mining Identity");
    println!("═══════════════════════════════════════════════");
    println!();
    println!("Derived from wallet seed (eHash derivation path)");
    println!();

    println!("Public Key (hex):");
    println!("  {}", public_key);
    println!();

    println!("Public Key (hpub format - use this for mining):");
    println!("  {}", hpub);
    println!();

    println!("Use this hpub in your mining configuration:");
    println!("  - TProxy config: default_locking_pubkey = \"{}\"", hpub);
    println!("  - Pool config: default_locking_pubkey = \"{}\"", hpub);
    println!();
    println!("Query and redeem eHash:");
    println!("  cdk-cli get-quotes-by-pubkey <MINT_URL>");
    println!("  cdk-cli mint-e-hash <MINT_URL> <QUOTE_ID>");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::SecretKey;

    #[test]
    fn test_encode_hpub() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &secret_key);

        let result = encode_hpub(&pubkey);
        assert!(result.is_ok());

        let hpub = result.unwrap();
        assert!(hpub.starts_with("hpub1"));
        assert!(hpub.len() > 10);
    }

    #[test]
    fn test_encode_hpub_deterministic() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &secret_key);

        let hpub1 = encode_hpub(&pubkey).unwrap();
        let hpub2 = encode_hpub(&pubkey).unwrap();

        assert_eq!(hpub1, hpub2);
    }
}
