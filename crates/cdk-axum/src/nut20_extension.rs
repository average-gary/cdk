//! NUT-20 Extension for eHash: Authenticated Quote Discovery and Minting
//!
//! This module extends cdk-axum with eHash-specific endpoints that allow miners
//! to discover their quotes using authenticated public key queries and mint tokens
//! from paid quotes. All operations require BIP340 Schnorr signature verification
//! to prove ownership of the locking public key.

use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::secp256k1::schnorr::Signature;
use cdk::amount::Amount;
use cdk::error::{ErrorCode, ErrorResponse};
use cdk::mint::QuoteId;
use cdk::nuts::{BlindSignature, BlindedMessage, CurrencyUnit, MintQuoteState, MintRequest, PublicKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tracing::{debug, instrument, warn};

use crate::MintState;

/// Request to query mint quotes by public key with signature authentication
///
/// This request allows miners to discover all their PAID quotes by providing
/// their locking public key (in hex or hpub format) and a signature proving ownership.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct QuotesByPubkeyRequest {
    /// Public key in hex format (64 chars) or hpub bech32 format
    ///
    /// Example hex: "03a1b2c3d4e5f6..."
    /// Example hpub: "hpub1q..."
    pub pubkey: String,

    /// BIP340 Schnorr signature over the message "get_quotes:{pubkey_hex}"
    ///
    /// The signature must be created using the private key corresponding to the pubkey.
    /// The message to sign is constructed as: "get_quotes:" + hex_encoded_pubkey
    pub signature: String,
}

/// Summary information about a mint quote for quote discovery responses
///
/// This struct contains essential quote information needed by miners to
/// decide which quotes to mint tokens from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct EHashQuoteSummary {
    /// Quote ID - used to request minting
    pub quote_id: String,

    /// Amount that was paid for this quote
    pub amount: Amount,

    /// Currency unit (e.g., "sat" or "HASH")
    pub unit: CurrencyUnit,

    /// Quote state (should be PAID for quotes returned by discovery)
    pub state: MintQuoteState,

    /// Unix timestamp when quote expires
    pub expiry: u64,

    /// Unix timestamp when quote was created
    pub created_time: u64,

    /// Payment request (e.g., eHash payment details)
    pub request: String,
}

/// Response containing all PAID quotes for an authenticated public key
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct QuotesByPubkeyResponse {
    /// List of PAID quotes associated with the authenticated public key
    pub quotes: Vec<EHashQuoteSummary>,
}

/// Request to mint eHash tokens from a PAID quote with signature authentication
///
/// This is the eHash-specific minting endpoint that verifies the quote's pubkey
/// matches the signature before processing the mint request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct PostMintEHashRequest {
    /// Quote ID to mint from
    pub quote: String,

    /// Blinded messages (outputs) to be signed by the mint
    pub outputs: Vec<BlindedMessage>,

    /// BIP340 Schnorr signature over the mint request message (NUT-20 format)
    ///
    /// The signature must be from the private key corresponding to the quote's pubkey.
    /// Message format per NUT-20: quote_id || B_0 || B_1 || ... || B_n
    pub signature: String,
}

/// Response from eHash minting endpoint containing blind signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct PostMintEHashResponse {
    /// Blind signatures for the requested outputs
    pub signatures: Vec<BlindSignature>,
}

/// Parse pubkey from either hex or hpub format
///
/// This function supports both raw hex public keys and hpub-encoded public keys,
/// providing flexibility for different client implementations.
///
/// # Arguments
///
/// * `pubkey_str` - Public key as hex string or hpub bech32 string
///
/// # Returns
///
/// Parsed `PublicKey` or error describing why parsing failed
fn parse_pubkey(pubkey_str: &str) -> Result<PublicKey, String> {
    // Try hex format first (most common)
    if let Ok(pk) = PublicKey::from_hex(pubkey_str) {
        return Ok(pk);
    }

    // Try hpub format (bech32 with 'hpub' HRP)
    // Note: This uses the external ehash crate's hpub parsing
    // We'll need to add the dependency when integrating with Pool/JDC roles
    // For now, provide error message about hpub support
    if pubkey_str.starts_with("hpub1") {
        return Err(
            "hpub format support requires ehash crate integration (coming in Pool/JDC integration)"
                .to_string(),
        );
    }

    Err(format!(
        "Invalid pubkey format. Expected hex (64 chars) or hpub format, got: {}",
        pubkey_str
    ))
}

/// Verify BIP340 Schnorr signature for the "get_quotes:{pubkey_hex}" message
///
/// This follows the NUT-20 signature verification pattern using the secp256k1 library.
///
/// # Arguments
///
/// * `pubkey` - The public key that should have created the signature
/// * `signature_str` - Hex-encoded BIP340 signature
///
/// # Returns
///
/// Ok(()) if signature is valid, Err with description if invalid
fn verify_get_quotes_signature(pubkey: &PublicKey, signature_str: &str) -> Result<(), String> {
    // Parse signature from hex
    let signature =
        Signature::from_str(signature_str).map_err(|e| format!("Invalid signature format: {}", e))?;

    // Construct message: "get_quotes:{pubkey_hex}"
    let pubkey_hex = pubkey.to_hex();
    let message = format!("get_quotes:{}", pubkey_hex);
    let msg_bytes = message.as_bytes();

    // Verify signature using NUT-20 style verification
    pubkey
        .verify(msg_bytes, &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))?;

    Ok(())
}

#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    context_path = "/v1",
    path = "/mint/quotes/by-pubkey",
    request_body = QuotesByPubkeyRequest,
    responses(
        (status = 200, description = "Successful response", body = QuotesByPubkeyResponse, content_type = "application/json"),
        (status = 400, description = "Invalid pubkey format or signature format", body = ErrorResponse, content_type = "application/json"),
        (status = 401, description = "Signature verification failed", body = ErrorResponse, content_type = "application/json"),
        (status = 500, description = "Database query failed", body = ErrorResponse, content_type = "application/json")
    )
))]
/// Handler for POST /v1/mint/quotes/by-pubkey
///
/// Authenticated quote discovery endpoint that returns all PAID quotes
/// for a given public key after verifying signature authentication.
///
/// # Authentication Flow
///
/// 1. Parse pubkey from request (hex or hpub format)
/// 2. Verify signature proves pubkey ownership
/// 3. Query database for quotes matching pubkey
/// 4. Filter to PAID quotes only
/// 5. Return quote summaries
///
/// # Error Cases
///
/// - 400 Bad Request: Invalid pubkey format or signature format
/// - 401 Unauthorized: Signature verification failed
/// - 500 Internal Server Error: Database query failed
#[instrument(skip(state))]
pub async fn get_quotes_by_pubkey(
    State(state): State<MintState>,
    Json(request): Json<QuotesByPubkeyRequest>,
) -> Result<Json<QuotesByPubkeyResponse>, Response> {
    debug!(
        "Received quote discovery request for pubkey: {}",
        request.pubkey
    );

    // Parse pubkey (supports hex and hpub formats)
    let pubkey = parse_pubkey(&request.pubkey).map_err(|e| {
        warn!("Failed to parse pubkey: {}", e);
        (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(ErrorCode::Unknown(400), e))).into_response()
    })?;

    // Verify signature proves pubkey ownership
    verify_get_quotes_signature(&pubkey, &request.signature).map_err(|e| {
        warn!("Signature verification failed: {}", e);
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse::new(ErrorCode::TokenNotVerified, e))).into_response()
    })?;

    debug!("Signature verified for pubkey: {}", pubkey.to_hex());

    // Query mint for all quotes matching this pubkey
    let quotes = state
        .mint
        .get_mint_quotes_by_pubkey(&pubkey)
        .await
        .map_err(|e| {
            warn!("Database query failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new(ErrorCode::Unknown(500), e.to_string()))).into_response()
        })?;

    debug!("Found {} quotes for pubkey", quotes.len());

    // Filter to PAID quotes only and convert to summary format
    let paid_quotes: Vec<EHashQuoteSummary> = quotes
        .into_iter()
        .filter(|q| q.state() == MintQuoteState::Paid)
        .map(|q| EHashQuoteSummary {
            quote_id: q.id.to_string(),
            amount: q.amount_paid(),
            unit: q.unit.clone(),
            state: q.state(),
            expiry: q.expiry,
            created_time: q.created_time,
            request: q.request.clone(),
        })
        .collect();

    debug!("Returning {} PAID quotes", paid_quotes.len());

    Ok(Json(QuotesByPubkeyResponse {
        quotes: paid_quotes,
    }))
}

#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    context_path = "/v1",
    path = "/mint/ehash",
    request_body = PostMintEHashRequest,
    responses(
        (status = 200, description = "Successful response", body = PostMintEHashResponse, content_type = "application/json"),
        (status = 400, description = "Invalid quote ID or request format", body = ErrorResponse, content_type = "application/json"),
        (status = 401, description = "Signature verification failed or missing", body = ErrorResponse, content_type = "application/json"),
        (status = 404, description = "Quote doesn't exist", body = ErrorResponse, content_type = "application/json"),
        (status = 409, description = "Quote not in PAID state", body = ErrorResponse, content_type = "application/json"),
        (status = 500, description = "Minting operation failed", body = ErrorResponse, content_type = "application/json")
    )
))]
/// Handler for POST /v1/mint/ehash
///
/// eHash-specific minting endpoint that verifies NUT-20 signature matches
/// the quote's pubkey before processing mint request.
///
/// # Minting Flow
///
/// 1. Parse and validate quote ID
/// 2. Fetch quote from database
/// 3. Verify quote is in PAID state
/// 4. Verify NUT-20 signature matches quote's pubkey
/// 5. Process minting using standard CDK flow
/// 6. Return blind signatures
///
/// # Error Cases
///
/// - 400 Bad Request: Invalid quote ID or request format
/// - 401 Unauthorized: Signature verification failed or missing
/// - 404 Not Found: Quote doesn't exist
/// - 409 Conflict: Quote not in PAID state
/// - 500 Internal Server Error: Minting operation failed
#[instrument(skip(state))]
pub async fn mint_ehash_tokens(
    State(state): State<MintState>,
    Json(request): Json<PostMintEHashRequest>,
) -> Result<Json<PostMintEHashResponse>, Response> {
    debug!("Received eHash mint request for quote: {}", request.quote);

    // Parse quote ID
    let quote_id = QuoteId::from_str(&request.quote).map_err(|e| {
        warn!("Invalid quote ID format: {}", e);
        (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(ErrorCode::Unknown(400), format!("Invalid quote ID: {}", e)))).into_response()
    })?;

    // Fetch quote from database directly (we need the internal MintQuote, not MintQuoteResponse)
    let quote = state
        .mint
        .localstore()
        .get_mint_quote(&quote_id)
        .await
        .map_err(|e| {
            warn!("Failed to fetch quote: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new(ErrorCode::Unknown(500), e.to_string()))).into_response()
        })?
        .ok_or_else(|| {
            warn!("Quote {} not found", quote_id);
            (StatusCode::NOT_FOUND, Json(ErrorResponse::new(ErrorCode::Unknown(404), "Quote not found".to_string()))).into_response()
        })?;

    // Verify quote is in PAID state
    if quote.state() != MintQuoteState::Paid {
        warn!(
            "Quote {} is not in PAID state: {:?}",
            quote_id,
            quote.state()
        );
        return Err((StatusCode::CONFLICT, Json(ErrorResponse::new(
            ErrorCode::QuoteNotPaid,
            format!("Quote is in {:?} state, expected PAID", quote.state()),
        ))).into_response());
    }

    // Get pubkey from quote (required for eHash quotes)
    let quote_pubkey = quote.pubkey.ok_or_else(|| {
        warn!("Quote {} missing pubkey field", quote_id);
        (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(
            ErrorCode::Unknown(400),
            "Quote does not have an associated pubkey".to_string(),
        ))).into_response()
    })?;

    debug!("Quote pubkey: {}", quote_pubkey.to_hex());

    // Construct MintRequest for signature verification
    let mint_request = MintRequest {
        quote: quote_id.clone(),
        outputs: request.outputs.clone(),
        signature: Some(request.signature.clone()),
    };

    // Verify NUT-20 signature matches quote's pubkey
    mint_request.verify_signature(quote_pubkey).map_err(|e| {
        warn!("NUT-20 signature verification failed: {}", e);
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse::new(
            ErrorCode::TokenNotVerified,
            format!("Signature verification failed: {}", e),
        ))).into_response()
    })?;

    debug!("NUT-20 signature verified for quote {}", quote_id);

    // Process minting using standard CDK flow
    let blind_signatures = state
        .mint
        .process_mint_request(mint_request)
        .await
        .map_err(|e| {
            warn!("Mint processing failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new(ErrorCode::Unknown(500), format!("Minting failed: {}", e)))).into_response()
        })?;

    debug!(
        "Successfully minted {} signatures for quote {}",
        blind_signatures.signatures.len(),
        quote_id
    );

    Ok(Json(PostMintEHashResponse {
        signatures: blind_signatures.signatures,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pubkey_hex() {
        let hex_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let result = parse_pubkey(hex_pubkey);
        assert!(result.is_ok(), "Should parse valid hex pubkey");

        let parsed = result.unwrap();
        assert_eq!(
            parsed.to_hex(),
            hex_pubkey,
            "Parsed pubkey should match input"
        );
    }

    #[test]
    fn test_parse_pubkey_invalid_hex() {
        let invalid_hex = "not_a_valid_hex_pubkey";
        let result = parse_pubkey(invalid_hex);
        assert!(result.is_err(), "Should fail on invalid hex");
    }

    #[test]
    fn test_parse_pubkey_hpub_not_yet_supported() {
        let hpub = "hpub1qw508d6qejxtdg4y5r3zarvary0c5xw7k";
        let result = parse_pubkey(hpub);
        // Currently returns error until ehash integration
        assert!(
            result.is_err(),
            "hpub support pending ehash crate integration"
        );
    }

    #[test]
    fn test_verify_get_quotes_signature_message_format() {
        use cdk::nuts::SecretKey;

        // Create test keypair
        let secret_key =
            SecretKey::from_hex("50d7fd7aa2b2fe4607f41f4ce6f8794fc184dd47b8cdfbe4b3d1249aa02d35aa")
                .unwrap();
        let pubkey = secret_key.public_key();

        // Construct message and sign it
        let message = format!("get_quotes:{}", pubkey.to_hex());
        let signature = secret_key.sign(message.as_bytes()).unwrap();

        // Verify signature
        let result = verify_get_quotes_signature(&pubkey, &signature.to_string());
        assert!(result.is_ok(), "Valid signature should verify");
    }

    #[test]
    fn test_verify_get_quotes_signature_invalid() {
        use cdk::nuts::SecretKey;

        let secret_key =
            SecretKey::from_hex("50d7fd7aa2b2fe4607f41f4ce6f8794fc184dd47b8cdfbe4b3d1249aa02d35aa")
                .unwrap();
        let pubkey = secret_key.public_key();

        // Sign wrong message
        let wrong_message = "wrong_message";
        let signature = secret_key.sign(wrong_message.as_bytes()).unwrap();

        // Should fail verification
        let result = verify_get_quotes_signature(&pubkey, &signature.to_string());
        assert!(result.is_err(), "Invalid signature should fail verification");
    }

    #[test]
    fn test_quotes_by_pubkey_request_serialization() {
        let request = QuotesByPubkeyRequest {
            pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            signature: "abc123".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: QuotesByPubkeyRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.pubkey, deserialized.pubkey);
        assert_eq!(request.signature, deserialized.signature);
    }

    #[test]
    fn test_ehash_quote_summary_serialization() {
        let summary = EHashQuoteSummary {
            quote_id: "test-quote-id".to_string(),
            amount: Amount::from(1000),
            unit: CurrencyUnit::Sat,
            state: MintQuoteState::Paid,
            expiry: 1234567890,
            created_time: 1234567800,
            request: "test-request".to_string(),
        };

        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: EHashQuoteSummary = serde_json::from_str(&json).unwrap();

        assert_eq!(summary.quote_id, deserialized.quote_id);
        assert_eq!(summary.amount, deserialized.amount);
    }
}
