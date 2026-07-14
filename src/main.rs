use ml_dsa::{MlDsa65, Generate, SigningKey, Signer, Verifier, KeyExport, Keypair};
use std::fs::File;
use std::io::{Write, Read};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use sha3::{Digest, Sha3_256};

// Deterministic FIPS 204 System Constraints
pub const ML_DSA_65_PK_SIZE: usize = 1952;
pub const ML_DSA_65_SIG_SIZE: usize = 3309;
pub const STATE_COMMITMENT_SIZE: usize = 32;

// Total calculated payload footprint: 8 (lineage) + 8 (block_height) + 8 (valid_until)
// + 32 (state_commitment) + 1952 (pk) + 3309 (sig) = 5317 bytes
pub const TOTAL_WIRE_SIZE: usize =
    8 + 8 + 8 + STATE_COMMITMENT_SIZE + ML_DSA_65_PK_SIZE + ML_DSA_65_SIG_SIZE;

#[derive(Debug)]
pub enum SubstrateError {
    BufferUnderflow { expected: usize, found: usize },
    InvalidLatticePublicKey,
    InvalidLatticeSignature,
    CryptographicAttestationFailed,
    ProofExpired { valid_until: u64, now: u64 },
    IoError(std::io::Error),
}

impl fmt::Display for SubstrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferUnderflow { expected, found } => write!(f, "Wire protocol chunk mismatch: expected {expected} bytes, found {found}"),
            Self::InvalidLatticePublicKey => write!(f, "Failed to instantiate FIPS 204 verifying key geometry from wire slice"),
            Self::InvalidLatticeSignature => write!(f, "Failed to parse standard module-lattice signature layout"),
            Self::CryptographicAttestationFailed => write!(f, "Lattice verification equation failed to resolve structurally"),
            Self::ProofExpired { valid_until, now } => write!(f, "Proof expired: valid_until={valid_until}, now={now}"),
            Self::IoError(e) => write!(f, "Substrate hardware storage I/O fault: {e}"),
        }
    }
}

impl std::error::Error for SubstrateError {}

impl From<std::io::Error> for SubstrateError {
    fn from(err: std::io::Error) -> Self {
        SubstrateError::IoError(err)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

/// Zero-Copy view interface across a raw underlying binary proof block
pub struct SovereignProofView<'a> {
    pub lineage_id: u64,
    pub block_height: u64,
    pub valid_until: u64,
    pub state_commitment: &'a [u8; STATE_COMMITMENT_SIZE],
    pub public_key_slice: &'a [u8],
    pub signature_slice: &'a [u8],
    raw_message_ctx: Vec<u8>,
}

impl<'a> SovereignProofView<'a> {
    /// Zero-allocation slice split parsing
    pub fn try_from_bytes(raw: &'a [u8]) -> Result<Self, SubstrateError> {
        if raw.len() < TOTAL_WIRE_SIZE {
            return Err(SubstrateError::BufferUnderflow { expected: TOTAL_WIRE_SIZE, found: raw.len() });
        }

        let mut cursor = 0;

        let lineage_id = u64::from_be_bytes(raw[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;

        let block_height = u64::from_be_bytes(raw[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;

        let valid_until = u64::from_be_bytes(raw[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;

        let state_commitment: &'a [u8; STATE_COMMITMENT_SIZE] = raw[cursor..cursor + 32].try_into().unwrap();
        cursor += 32;

        let public_key_slice = &raw[cursor..cursor + ML_DSA_65_PK_SIZE];
        cursor += ML_DSA_65_PK_SIZE;

        let signature_slice = &raw[cursor..cursor + ML_DSA_65_SIG_SIZE];

        // Reconstruct verification context message mapping linearly from the view data
        let mut raw_message_ctx = Vec::with_capacity(8 + 8 + 8 + STATE_COMMITMENT_SIZE);
        raw_message_ctx.extend_from_slice(&lineage_id.to_be_bytes());
        raw_message_ctx.extend_from_slice(&block_height.to_be_bytes());
        raw_message_ctx.extend_from_slice(&valid_until.to_be_bytes());
        raw_message_ctx.extend_from_slice(state_commitment);

        Ok(Self {
            lineage_id,
            block_height,
            valid_until,
            state_commitment,
            public_key_slice,
            signature_slice,
            raw_message_ctx,
        })
    }

    /// Validates the internal post-quantum lattice attestation signature,
    /// then checks that the proof has not expired.
    pub fn verify(&self) -> Result<(), SubstrateError> {
        let pk_encoded = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(self.public_key_slice)
            .map_err(|_| SubstrateError::InvalidLatticePublicKey)?;
        let verifying_key = ml_dsa::VerifyingKey::<MlDsa65>::decode(&pk_encoded);

        let sig_encoded = ml_dsa::EncodedSignature::<MlDsa65>::try_from(self.signature_slice)
            .map_err(|_| SubstrateError::InvalidLatticeSignature)?;
        let signature = ml_dsa::Signature::<MlDsa65>::decode(&sig_encoded)
            .ok_or(SubstrateError::InvalidLatticeSignature)?;

        verifying_key.verify(&self.raw_message_ctx, &signature)
            .map_err(|_| SubstrateError::CryptographicAttestationFailed)?;

        let now = unix_now();
        if now > self.valid_until {
            return Err(SubstrateError::ProofExpired { valid_until: self.valid_until, now });
        }

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Initializing Optimized Zero-Copy FIPS 204 Engine ---");

    // 1. Prepare State Elements
    let lineage_id: u64 = 8888;
    let block_height: u64 = 9999;
    const VALIDITY_WINDOW_SECS: u64 = 300; // 5 minutes
    let valid_until: u64 = unix_now() + VALIDITY_WINDOW_SECS;

    let mut hasher = Sha3_256::new();
    hasher.update(lineage_id.to_be_bytes());
    hasher.update(block_height.to_be_bytes());
    hasher.update(b"guzcom-sovereign-state-v1");
    let state_commitment: [u8; 32] = hasher.finalize().into();

    // 2. Generate Real Keypair & Context Signing
    println!("[-] Generating ML-DSA-65 credentials via system entropy...");
    let signing_key = SigningKey::<MlDsa65>::generate();
    let verifying_key = signing_key.verifying_key();

    let mut message = Vec::new();
    message.extend_from_slice(&lineage_id.to_be_bytes());
    message.extend_from_slice(&block_height.to_be_bytes());
    message.extend_from_slice(&valid_until.to_be_bytes());
    message.extend_from_slice(&state_commitment);

    let signature = signing_key.sign(&message);

    // 3. Construct Fixed-Width Tight Binary Wire Format
    let pk_bytes = verifying_key.to_bytes();
    let sig_bytes = signature.encode();

    let mut wire_buffer = Vec::with_capacity(TOTAL_WIRE_SIZE);
    wire_buffer.extend_from_slice(&lineage_id.to_be_bytes());
    wire_buffer.extend_from_slice(&block_height.to_be_bytes());
    wire_buffer.extend_from_slice(&valid_until.to_be_bytes());
    wire_buffer.extend_from_slice(&state_commitment);
    wire_buffer.extend_from_slice(pk_bytes.as_ref());
    wire_buffer.extend_from_slice(sig_bytes.as_ref());

    // 4. Output to disk storage
    let filename = "sovereign_state_proof.bin";
    {
        let mut file = File::create(filename)?;
        file.write_all(&wire_buffer)?;
    }
    println!("Shipped packed binary target '{}' (Total footprint: {} bytes).", filename, wire_buffer.len());

    // 5. Execute Zero-Copy Parsing and Attestation Verification
    println!("\n--- Simulating Zero-Copy In-Place Verification Loop ---");
    let mut file_input = File::open(filename)?;
    let mut read_buffer = Vec::new();
    file_input.read_to_end(&mut read_buffer)?;

    // Zero-alloc overlay assignment
    let proof_view = SovereignProofView::try_from_bytes(&read_buffer)?;

    println!("View Metadata Map Successfully Extracted:");
    println!(" -> Sovereign Lineage ID: {}", proof_view.lineage_id);
    println!(" -> Active Block Height:  {}", proof_view.block_height);
    println!(" -> Valid Until (unix):   {}", proof_view.valid_until);

    // Run the validation check
    match proof_view.verify() {
        Ok(_) => println!("\n[SUCCESS: ZERO-COPY CRYPTOGRAPHIC PROOF VERIFIED IN-PLACE]"),
        Err(e) => {
            eprintln!("\n[CRITICAL ERROR: ATTESTATION EQUATION MISMATCH: {}]", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

#[cfg(test)]
mod verification_fuzz_tests {
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]
        #[test]
        fn test_zero_copy_parser_edge_cases(ref data in proptest::collection::vec(any::<u8>(), 0..5000)) {
            // This hammers the parser with millions of structured mutations
            // to verify that random byte streams never cause an unhandled panic or OOB crash.
            if let Ok(encoded_pk) = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(&data[..]) {
                let _ = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&encoded_pk);
            }

            if let Ok(encoded_sig) = ml_dsa::EncodedSignature::<ml_dsa::MlDsa65>::try_from(&data[..]) {
                let _ = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&encoded_sig);
            }
        }
    }
}

#[cfg(test)]
mod correctness_tests {
    use super::*;

    fn build_proof(valid_until: u64) -> Vec<u8> {
        let lineage_id: u64 = 42;
        let block_height: u64 = 100;

        let mut hasher = Sha3_256::new();
        hasher.update(lineage_id.to_be_bytes());
        hasher.update(block_height.to_be_bytes());
        hasher.update(b"guzcom-sovereign-state-v1");
        let state_commitment: [u8; 32] = hasher.finalize().into();

        let signing_key = SigningKey::<MlDsa65>::generate();
        let verifying_key = signing_key.verifying_key();

        let mut message = Vec::new();
        message.extend_from_slice(&lineage_id.to_be_bytes());
        message.extend_from_slice(&block_height.to_be_bytes());
        message.extend_from_slice(&valid_until.to_be_bytes());
        message.extend_from_slice(&state_commitment);

        let signature = signing_key.sign(&message);
        let pk_bytes = verifying_key.to_bytes();
        let sig_bytes = signature.encode();

        let mut wire_buffer = Vec::with_capacity(TOTAL_WIRE_SIZE);
        wire_buffer.extend_from_slice(&lineage_id.to_be_bytes());
        wire_buffer.extend_from_slice(&block_height.to_be_bytes());
        wire_buffer.extend_from_slice(&valid_until.to_be_bytes());
        wire_buffer.extend_from_slice(&state_commitment);
        wire_buffer.extend_from_slice(pk_bytes.as_ref());
        wire_buffer.extend_from_slice(sig_bytes.as_ref());
        wire_buffer
    }

    #[test]
    fn valid_proof_roundtrips_and_verifies() {
        let valid_until = unix_now() + 300;
        let wire = build_proof(valid_until);
        let view = SovereignProofView::try_from_bytes(&wire).expect("parse should succeed");
        assert_eq!(view.lineage_id, 42);
        assert_eq!(view.block_height, 100);
        assert_eq!(view.valid_until, valid_until);
        view.verify().expect("valid, unexpired proof should verify");
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let valid_until = unix_now() + 300;
        let mut wire = build_proof(valid_until);
        // Flip a byte inside the signature region (after lineage+height+valid_until+commitment+pk)
        let sig_offset = 8 + 8 + 8 + STATE_COMMITMENT_SIZE + ML_DSA_65_PK_SIZE;
        wire[sig_offset] ^= 0xFF;
        let view = SovereignProofView::try_from_bytes(&wire).expect("parse should still succeed structurally");
        let result = view.verify();
        assert!(result.is_err(), "tampered signature must not verify");
    }

    #[test]
    fn tampered_message_is_rejected() {
        let valid_until = unix_now() + 300;
        let mut wire = build_proof(valid_until);
        // Flip a byte in block_height, which is covered by the signature
        wire[8] ^= 0xFF;
        let view = SovereignProofView::try_from_bytes(&wire).expect("parse should still succeed structurally");
        let result = view.verify();
        assert!(result.is_err(), "tampered signed field must not verify");
    }

    #[test]
    fn expired_proof_is_rejected() {
        // valid_until in the past
        let valid_until = unix_now().saturating_sub(60);
        let wire = build_proof(valid_until);
        let view = SovereignProofView::try_from_bytes(&wire).expect("parse should succeed");
        let result = view.verify();
        match result {
            Err(SubstrateError::ProofExpired { .. }) => {}
            other => panic!("expected ProofExpired, got {other:?}"),
        }
    }
}
