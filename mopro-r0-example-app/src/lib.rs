// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This application demonstrates how to send an off-chain proof request
// to the Bonsai proving service and publish the received proofs directly
// to your deployed app contract.

// Allow unexpected cfg for the full file
#![allow(unexpected_cfgs)]

use ecdsa_methods::{ECDSA_VERIFY_ELF, ECDSA_VERIFY_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use p256::{
    EncodedPoint,
    ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer},
};
use rand_core::OsRng;

mopro_ffi::app!();

#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum Risc0Error {
    #[error("Failed to prove: {0}")]
    ProveError(String),
    #[error("Failed to serialize receipt: {0}")]
    SerializeError(String),
    #[error("Failed to verify: {0}")]
    VerifyError(String),
    #[error("Failed to decode journal: {0}")]
    DecodeError(String),
}

#[derive(uniffi::Record, Clone)]
pub struct Risc0ProofOutput {
    pub receipt: Vec<u8>,
}

#[derive(uniffi::Record, Clone)]
pub struct Risc0VerifyOutput {
    pub is_valid: bool,
    pub verified_message: String,
}

#[uniffi::export]
pub fn risc0_prove(message: String) -> Result<Risc0ProofOutput, Risc0Error> {
    // Generate a random secp256r1 keypair and sign the message
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let message_bytes = message.as_bytes();
    let signature: Signature = signing_key.sign(message_bytes);

    // Create input for zkVM (public key, message, signature)
    let input = (verifying_key.to_encoded_point(true), message_bytes, signature);

    // Create executor environment with ECDSA input
    let env = ExecutorEnv::builder()
        .write(&input)
        .map_err(|e| Risc0Error::ProveError(format!("Failed to write input: {}", e)))?
        .build()
        .map_err(|e| {
            Risc0Error::ProveError(format!("Failed to build executor environment: {}", e))
        })?;

    // Get the default prover
    let prover = default_prover();

    // Generate proof
    let prove_info = prover
        .prove(env, ECDSA_VERIFY_ELF)
        .map_err(|e| Risc0Error::ProveError(format!("Failed to generate proof: {}", e)))?;

    // Extract receipt
    let receipt = prove_info.receipt;

    // Serialize receipt to bytes
    let receipt_bytes = bincode::serialize(&receipt)
        .map_err(|e| Risc0Error::SerializeError(format!("Failed to serialize receipt: {}", e)))?;

    Ok(Risc0ProofOutput {
        receipt: receipt_bytes,
    })
}

#[uniffi::export]
pub fn risc0_verify(receipt_bytes: Vec<u8>) -> Result<Risc0VerifyOutput, Risc0Error> {
    // Deserialize receipt from bytes
    let receipt: Receipt = bincode::deserialize(&receipt_bytes)
        .map_err(|e| Risc0Error::SerializeError(format!("Failed to deserialize receipt: {}", e)))?;

    // Verify the receipt
    receipt
        .verify(ECDSA_VERIFY_ID)
        .map_err(|e| Risc0Error::VerifyError(format!("Failed to verify receipt: {}", e)))?;

    // Extract output from journal (verifying key and message)
    let (receipt_verifying_key, receipt_message): (EncodedPoint, Vec<u8>) = receipt
        .journal
        .decode()
        .map_err(|e| Risc0Error::DecodeError(format!("Failed to decode journal: {}", e)))?;

    let verified_message = String::from_utf8(receipt_message)
        .map_err(|e| Risc0Error::DecodeError(format!("Failed to convert message to string: {}", e)))?;

    Ok(Risc0VerifyOutput {
        is_valid: true,
        verified_message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risc0_prove_success() {
        // Test proving with a simple message
        let message = "Hello, ECDSA!".to_string();
        let result = risc0_prove(message);

        assert!(result.is_ok(), "Proving should succeed for valid message");

        let proof_output = result.unwrap();
        assert!(
            !proof_output.receipt.is_empty(),
            "Receipt should not be empty"
        );
    }

    #[test]
    fn test_risc0_verify_success() {
        // First generate a proof
        let message = "Test message for verification".to_string();
        let prove_result = risc0_prove(message.clone());
        assert!(prove_result.is_ok(), "Proving should succeed");

        let proof_output = prove_result.unwrap();

        // Now verify the proof
        let verify_result = risc0_verify(proof_output.receipt);
        assert!(
            verify_result.is_ok(),
            "Verification should succeed for valid proof"
        );

        let verify_output = verify_result.unwrap();
        assert!(verify_output.is_valid, "Proof should be valid");
        assert_eq!(
            verify_output.verified_message, message,
            "Verified message should match original message"
        );
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        // Test the complete prove -> verify workflow with multiple messages
        let test_messages = [
            "Simple message",
            "Message with numbers: 12345",
            "Special chars: !@#$%^&*()",
            "Unicode: 你好世界",
            ""
        ];

        for &message in &test_messages {
            let message_str = message.to_string();

            // Generate proof
            let prove_result = risc0_prove(message_str.clone());
            assert!(
                prove_result.is_ok(),
                "Proving should succeed for message: '{}'",
                message
            );

            let proof_output = prove_result.unwrap();

            // Verify proof
            let verify_result = risc0_verify(proof_output.receipt);
            assert!(
                verify_result.is_ok(),
                "Verification should succeed for message: '{}'",
                message
            );

            let verify_output = verify_result.unwrap();
            assert!(
                verify_output.is_valid,
                "Proof should be valid for message: '{}'",
                message
            );
            assert_eq!(
                verify_output.verified_message, message_str,
                "Verified message should match original for: '{}'",
                message
            );
        }
    }
}
