use p256::{
    EncodedPoint,
    ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer},
};
use ecdsa_methods::{ECDSA_VERIFY_ELF, ECDSA_VERIFY_ID};
use rand_core::OsRng;
use risc0_zkvm::{ExecutorEnv, Receipt, default_prover};
use log::{info, debug};

/// Given an secp256r1 verifier key (i.e. public key), message and signature,
/// runs the ECDSA verifier inside the zkVM and returns a receipt, including a
/// journal and seal attesting to the fact that the prover knows a valid
/// signature from the committed public key over the committed message.
fn prove_ecdsa_verification(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Receipt {
    let input = (verifying_key.to_encoded_point(true), message, signature);
    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    prover.prove(env, ECDSA_VERIFY_ELF).unwrap().receipt
}

fn main() {
    // Initialize the logger
    env_logger::init();

    info!("Starting P256 ECDSA signature verification in zkVM");

    // Generate a random secp256r1 keypair and sign the message.
    debug!("Generating random secp256r1 keypair");
    let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
    let verifying_key = signing_key.verifying_key();
    info!("Generated keypair with public key: {}", verifying_key.to_encoded_point(true));

    let message = b"This is a message that will be signed, and verified within the zkVM";
    debug!("Message to sign: {:?}", std::str::from_utf8(message).unwrap());

    debug!("Signing message with private key");
    let signature: Signature = signing_key.sign(message);
    debug!("Generated signature: {:?}", signature);

    // Run signature verified in the zkVM guest and get the resulting receipt.
    info!("Running ECDSA verification in zkVM guest");
    let receipt = prove_ecdsa_verification(verifying_key, message, &signature);
    info!("zkVM execution completed, receipt generated");

    // Verify the receipt and then access the journal.
    debug!("Verifying receipt with method ID");
    receipt.verify(ECDSA_VERIFY_ID).unwrap();
    info!("Receipt verification successful");

    debug!("Decoding journal from receipt");
    let (receipt_verifying_key, receipt_message): (EncodedPoint, Vec<u8>) =
        receipt.journal.decode().unwrap();
    debug!("Journal decoded successfully");

    info!("SUCCESS: Verified the signature over message {:?} with key {}",
        std::str::from_utf8(&receipt_message[..]).unwrap(),
        receipt_verifying_key,
    );

    info!("P256 ECDSA verification in zkVM completed successfully");
}
