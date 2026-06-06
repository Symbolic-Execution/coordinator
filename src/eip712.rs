use crate::error::CoordinatorError;
use crate::types::{
    Address, DisclosureRequest, Eip712Domain, EthereumSignature, ReaderId, RegisterReader,
};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

const EIP712_DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,bytes32 salt)";
const REGISTER_READER_TYPE: &str =
    "RegisterReader(address controller,bytes32 reader_id,bytes32 nonce,uint64 expiry)";
const DISCLOSURE_REQUEST_TYPE: &str = "DisclosureRequest(address contract,bytes32 handle_id,bytes32 reader_id,bytes32 nonce,uint64 expiry)";

pub fn verify_register_reader_signature(
    domain: &Eip712Domain,
    message: &RegisterReader,
    signature: EthereumSignature,
) -> Result<(), CoordinatorError> {
    let digest = typed_data_digest(domain, &hash_register_reader(message));
    verify_signature(digest, signature, message.controller)
}

pub fn verify_disclosure_signature(
    domain: &Eip712Domain,
    controller: Address,
    message: &DisclosureRequest,
    signature: EthereumSignature,
) -> Result<(), CoordinatorError> {
    let digest = typed_data_digest(domain, &hash_disclosure_request(message));
    verify_signature(digest, signature, controller)
}

pub fn reader_id(reader_pubkey: crate::types::X25519PublicKey) -> ReaderId {
    let hash = keccak256(&reader_pubkey.0);
    ReaderId(hash)
}

fn verify_signature(
    digest: [u8; 32],
    ethereum_signature: EthereumSignature,
    expected_signer: Address,
) -> Result<(), CoordinatorError> {
    let signature = Signature::try_from(&ethereum_signature.0[..64]).map_err(|error| {
        CoordinatorError::Unauthorized(format!("invalid signature bytes: {error}"))
    })?;
    let recovery_id = normalize_recovery_id(signature_byte(signature_recovery_byte(
        &ethereum_signature.0,
    )))?;
    let verifying_key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .map_err(|error| {
            CoordinatorError::Unauthorized(format!("signature recovery failed: {error}"))
        })?;
    let recovered = ethereum_address(&verifying_key);

    if recovered != expected_signer {
        return Err(CoordinatorError::Unauthorized(
            "signature does not match expected controller".to_string(),
        ));
    }

    Ok(())
}

fn signature_recovery_byte(bytes: &[u8; 65]) -> u8 {
    bytes[64]
}

fn signature_byte(v: u8) -> u8 {
    match v {
        27 | 28 => v - 27,
        _ => v,
    }
}

fn normalize_recovery_id(value: u8) -> Result<RecoveryId, CoordinatorError> {
    RecoveryId::try_from(value)
        .map_err(|_| CoordinatorError::Unauthorized("unsupported Ethereum recovery id".to_string()))
}

fn typed_data_digest(domain: &Eip712Domain, struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(66);
    bytes.extend_from_slice(b"\x19\x01");
    bytes.extend_from_slice(&hash_eip712_domain(domain));
    bytes.extend_from_slice(struct_hash);
    keccak256(&bytes)
}

fn hash_eip712_domain(domain: &Eip712Domain) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(32 * 5);
    encoded.extend_from_slice(&keccak256(EIP712_DOMAIN_TYPE.as_bytes()));
    encoded.extend_from_slice(&keccak256(domain.name.as_bytes()));
    encoded.extend_from_slice(&keccak256(domain.version.as_bytes()));
    encoded.extend_from_slice(&encode_u64_word(domain.chain_id));
    encoded.extend_from_slice(&domain.salt.0);
    keccak256(&encoded)
}

fn hash_register_reader(message: &RegisterReader) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(32 * 5);
    encoded.extend_from_slice(&keccak256(REGISTER_READER_TYPE.as_bytes()));
    encoded.extend_from_slice(&encode_address_word(message.controller));
    encoded.extend_from_slice(&message.reader_id.0);
    encoded.extend_from_slice(&message.nonce.0);
    encoded.extend_from_slice(&encode_u64_word(message.expiry));
    keccak256(&encoded)
}

fn hash_disclosure_request(message: &DisclosureRequest) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(32 * 6);
    encoded.extend_from_slice(&keccak256(DISCLOSURE_REQUEST_TYPE.as_bytes()));
    encoded.extend_from_slice(&encode_address_word(message.contract));
    encoded.extend_from_slice(&message.handle_id.0);
    encoded.extend_from_slice(&message.reader_id.0);
    encoded.extend_from_slice(&message.nonce.0);
    encoded.extend_from_slice(&encode_u64_word(message.expiry));
    keccak256(&encoded)
}

fn encode_address_word(address: Address) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(&address.0);
    word
}

fn encode_u64_word(value: u64) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn ethereum_address(key: &VerifyingKey) -> Address {
    let encoded = key.to_encoded_point(false);
    let hash = keccak256(&encoded.as_bytes()[1..]);
    let mut address = [0_u8; 20];
    address.copy_from_slice(&hash[12..]);
    Address(address)
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let hash = Keccak256::digest(bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&hash);
    out
}

pub mod test_helpers {
    use super::*;
    use crate::types::{Bytes32, DisclosureRequest};
    use k256::ecdsa::SigningKey;

    pub fn test_domain(chain_id: u64) -> Eip712Domain {
        Eip712Domain {
            name: "Coordinator".to_string(),
            version: "1".to_string(),
            chain_id,
            salt: Bytes32([0x99; 32]),
        }
    }

    pub fn signing_key_for_tests(seed: [u8; 32]) -> SigningKey {
        SigningKey::from_bytes((&seed).into()).unwrap()
    }

    pub fn address_for_signing_key(signing_key: &SigningKey) -> Address {
        ethereum_address(signing_key.verifying_key())
    }

    pub fn sign_register_reader(
        signing_key: &SigningKey,
        domain: &Eip712Domain,
        message: &RegisterReader,
    ) -> EthereumSignature {
        sign_digest(
            signing_key,
            typed_data_digest(domain, &hash_register_reader(message)),
        )
    }

    pub fn sign_disclosure(
        signing_key: &SigningKey,
        domain: &Eip712Domain,
        message: &DisclosureRequest,
    ) -> EthereumSignature {
        sign_digest(
            signing_key,
            typed_data_digest(domain, &hash_disclosure_request(message)),
        )
    }

    fn sign_digest(signing_key: &SigningKey, digest: [u8; 32]) -> EthereumSignature {
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
        let mut bytes = [0_u8; 65];
        bytes[..64].copy_from_slice(&signature.to_bytes());
        bytes[64] = recovery_id.to_byte();
        EthereumSignature(bytes)
    }

    #[test]
    fn round_trips_register_reader_signature() {
        let signing_key = signing_key_for_tests([7; 32]);
        let controller = address_for_signing_key(&signing_key);
        let domain = test_domain(31337);
        let message = RegisterReader {
            controller,
            reader_id: ReaderId([1; 32]),
            nonce: crate::types::Nonce([2; 32]),
            expiry: 100,
        };

        let signature = sign_register_reader(&signing_key, &domain, &message);
        verify_register_reader_signature(&domain, &message, signature).unwrap();
    }

    #[test]
    fn round_trips_disclosure_signature() {
        let signing_key = signing_key_for_tests([8; 32]);
        let controller = address_for_signing_key(&signing_key);
        let domain = test_domain(31337);
        let message = DisclosureRequest {
            contract: Address([3; 20]),
            handle_id: crate::types::HandleId([4; 32]),
            reader_id: ReaderId([5; 32]),
            nonce: crate::types::Nonce([6; 32]),
            expiry: 100,
        };

        let signature = sign_disclosure(&signing_key, &domain, &message);
        verify_disclosure_signature(&domain, controller, &message, signature).unwrap();
    }
}
