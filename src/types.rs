use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; 20]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Bytes32(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReaderId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HandleId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nonce(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DomainId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct X25519PublicKey(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EthereumSignature(pub [u8; 65]);

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReaderKeyAlgorithm {
    X25519,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CiphertextSuite {
    HpkeX25519HkdfSha256Aes256Gcm,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Pending,
    Ready,
    Failed,
    Expired,
}

pub type UnixSeconds = u64;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Eip712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub salt: Bytes32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoordinatorConfigResponse {
    pub version: u16,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub mpc_key_id: KeyId,
    pub mpc_hpke_public_key: X25519PublicKey,
    pub reader_key_algorithm: ReaderKeyAlgorithm,
    pub ciphertext_suite: CiphertextSuite,
    pub eip712_domain: Eip712Domain,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PutReaderRequest {
    pub controller: Address,
    pub reader_pubkey: X25519PublicKey,
    pub nonce: Nonce,
    pub expiry: UnixSeconds,
    pub signature: EthereumSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PutReaderResponse {
    pub reader_id: ReaderId,
    pub controller: Address,
    pub registered_at: UnixSeconds,
    pub expires_at: Option<UnixSeconds>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterReader {
    pub controller: Address,
    pub reader_id: ReaderId,
    pub nonce: Nonce,
    pub expiry: UnixSeconds,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostDisclosureRequest {
    pub contract: Address,
    pub handle_id: HandleId,
    pub reader_id: ReaderId,
    pub nonce: Nonce,
    pub expiry: UnixSeconds,
    pub signature: EthereumSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisclosureRequest {
    pub contract: Address,
    pub handle_id: HandleId,
    pub reader_id: ReaderId,
    pub nonce: Nonce,
    pub expiry: UnixSeconds,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PostDisclosureResponse {
    Ready {
        request_id: RequestId,
        ciphertext: ReaderCiphertextV1,
    },
    Pending {
        request_id: RequestId,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GetDisclosureResponse {
    Pending {
        request_id: RequestId,
    },
    Ready {
        request_id: RequestId,
        ciphertext: ReaderCiphertextV1,
    },
    Failed {
        request_id: RequestId,
        error: String,
    },
    Expired {
        request_id: RequestId,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadBytes(pub Vec<u8>);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MpcConfigResponse {
    pub version: u16,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub key_id: KeyId,
    pub hpke_public_key: X25519PublicKey,
    pub reader_key_algorithm: ReaderKeyAlgorithm,
    pub ciphertext_suite: CiphertextSuite,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MpcPutReaderRequest {
    pub reader_pubkey: X25519PublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MpcPutReaderResponse {
    pub reader_id: ReaderId,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemCiphertextV1 {
    pub key_id: KeyId,
    pub enc: PayloadBytes,
    pub wrapped_key: PayloadBytes,
    pub nonce: FixedBytes<12>,
    pub ciphertext: PayloadBytes,
    pub aad: PayloadBytes,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReaderCiphertextV1 {
    pub key_id: KeyId,
    pub enc: PayloadBytes,
    pub ciphertext: PayloadBytes,
    pub aad: PayloadBytes,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToReaderRequest {
    pub request_id: RequestId,
    pub chain_id: u64,
    pub handle_id: HandleId,
    pub reader_id: ReaderId,
    pub system_ciphertext: SystemCiphertextV1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToReaderResponse {
    pub ciphertext: ReaderCiphertextV1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolveHandleRequest {
    pub request_id: RequestId,
    pub chain_id: u64,
    pub contract: Address,
    pub handle_id: HandleId,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ResolveHandleResponse {
    Pending,
    Ready {
        system_ciphertext: SystemCiphertextV1,
        receipt: PayloadBytes,
    },
    Failed {
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GetHandleResponse {
    Pending {
        handle_id: HandleId,
    },
    Ready {
        handle_id: HandleId,
        system_ciphertext: SystemCiphertextV1,
        receipt: PayloadBytes,
    },
    Failed {
        handle_id: HandleId,
        error: String,
    },
}

fn serialize_fixed_bytes<const N: usize, S>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut encoded = String::with_capacity(2 + (N * 2));
    encoded.push_str("0x");
    encoded.push_str(&hex::encode(bytes));
    serializer.serialize_str(&encoded)
}

fn deserialize_fixed_bytes<'de, const N: usize, D>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    struct FixedBytesVisitor<const N: usize>;

    impl<const N: usize> de::Visitor<'_> for FixedBytesVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a 0x-prefixed hex string with {N} bytes")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let hex = value
                .strip_prefix("0x")
                .ok_or_else(|| E::custom("missing 0x prefix"))?;
            if hex.len() != N * 2 {
                return Err(E::custom(format!("expected {} hex characters", N * 2)));
            }

            let mut bytes = [0; N];
            hex::decode_to_slice(hex, &mut bytes).map_err(E::custom)?;
            Ok(bytes)
        }
    }

    deserializer.deserialize_str(FixedBytesVisitor::<N>)
}

macro_rules! fixed_bytes_newtype_serde {
    ($name:ident, $len:literal) => {
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serialize_fixed_bytes(&self.0, serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserialize_fixed_bytes::<$len, D>(deserializer).map(Self)
            }
        }
    };
}

impl<const N: usize> Serialize for FixedBytes<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_fixed_bytes(&self.0, serializer)
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedBytes<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_fixed_bytes(deserializer).map(Self)
    }
}

fixed_bytes_newtype_serde!(Address, 20);
fixed_bytes_newtype_serde!(Bytes32, 32);
fixed_bytes_newtype_serde!(ReaderId, 32);
fixed_bytes_newtype_serde!(RequestId, 32);
fixed_bytes_newtype_serde!(HandleId, 32);
fixed_bytes_newtype_serde!(Nonce, 32);
fixed_bytes_newtype_serde!(DomainId, 32);
fixed_bytes_newtype_serde!(KeyId, 32);
fixed_bytes_newtype_serde!(X25519PublicKey, 32);
fixed_bytes_newtype_serde!(EthereumSignature, 65);

fn serialize_base64url<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
}

fn deserialize_base64url<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    URL_SAFE_NO_PAD.decode(encoded).map_err(de::Error::custom)
}

impl Serialize for PayloadBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_base64url(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for PayloadBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_base64url(deserializer).map(Self)
    }
}
