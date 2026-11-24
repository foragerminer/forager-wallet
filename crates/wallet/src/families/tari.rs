//! Tari (XTM): the 24-word CipherSeed, the two keys it derives, and the dual address.
//!
//! **Seed.** A CipherSeed holds a birthday (days since 2022-01-01 UTC, `u16`), 16 bytes of entropy
//! and a 5-byte salt. It is enciphered to 33 bytes:
//! `version ‖ ChaCha20(birthday_le ‖ entropy ‖ mac) ‖ salt ‖ crc32_le`, where Argon2d (v0x13,
//! 46 MiB, one pass, one lane) of the passphrase `TARI_CIPHER_SEED` over a salt hashed from the
//! 5-byte salt gives the ChaCha20 key and the MAC key. The 33 bytes are 264 bits, read
//! least-significant bit first in groups of 11, one word per group from the 2048-word English list
//! (the BIP39 list, but **not** BIP39: no BIP39 checksum and no PBKDF2). Only version 2, the
//! form with no user passphrase, is produced or read.
//!
//! **Keys.** `view_sk = derive(entropy, "data encryption")` and `spend_sk = derive(entropy,
//! "comms")`, where `derive` is Blake2b-512 under Tari's domain separation of
//! `entropy`, the branch and `0u64`, reduced modulo the Ristretto255 group order. Each public key
//! is `sk * G`, compressed. Only the entropy matters: the birthday and salt never reach a key.
//!
//! **Address.** See [`crate::codec::tari`]: mainnet network byte `0x00`, then the features byte,
//! the two keys and a DammSum. This module emits the one-sided form (`0x01`, `12…`), which is what
//! a coinbase pays.
//!
//! Sources, all `tari-project/tari@ae2296bc97f43979171981394253eedb5b1b9f5b` (BSD-3-Clause):
//! `base_layer/common_types/src/seeds/cipher_seed.rs` (`encipher`, `from_enciphered_bytes`,
//! `derive_keys`, `generate_mac`, `apply_stream_cipher`), `seeds/mnemonic.rs` (`from_bytes`,
//! `to_bytes_with_language`), `seeds/mod.rs` (the hasher labels),
//! `base_layer/transaction_components/src/key_manager/wallet_types.rs` (`SeedWordsWallet::
//! construct_new`, `derive_private_key`), `hashing/src/domains.rs` (`KeyManagerDomain`) and
//! `tari_crypto` 0.24.1 `src/hashing.rs` (`DomainSeparatedHasher`). No code is taken from them. The
//! known-answer vectors below were produced by running that code.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::Scalar;
use zeroize::{Zeroize, Zeroizing};

use crate::codec::tari::{dual_bytes, encode, FEATURE_ONE_SIDED};
use crate::coins::TARI_NETWORK_MAINNET;
use crate::wordlist_bip39_en::WORDS;

/// The only CipherSeed version produced or read: Argon2d under the default passphrase.
const VERSION: u8 = 2;
/// The version a user passphrase produces (Argon2id). Recognised only to name it in an error.
const VERSION_PASSPHRASE: u8 = 3;
/// `DEFAULT_CIPHER_SEED_PASSPHRASE`.
const DEFAULT_PASSPHRASE: &[u8] = b"TARI_CIPHER_SEED";
/// `BIRTHDAY_GENESIS_FROM_UNIX_EPOCH`: 2022-01-01 00:00:00 UTC.
const BIRTHDAY_GENESIS_UNIX: u64 = 1_640_995_200;

/// Bytes of entropy in a CipherSeed: the only input to the keys.
pub(crate) const ENTROPY_LEN: usize = 16;
/// Bytes of the CipherSeed's own salt.
pub(crate) const SALT_LEN: usize = 5;
const MAC_LEN: usize = 5;
/// `birthday(2) ‖ entropy(16) ‖ mac(5)`: the enciphered part.
const SECRET_LEN: usize = 2 + ENTROPY_LEN + MAC_LEN;
/// `version ‖ secret ‖ salt ‖ crc32`.
const ENCIPHERED_LEN: usize = 1 + SECRET_LEN + SALT_LEN + 4;
/// Words in a Tari seed phrase: 33 bytes are exactly 24 groups of 11 bits.
pub(crate) const WORD_COUNT: usize = 24;

/// The `KeyManagerDomain` tag prefix: `"com.tari.base_layer.key_manager"`, version 1.
const DOMAIN: &str = "com.tari.base_layer.key_manager.v1.";
/// `HASHER_LABEL_DERIVE_KEY`.
const LABEL_DERIVE_KEY: &str = "derive_key";
/// `HASHER_LABEL_CIPHER_SEED_PBKDF_SALT`.
const LABEL_PBKDF_SALT: &str = "cipher_seed_pbkdf_salt";
/// `HASHER_LABEL_CIPHER_SEED_ENCRYPTION_NONCE`.
const LABEL_NONCE: &str = "cipher_seed_encryption_nonce";
/// `HASHER_LABEL_CIPHER_SEED_MAC`.
const LABEL_MAC: &str = "cipher_seed_mac";
/// `VIEW_KEY_BRANCH`.
const VIEW_BRANCH: &str = "data encryption";
/// `SPEND_KEY_BRANCH`.
const SPEND_BRANCH: &str = "comms";

/// Tari's `DomainSeparatedHasher<Blake2b<N>, KeyManagerDomain>`: Blake2b with an `out_len`-byte
/// digest (the digest length is a Blake2b parameter, not a truncation) over
/// `len_le64(tag) ‖ tag` and then `len_le64(chunk) ‖ chunk` for each chunk, where
/// `tag = "com.tari.base_layer.key_manager.v1.<label>"`.
fn ds_hash(out_len: usize, label: &str, chunks: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut state = blake2b_simd::Params::new().hash_length(out_len).to_state();
    let tag = format!("{DOMAIN}{label}");
    state.update(&(tag.len() as u64).to_le_bytes());
    state.update(tag.as_bytes());
    for chunk in chunks {
        state.update(&(chunk.len() as u64).to_le_bytes());
        state.update(chunk);
    }
    Zeroizing::new(state.finalize().as_bytes().to_vec())
}

/// A decoded CipherSeed. The salt and birthday are carried so the same 24 words can be printed
/// back; neither reaches a key.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CipherSeed {
    pub(crate) birthday: u16,
    pub(crate) entropy: [u8; ENTROPY_LEN],
    pub(crate) salt: [u8; SALT_LEN],
}

impl Drop for CipherSeed {
    fn drop(&mut self) {
        self.entropy.zeroize();
        self.salt.zeroize();
    }
}

/// Why a phrase did not decode to a CipherSeed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SeedError {
    WordCount(usize),
    UnknownWord(usize),
    Checksum,
    Version(u8),
    Mac,
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeedError::WordCount(n) => write!(f, "a Tari seed is {WORD_COUNT} words, got {n}"),
            SeedError::UnknownWord(i) => {
                write!(f, "word {i} is not in the English Tari word list")
            }
            SeedError::Checksum => {
                f.write_str("the seed's CRC-32 does not match: a word is wrong or out of order")
            }
            SeedError::Version(VERSION_PASSPHRASE) => f.write_str(
                "this seed is protected by a user passphrase (CipherSeed version 3), which is not \
                 supported",
            ),
            SeedError::Version(v) => write!(f, "unknown CipherSeed version {v}"),
            SeedError::Mac => f.write_str(
                "the seed decrypts but its MAC does not verify: it was enciphered with a \
                 passphrase, or it is corrupt",
            ),
        }
    }
}

/// Argon2d of the default passphrase: the ChaCha20 key (first 32 bytes) and the MAC key (last 32).
fn derive_keys(salt: &[u8; SALT_LEN]) -> Zeroizing<[u8; 64]> {
    let argon_salt = ds_hash(32, LABEL_PBKDF_SALT, &[salt]);
    let params = Params::new(46 * 1024, 1, 1, Some(64)).expect("fixed Argon2 parameters are valid");
    let mut out = Zeroizing::new([0u8; 64]);
    Argon2::new(Algorithm::Argon2d, Version::V0x13, params)
        .hash_password_into(DEFAULT_PASSPHRASE, &argon_salt[..16], out.as_mut())
        .expect("fixed Argon2 inputs are valid");
    out
}

/// The first 5 bytes of the MAC over `version ‖ birthday_le ‖ entropy ‖ salt ‖ mac_key`, each a
/// separate length-prefixed chunk.
fn mac(birthday: [u8; 2], entropy: &[u8], salt: &[u8], mac_key: &[u8]) -> [u8; MAC_LEN] {
    let h = ds_hash(
        32,
        LABEL_MAC,
        &[&[VERSION], &birthday, entropy, salt, mac_key],
    );
    h[..MAC_LEN].try_into().expect("5 of 32 bytes")
}

/// ChaCha20 (96-bit nonce, counter 0) in place, keyed by `enc_key`, nonce from the salt.
fn apply_cipher(data: &mut [u8], enc_key: &[u8], salt: &[u8]) {
    let nonce = ds_hash(32, LABEL_NONCE, &[salt]);
    let key: [u8; 32] = enc_key.try_into().expect("32-byte key");
    let iv: [u8; 12] = nonce[..12].try_into().expect("12-byte nonce");
    ChaCha20::new(&key.into(), &iv.into()).apply_keystream(data);
}

impl CipherSeed {
    /// Encipher to the 33 bytes the 24 words carry. Runs Argon2 once (46 MiB).
    pub(crate) fn encipher(&self) -> Zeroizing<[u8; ENCIPHERED_LEN]> {
        let keys = derive_keys(&self.salt);
        let birthday = self.birthday.to_le_bytes();
        let mut out = Zeroizing::new([0u8; ENCIPHERED_LEN]);
        out[0] = VERSION;
        out[1..3].copy_from_slice(&birthday);
        out[3..3 + ENTROPY_LEN].copy_from_slice(&self.entropy);
        out[3 + ENTROPY_LEN..1 + SECRET_LEN].copy_from_slice(&mac(
            birthday,
            &self.entropy,
            &self.salt,
            &keys[32..],
        ));
        apply_cipher(&mut out[1..1 + SECRET_LEN], &keys[..32], &self.salt);
        out[1 + SECRET_LEN..1 + SECRET_LEN + SALT_LEN].copy_from_slice(&self.salt);
        let crc = crc32fast::hash(&out[..ENCIPHERED_LEN - 4]);
        out[ENCIPHERED_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        out
    }

    /// Decipher 33 bytes: CRC, version 2, then Argon2, decryption and the MAC check.
    pub(crate) fn decipher(bytes: &[u8; ENCIPHERED_LEN]) -> Result<Self, SeedError> {
        let (payload, crc) = bytes.split_at(ENCIPHERED_LEN - 4);
        if crc32fast::hash(payload).to_le_bytes() != crc {
            return Err(SeedError::Checksum);
        }
        if payload[0] != VERSION {
            return Err(SeedError::Version(payload[0]));
        }
        let salt: [u8; SALT_LEN] = payload[1 + SECRET_LEN..].try_into().expect("5-byte salt");
        let keys = derive_keys(&salt);
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        secret.copy_from_slice(&payload[1..1 + SECRET_LEN]);
        apply_cipher(secret.as_mut(), &keys[..32], &salt);
        let birthday = [secret[0], secret[1]];
        let entropy: [u8; ENTROPY_LEN] = secret[2..2 + ENTROPY_LEN].try_into().expect("16 bytes");
        let seed = CipherSeed {
            birthday: u16::from_le_bytes(birthday),
            entropy,
            salt,
        };
        let expected = mac(birthday, &seed.entropy, &salt, &keys[32..]);
        // Not secret-dependent timing worth defending offline, but compare every byte anyway.
        let diff = expected
            .iter()
            .zip(&secret[2 + ENTROPY_LEN..])
            .fold(0u8, |d, (a, b)| d | (a ^ b));
        if diff != 0 {
            return Err(SeedError::Mac);
        }
        Ok(seed)
    }

    /// The 24 words of this seed (runs Argon2 once).
    pub(crate) fn to_phrase(&self) -> Zeroizing<String> {
        bytes_to_phrase(&self.encipher())
    }

    /// Decode and verify a 24-word phrase (runs Argon2 once).
    pub(crate) fn from_phrase(phrase: &str) -> Result<Self, SeedError> {
        let bytes = phrase_to_bytes(phrase)?;
        Self::decipher(&bytes)
    }
}

/// 33 bytes to 24 words: the bytes as one little-endian bit string, 11 bits per word, least
/// significant bit first (`tari_utilities::bit::bytes_to_bits`, `checked_bits_to_uint`).
fn bytes_to_phrase(bytes: &[u8; ENCIPHERED_LEN]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    for w in 0..WORD_COUNT {
        let mut index = 0usize;
        for b in 0..11 {
            let bit = w * 11 + b;
            index |= usize::from((bytes[bit / 8] >> (bit % 8)) & 1) << b;
        }
        if w > 0 {
            out.push(' ');
        }
        out.push_str(WORDS[index]);
    }
    out
}

/// 24 words to 33 bytes, the inverse of [`bytes_to_phrase`]. Words are matched case-insensitively
/// and may be separated by any whitespace, as the official parser allows.
fn phrase_to_bytes(phrase: &str) -> Result<Zeroizing<[u8; ENCIPHERED_LEN]>, SeedError> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != WORD_COUNT {
        return Err(SeedError::WordCount(words.len()));
    }
    let mut out = Zeroizing::new([0u8; ENCIPHERED_LEN]);
    for (w, word) in words.iter().enumerate() {
        let lower = Zeroizing::new(word.to_ascii_lowercase());
        let index = WORDS
            .binary_search(&lower.as_str())
            .map_err(|_| SeedError::UnknownWord(w + 1))?;
        for b in 0..11 {
            let bit = w * 11 + b;
            out[bit / 8] |= (((index >> b) & 1) as u8) << (bit % 8);
        }
    }
    Ok(out)
}

/// Today's CipherSeed birthday: whole days since 2022-01-01 UTC, or 0 if the clock is unreadable
/// or out of range (`birthday_from_unix_millis`).
pub(crate) fn birthday_today() -> u16 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    u16::try_from(secs.saturating_sub(BIRTHDAY_GENESIS_UNIX) / 86_400).unwrap_or(0)
}

/// `derive_private_key(entropy, branch, 0)`: the 64-byte domain-separated hash reduced modulo
/// the group order (`RistrettoSecretKey::from_uniform_bytes`).
fn derive_key(entropy: &[u8; ENTROPY_LEN], branch: &str) -> Scalar {
    let h = ds_hash(
        64,
        LABEL_DERIVE_KEY,
        &[entropy, branch.as_bytes(), &0u64.to_le_bytes()],
    );
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h);
    let s = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    s
}

/// The view and spend private keys of a seed's entropy, as 32 little-endian bytes each.
pub(crate) fn private_keys(entropy: &[u8; ENTROPY_LEN]) -> ([u8; 32], [u8; 32]) {
    let mut v = derive_key(entropy, VIEW_BRANCH);
    let mut s = derive_key(entropy, SPEND_BRANCH);
    let out = (v.to_bytes(), s.to_bytes());
    v.zeroize();
    s.zeroize();
    out
}

/// The compressed public key `sk * G` of a canonical private key.
fn public_key(sk: &[u8; 32]) -> [u8; 32] {
    let mut s = Scalar::from_bytes_mod_order(*sk);
    let pk = (RISTRETTO_BASEPOINT_POINT * s).compress().to_bytes();
    s.zeroize();
    pk
}

/// The mainnet dual address with the given features byte for a seed's entropy.
pub(crate) fn address_with_features(entropy: &[u8; ENTROPY_LEN], features: u8) -> String {
    let (mut v, mut s) = private_keys(entropy);
    let bytes = dual_bytes(
        TARI_NETWORK_MAINNET,
        features,
        &public_key(&v),
        &public_key(&s),
    );
    v.zeroize();
    s.zeroize();
    encode(&bytes)
}

/// The one-sided mainnet address (`12…`) for a seed's entropy: the form a coinbase pays.
pub(crate) fn address(entropy: &[u8; ENTROPY_LEN]) -> String {
    address_with_features(entropy, FEATURE_ONE_SIDED)
}

/// Parse 16 bytes of entropy as 32 hex characters, whitespace ignored.
pub(crate) fn parse_entropy(input: &str) -> Option<[u8; ENTROPY_LEN]> {
    let mut compact: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let out = crate::hexbytes::decode_n::<ENTROPY_LEN>(&compact);
    compact.zeroize();
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::codec::tari::FEATURE_INTERACTIVE;
    use crate::hexbytes::encode as hex;

    /// One official vector: `(words, birthday, entropy, view_sk, view_pk, spend_sk, spend_pk,
    /// one-sided address, default address)`.
    pub(crate) struct Vector {
        pub(crate) words: &'static str,
        pub(crate) entropy: &'static str,
        view_sk: &'static str,
        view_pk: Option<&'static str>,
        spend_sk: &'static str,
        spend_pk: Option<&'static str>,
        pub(crate) one_sided: &'static str,
        pub(crate) default: &'static str,
    }

    /// Produced by running `tari-project/tari@ae2296bc`'s own code: `CipherSeed::random` (no
    /// passphrase, birthday 1788), `to_mnemonic`, `SeedWordsWallet::construct_new`,
    /// `CompressedPublicKey::from_secret_key` and `TariAddress::new_dual_address(..).to_base58()`
    /// with `create_one_sided_only()` and the default features.
    pub(crate) const VECTORS: [Vector; 2] = [
        Vector {
            words: "leopard adjust liberty card snack captain venue avocado unusual detail load \
                    section tube hungry middle forget immune shoot inquiry apology pause magic \
                    ancient shrug",
            entropy: "50d13db652badc4bf5d474f9f52a179b",
            view_sk: "b760963a9eb4614e83c63514d0183ddb38badf325441248f01197deb93d66705",
            view_pk: Some("5864bb035381e44bf84e2ca9b004bf13f31f847c09825af1328e56a95c9c142c"),
            spend_sk: "cf3030dc33956c65acd8c0861712853c530e9d1bb1d6e99250852402e11cd004",
            spend_pk: Some("d441523e3d598f33a69ea0c5731de1b87f05736aa2787fa30e608a3019b6a246"),
            one_sided: "128oRQaWVvBxWLKB7VvU9XzWwP7C5rMptNa3HxT2L8GMRgeKMnGJdt1w5geMC6oDqmL7JgJmTtTqz8hGoVSXpEsAzVp",
            default: "148oRQaWVvBxWLKB7VvU9XzWwP7C5rMptNa3HxT2L8GMRgeKMnGJdt1w5geMC6oDqmL7JgJmTtTqz8hGoVSXpEsAzVR",
        },
        Vector {
            words: "gate entry coin orphan pond usage fever belt seven kidney wreck clock title \
                    plunge horror menu ethics olive length fall same sure robust item",
            entropy: "3ef7b5b830b19e7863fb73d26131d703",
            view_sk: "7e75e2502aea115cb155e2d94ec771160e6ed06ec978f495869a9bed17bb800f",
            view_pk: None,
            spend_sk: "99f6386ffa14e973a43916e64440499315868f985de9930054c8886e5b1a1400",
            spend_pk: None,
            one_sided: "12Bxe37CadXF3HG9CyjwfVrnAMTAUzD1mhQkwBDwjdDgbQNfUGMriqhdQnfKfbSiEZM2MR5kM8CWdKNdKcntZaF8kdf",
            default: "14Bxe37CadXF3HG9CyjwfVrnAMTAUzD1mhQkwBDwjdDgbQNfUGMriqhdQnfKfbSiEZM2MR5kM8CWdKNdKcntZaF8kdJ",
        },
    ];

    fn entropy_of(v: &Vector) -> [u8; ENTROPY_LEN] {
        parse_entropy(v.entropy).unwrap()
    }

    /// Entropy to keys to addresses, no Argon2 involved.
    #[test]
    fn official_keys_and_addresses() {
        for v in &VECTORS {
            let e = entropy_of(v);
            let (view, spend) = private_keys(&e);
            assert_eq!(hex(&view), v.view_sk);
            assert_eq!(hex(&spend), v.spend_sk);
            if let Some(pk) = v.view_pk {
                assert_eq!(hex(&public_key(&view)), pk);
            }
            if let Some(pk) = v.spend_pk {
                assert_eq!(hex(&public_key(&spend)), pk);
            }
            assert_eq!(address(&e), v.one_sided);
            assert_eq!(
                address_with_features(&e, FEATURE_ONE_SIDED | FEATURE_INTERACTIVE),
                v.default
            );
            assert_eq!(v.one_sided.len(), 91);
        }
    }

    /// The official words decode (CRC, Argon2, ChaCha20, MAC) to the official entropy and
    /// birthday, and enciphering that seed again gives back the same words.
    #[test]
    fn official_words_decode_and_re_encipher() {
        for v in &VECTORS {
            let seed = CipherSeed::from_phrase(v.words).unwrap();
            assert_eq!(hex(&seed.entropy), v.entropy);
            assert_eq!(seed.birthday, 1788);
            let canonical = v.words.split_whitespace().collect::<Vec<_>>().join(" ");
            assert_eq!(seed.to_phrase().as_str(), canonical);
        }
    }

    /// The seed of [`fixed_seed`] enciphers to these words. Cross-checked once, outside this
    /// repository, by feeding the words to the official `CipherSeed::from_mnemonic(&words, None)`
    /// of `tari-project/tari@ae2296bc`, which returned the entropy `00 01 .. 0f` and the birthday
    /// 1789, and whose `SeedWordsWallet` and `TariAddress::to_base58` gave [`FIXED_ADDRESS`].
    pub(crate) const FIXED_WORDS: &str = "able rural exit song suit warfare orbit neck pepper say \
                                          second runway museum room grace east raise length \
                                          express demand enable apple situate maid";

    /// The one-sided address of [`fixed_seed`], from the same official run.
    pub(crate) const FIXED_ADDRESS: &str =
        "12Do2V8XgiphRqp4461rUuuEDLetmW6aYuRsofejJF3ynJW9oCngb6RPE6q6iKyCjittwtfEi8SRT9JvJCBrmTTUXmR";

    pub(crate) fn fixed_seed() -> CipherSeed {
        CipherSeed {
            birthday: 1789,
            entropy: core::array::from_fn(|i| i as u8),
            salt: [0xa0, 0xa1, 0xa2, 0xa3, 0xa4],
        }
    }

    #[test]
    fn fixed_seed_enciphers_to_pinned_words() {
        let seed = fixed_seed();
        let words = seed.to_phrase();
        let pinned = FIXED_WORDS.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(words.as_str(), pinned);
        assert!(CipherSeed::from_phrase(&words) == Ok(seed.clone()));
        assert_eq!(address(&seed.entropy), FIXED_ADDRESS);
    }

    /// Each layer of the decoder refuses what it should: word count, unknown word, CRC, version,
    /// and a MAC that does not verify.
    #[test]
    fn corrupt_phrases_are_refused() {
        let words: Vec<&str> = VECTORS[0].words.split_whitespace().collect();
        assert_eq!(
            phrase_to_bytes(&words[..23].join(" ")).err(),
            Some(SeedError::WordCount(23))
        );
        let mut bad = words.clone();
        bad[4] = "notaword";
        assert_eq!(
            phrase_to_bytes(&bad.join(" ")).err(),
            Some(SeedError::UnknownWord(5))
        );
        // Swapping two words breaks the CRC.
        let mut swapped = words.clone();
        swapped.swap(0, 1);
        assert_eq!(
            CipherSeed::from_phrase(&swapped.join(" ")).err(),
            Some(SeedError::Checksum)
        );
        // Re-checksummed bytes with a flipped ciphertext bit pass the CRC and fail the MAC; a
        // version 3 byte is refused by name.
        let base = phrase_to_bytes(VECTORS[0].words).unwrap();
        let recrc = |mut b: [u8; ENCIPHERED_LEN]| {
            let crc = crc32fast::hash(&b[..ENCIPHERED_LEN - 4]);
            b[ENCIPHERED_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
            b
        };
        let mut flipped = *base;
        flipped[5] ^= 1;
        assert!(CipherSeed::decipher(&recrc(flipped)) == Err(SeedError::Mac));
        let mut v3 = *base;
        v3[0] = VERSION_PASSPHRASE;
        assert!(CipherSeed::decipher(&recrc(v3)) == Err(SeedError::Version(3)));
        // Upper case is accepted, as the official parser lowercases.
        let upper = VECTORS[1].words.to_ascii_uppercase();
        assert_eq!(
            *phrase_to_bytes(&upper).unwrap(),
            *phrase_to_bytes(VECTORS[1].words).unwrap()
        );
    }

    /// The bit packing is a bijection on 33 bytes.
    #[test]
    fn packing_round_trips() {
        let bytes: [u8; ENCIPHERED_LEN] = core::array::from_fn(|i| (i * 37 + 11) as u8);
        assert_eq!(*phrase_to_bytes(&bytes_to_phrase(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn birthday_is_after_2026() {
        // 2026-01-01 is day 1461.
        assert!(birthday_today() >= 1461);
    }
}
