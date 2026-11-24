//! Zano (ZANO): CryptoNote-style dual keys derived from a 32-byte seed, and the 26-word seed
//! phrase the official wallet restores from.
//!
//! Every rule below follows `hyle-team/zano@d49f34aa8d7978586990aa83922df0f567a8ae3b`:
//!
//! - Keys (`src/crypto/crypto.cpp`, `keys_from_default`, `dependent_key`): the spend secret is
//!   `seed ‖ Keccak256(seed)` read as a 64-byte little-endian integer and reduced modulo the
//!   ed25519 group order; the view secret is `Keccak256(spend secret)` reduced the same way as a
//!   32-byte integer; each public key is the secret times the ed25519 base point. Keccak-256 is the
//!   original Keccak that Monero and Ethereum use, not SHA3-256.
//! - Address (`src/currency_core/currency_format_utils.cpp`, `get_account_address_as_str`): the
//!   CryptoNote block-base58 of `varint(prefix) ‖ spend public ‖ view public [‖ flags]` and the first
//!   four bytes of its Keccak-256. A normal address (flags 0) has prefix `0xc5` and no flags byte
//!   (`Zx…`); an auditable one has prefix `0x98c8` and the flags byte `0x01` (`aZx…`).
//! - Phrase (`src/currency_core/account.cpp`, `get_seed_phrase`, `restore_from_seed_phrase`;
//!   `src/common/mnemonic-encoding.cpp`; `currency_format_utils.cpp`, `get_word_from_timestamp`):
//!   24 words carry the seed, each little-endian `u32` as three base-1626 digits; word 25 is the
//!   number of weeks since 2018-12-01 (800 is added when a password is set); word 26 is
//!   `auditable | checksum << 1`, where the checksum is `u64le(Keccak256(h)[..8]) % 814` with
//!   `h = Keccak256(seed ‖ password)` whose first eight bytes are overwritten by the week-rounded
//!   timestamp, and a checksum of 813 is written as 0.
//!
//! No password is supported: a phrase that says it has one is refused by name.

use curve25519_dalek::Scalar;
use zeroize::Zeroize;

use crate::codec::cryptonote;
use crate::coins::{ZANO_ADDRESS_PREFIX, ZANO_AUDITABLE_ADDRESS_PREFIX};
use crate::curves::ed25519;
use crate::hash::keccak256;
use crate::wordlist_zano_en::WORDS;

/// Seconds at which week 0 of the timestamp word begins, 2018-12-01 00:00 UTC:
/// `WALLET_BRAIN_DATE_OFFSET` in `src/currency_core/currency_config.h`.
const BRAIN_DATE_OFFSET: u64 = 1_543_622_400;

/// One week, `WALLET_BRAIN_DATE_QUANTUM`.
const BRAIN_DATE_QUANTUM: u64 = 604_800;

/// `WALLET_BRAIN_DATE_MAX_WEEKS_COUNT`: weeks at or above it in the timestamp word mean a password.
const MAX_WEEKS: u64 = 800;

/// The word-list length, `NUMWORDS`.
const NUM_WORDS: u32 = 1626;

/// `NUMWORDS >> 1`, the largest checksum value; `get_seed_phrase` writes it as 0.
const CHECKSUM_MAX: u64 = 813;

/// Words in a current phrase: 24 seed words, the timestamp word, the flags-and-checksum word.
pub(crate) const PHRASE_WORDS: usize = 26;

/// Words in a version-1 phrase, which has no flags-and-checksum word.
const PHRASE_WORDS_V1: usize = 25;

/// The spend and view private keys of a seed, as 32 little-endian bytes each.
pub(crate) fn private_keys(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(seed);
    wide[32..].copy_from_slice(&keccak256(seed));
    let spend = Scalar::from_bytes_mod_order_wide(&wide).to_bytes();
    wide.zeroize();
    let view = ed25519::reduce_scalar_mod_l(&keccak256(&spend));
    (spend, view)
}

/// The address of two private keys, auditable or normal.
pub(crate) fn address_from_keys(spend: &[u8; 32], view: &[u8; 32], auditable: bool) -> String {
    let mut data = Vec::with_capacity(3 + 64 + 1 + 4);
    let prefix = if auditable {
        ZANO_AUDITABLE_ADDRESS_PREFIX
    } else {
        ZANO_ADDRESS_PREFIX
    };
    cryptonote::write_varint(prefix, &mut data);
    data.extend_from_slice(&ed25519::scalarmult_base(spend));
    data.extend_from_slice(&ed25519::scalarmult_base(view));
    if auditable {
        data.push(1);
    }
    let checksum = keccak256(&data);
    data.extend_from_slice(&checksum[..4]);
    cryptonote::encode(&data)
}

/// The address of a seed, auditable or normal.
pub(crate) fn address(seed: &[u8; 32], auditable: bool) -> String {
    let (mut spend, mut view) = private_keys(seed);
    let a = address_from_keys(&spend, &view, auditable);
    spend.zeroize();
    view.zeroize();
    a
}

/// The week count a creation time encodes, `get_word_from_timestamp` without a password. `None` at
/// or past week 800, where the C++ refuses to make a phrase.
fn weeks_of(timestamp: u64) -> Option<u64> {
    let weeks = timestamp.saturating_sub(BRAIN_DATE_OFFSET) / BRAIN_DATE_QUANTUM;
    (weeks < MAX_WEEKS).then_some(weeks)
}

/// The checksum of the flags-and-checksum word, for a seed and the week-rounded timestamp the
/// timestamp word decodes to, with an empty password.
fn checksum(seed: &[u8; 32], rounded_timestamp: u64) -> u64 {
    let mut h = keccak256(seed);
    h[..8].copy_from_slice(&rounded_timestamp.to_le_bytes());
    let h2 = keccak256(&h);
    let mut low = [0u8; 8];
    low.copy_from_slice(&h2[..8]);
    match u64::from_le_bytes(low) % (CHECKSUM_MAX + 1) {
        CHECKSUM_MAX => 0,
        c => c,
    }
}

/// The 26-word phrase for `seed`, created at `timestamp` (Unix seconds), not auditable. `None` when
/// the timestamp is past the 800 weeks the timestamp word can hold.
pub(crate) fn phrase(seed: &[u8; 32], timestamp: u64) -> Option<String> {
    let weeks = weeks_of(timestamp)?;
    let mut words: Vec<&'static str> = Vec::with_capacity(PHRASE_WORDS);
    for chunk in seed.as_chunks::<4>().0 {
        let v = u32::from_le_bytes(*chunk);
        let w1 = v % NUM_WORDS;
        let w2 = (v / NUM_WORDS + w1) % NUM_WORDS;
        let w3 = (v / NUM_WORDS / NUM_WORDS + w2) % NUM_WORDS;
        words.extend([w1, w2, w3].map(|w| WORDS[w as usize]));
    }
    let rounded = weeks * BRAIN_DATE_QUANTUM + BRAIN_DATE_OFFSET;
    words.push(WORDS[usize::try_from(weeks).ok()?]);
    // Auditable flag 0, so the word index is the checksum shifted left once (at most 1624).
    words.push(WORDS[usize::try_from(checksum(seed, rounded) << 1).ok()?]);
    Some(words.join(" "))
}

/// What a phrase restores: the seed, whether the address is auditable, and the creation time.
pub(crate) struct Restored {
    /// The 32-byte seed the 24 words carry.
    pub(crate) seed: [u8; 32],
    /// The auditable flag of the 26th word (always `false` for a 25-word phrase).
    pub(crate) auditable: bool,
}

impl Drop for Restored {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// The index of `word` in the list, as `num_by_word` finds it: exact, lowercase.
fn index_of(word: &str, position: usize) -> Result<u32, String> {
    WORDS
        .iter()
        .position(|w| *w == word)
        .and_then(|i| u32::try_from(i).ok())
        .ok_or_else(|| format!("word {position} (\"{word}\") is not in Zano's word list"))
}

/// Restore a 26-word phrase (or a 25-word version-1 phrase, which has no checksum word), as
/// `account_base::restore_from_seed_phrase` does with an empty password. The checksum word is
/// verified; a phrase whose timestamp word says it was made with a password is refused.
pub(crate) fn from_phrase(phrase: &str) -> Result<Restored, String> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != PHRASE_WORDS && words.len() != PHRASE_WORDS_V1 {
        return Err(format!(
            "a Zano seed phrase has {PHRASE_WORDS} words ({PHRASE_WORDS_V1} for the old form \
             with no checksum word), not {}",
            words.len()
        ));
    }
    let mut seed = [0u8; 32];
    for (i, triple) in words[..24].chunks(3).enumerate() {
        let w1 = index_of(triple[0], 3 * i + 1)?;
        let w2 = index_of(triple[1], 3 * i + 2)?;
        let w3 = index_of(triple[2], 3 * i + 3)?;
        // `text2binary_throw` computes this in `uint32_t`, so it wraps; so does this.
        let n = NUM_WORDS;
        let v = w1
            .wrapping_add(n.wrapping_mul((n - w1 + w2) % n))
            .wrapping_add(n.wrapping_mul(n).wrapping_mul((n - w2 + w3) % n));
        seed[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    let weeks = u64::from(index_of(words[24], 25)?);
    if weeks >= MAX_WEEKS {
        seed.zeroize();
        return Err(
            "this Zano phrase was made with a seed password, which this tool does not support; \
             restore it in the official Zano wallet"
                .to_string(),
        );
    }
    let mut restored = Restored {
        seed,
        auditable: false,
    };
    seed.zeroize();
    if let Some(word) = words.get(25) {
        let flags_and_checksum = u64::from(index_of(word, 26)?);
        let rounded = weeks * BRAIN_DATE_QUANTUM + BRAIN_DATE_OFFSET;
        if flags_and_checksum >> 1 != checksum(&restored.seed, rounded) {
            return Err(
                "the Zano phrase's checksum word does not match its other words; check them"
                    .to_string(),
            );
        }
        restored.auditable = flags_and_checksum & 1 == 1;
    }
    Ok(restored)
}

/// The current time as Unix seconds, the creation time a fresh phrase records.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::hexbytes::{encode as hex, hex32};

    /// Zano's own unit test, `tests/unit_tests/wallet_seed_test.cpp` L127-L143: the new-style
    /// 26-word phrase and its auditable twin, with the private keys the C++ asserts and creation
    /// time 1922832000. The two addresses are this codec's output for those keys, the C++ test
    /// asserting none.
    pub(crate) const UNIT_PHRASE: &str =
        "six six six six six six six six six six six six six six six \
         six six six six six six six six six six frown";
    pub(crate) const UNIT_AUDITABLE_PHRASE: &str =
        "six six six six six six six six six six six six six \
         six six six six six six six six six six six six grace";
    const UNIT_SPEND: &str = "f54f61e3b974ad86171ae4944205c7bd0395bd7845899cda8b1fbc5c947bb402";
    const UNIT_VIEW: &str = "a18715058bbd914959c3a735b2022e9ae1d04452bc1fad9e63c53668b7f57907";
    pub(crate) const UNIT_ADDRESS: &str = "ZxDachPpH6Wc6PU36Se55dPEWd2SjkZQaNRrbCZJQihw2M5YYfeSsogUncHPCHDkG3XYGviMCXoWrNqvUz6QUJyw13Gemoa6u";
    const UNIT_AUDITABLE_ADDRESS: &str = "aZxbFpPZMLTM3QBvFLgNXu4S4cFnru9Lz3bNg6oxtXxyL5FNavPBvpGcQG4UgDHaw4XE9PAJFDikCdiXMCPU3QUvc8SGZQwdbWo";

    /// A seed of bytes 00..1f, created at 1764000000 (2025-11-24). The phrase, keys and address
    /// come from a from-scratch Python oracle that first reproduced the C++ unit-test keys above
    /// and the `zano-utils-js` address vector below.
    pub(crate) const SEQ_SEED: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const SEQ_TIMESTAMP: u64 = 1_764_000_000;
    pub(crate) const SEQ_PHRASE: &str =
        "before bring today bleed process melody cruel devil nowhere \
         frozen bit month fur suffocate thigh against volume effort hill worse thick shove world \
         different leaf reach";
    const SEQ_SPEND: &str = "ab844f4631f0537fbb49ca98789c5d671427d60b089b7cde424aaab6241ba009";
    const SEQ_VIEW: &str = "ba5d6314b75189637e7450cd4f21524fc5cfe9e45a646d608ab496b8ce6e790c";
    pub(crate) const SEQ_ADDRESS: &str = "ZxCrb7RQme5crtLnBWbd1SDCxFWaqSeMVVrVDaQanwdPBuUcWX2mWdKRR2NS7Smi6yZ2pWhgrjcLpPvxFoEGEUq71g1X7RwaP";

    fn one_line(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn the_word_list_opens_like_just_love() {
        assert_eq!(WORDS[..3], ["like", "just", "love"]);
        assert_eq!(WORDS[1625], "weary");
    }

    #[test]
    fn zano_unit_test_phrase_restores_the_cpp_keys() {
        for (p, auditable, addr) in [
            (UNIT_PHRASE, false, UNIT_ADDRESS),
            (UNIT_AUDITABLE_PHRASE, true, UNIT_AUDITABLE_ADDRESS),
        ] {
            let r = from_phrase(&one_line(p)).unwrap();
            assert_eq!(r.auditable, auditable);
            let (spend, view) = private_keys(&r.seed);
            assert_eq!(hex(&spend), UNIT_SPEND);
            assert_eq!(hex(&view), UNIT_VIEW);
            assert_eq!(address_from_keys(&spend, &view, auditable), addr);
        }
        // The C++ creation time is 1922832000: the phrase this tool makes for that seed and time is
        // the unit test's own.
        let r = from_phrase(&one_line(UNIT_PHRASE)).unwrap();
        assert_eq!(
            phrase(&r.seed, 1_922_832_000).unwrap(),
            one_line(UNIT_PHRASE)
        );
    }

    #[test]
    fn a_generated_phrase_matches_the_oracle() {
        let seed = hex32(SEQ_SEED);
        assert_eq!(phrase(&seed, SEQ_TIMESTAMP).unwrap(), one_line(SEQ_PHRASE));
        let (spend, view) = private_keys(&seed);
        assert_eq!(hex(&spend), SEQ_SPEND);
        assert_eq!(hex(&view), SEQ_VIEW);
        assert_eq!(address(&seed, false), SEQ_ADDRESS);
        let r = from_phrase(&one_line(SEQ_PHRASE)).unwrap();
        assert_eq!(r.seed, seed);
        assert!(!r.auditable);
    }

    /// `zano-utils-js` `tests/account-utils.spec.ts`: a secret spend key and the address the
    /// library derives from it, through `getAccountBySecretSpendKey`.
    #[test]
    fn zano_utils_js_spend_key_vector() {
        let spend = hex32("80b3e96a3eb765332b0fd3e44e0fefa58747a70025bf91aa4a7b758ab6f5590d");
        let view = ed25519::reduce_scalar_mod_l(&keccak256(&spend));
        assert_eq!(
            hex(&view),
            "3e75ffee51eb21b1d6404ddcab5b3aaa49edbfe225e9a893d87074aacae46b09"
        );
        assert_eq!(
            address_from_keys(&spend, &view, false),
            "ZxDFpn4k7xVYyc9VZ3LphrJbkpc46xfREace5bme1aXiMzKPAHA8jsTWcHSXhv9AdodSaoGXK9Mg7bk3ec4FkQrj357fZPWZX"
        );
    }

    /// The timestamp word floors to whole weeks from 2018-12-01, and a time before that is week 0.
    #[test]
    fn timestamp_words_floor_to_weeks() {
        assert_eq!(weeks_of(0), Some(0));
        assert_eq!(
            weeks_of(BRAIN_DATE_OFFSET + BRAIN_DATE_QUANTUM - 1),
            Some(0)
        );
        assert_eq!(weeks_of(BRAIN_DATE_OFFSET + BRAIN_DATE_QUANTUM), Some(1));
        assert_eq!(weeks_of(BRAIN_DATE_OFFSET + 800 * BRAIN_DATE_QUANTUM), None);
    }

    /// The C++ writes a checksum of 813 as 0, and reads 0 for it back. `zano-utils-js` omits that
    /// step, which is why this follows the C++. A seed whose raw checksum is 813 is found by search
    /// over the first seeds `i ‖ 0…`, so the special case is exercised, not just stated.
    #[test]
    fn a_checksum_of_813_is_written_as_zero() {
        let rounded = BRAIN_DATE_OFFSET;
        let raw = |seed: &[u8; 32]| {
            let mut h = keccak256(seed);
            h[..8].copy_from_slice(&rounded.to_le_bytes());
            let h2 = keccak256(&h);
            u64::from_le_bytes(h2[..8].try_into().unwrap()) % 814
        };
        let seed = (0u32..100_000)
            .map(|i| {
                let mut s = [0u8; 32];
                s[..4].copy_from_slice(&i.to_le_bytes());
                s
            })
            .find(|s| raw(s) == CHECKSUM_MAX)
            .expect("one seed in 814 has the raw checksum 813");
        assert_eq!(checksum(&seed, rounded), 0);
        let p = phrase(&seed, rounded).unwrap();
        assert_eq!(p.split(' ').next_back(), Some(WORDS[0]));
        assert_eq!(from_phrase(&p).unwrap().seed, seed);
    }

    #[test]
    fn bad_phrases_are_refused() {
        let good = one_line(SEQ_PHRASE);
        let mut words: Vec<&str> = good.split(' ').collect();
        // A wrong checksum word.
        words[25] = if words[25] == "reach" {
            "like"
        } else {
            "reach"
        };
        assert!(from_phrase(&words.join(" ")).is_err());
        // Two seed words swapped.
        let mut swapped: Vec<&str> = good.split(' ').collect();
        swapped.swap(0, 1);
        assert!(from_phrase(&swapped.join(" ")).is_err());
        // A word not in the list, a wrong count, and a password-protected timestamp word (index
        // 800 or above).
        assert!(from_phrase(&good.replacen("before", "abbey", 1)).is_err());
        assert!(from_phrase(&good.split(' ').take(24).collect::<Vec<_>>().join(" ")).is_err());
        let mut pw: Vec<&str> = good.split(' ').collect();
        pw[24] = WORDS[900];
        let err = from_phrase(&pw.join(" ")).err().unwrap();
        assert!(err.contains("password"), "{err}");
        // The 25-word form has no checksum word and restores the same seed.
        let v1: Vec<&str> = good.split(' ').take(25).collect();
        assert_eq!(from_phrase(&v1.join(" ")).unwrap().seed, hex32(SEQ_SEED));
    }
}
