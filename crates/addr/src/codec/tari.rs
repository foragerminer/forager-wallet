//! Tari dual-address bytes and their base58 text form.
//!
//! `bytes = network ‖ features ‖ view key (32) ‖ spend key (32) ‖ payment id (0..=256) ‖ checksum`,
//! where the checksum is the one-byte DammSum of everything before it, so the DammSum of the whole
//! string is zero. The text form is **not** the base58 of those bytes: it is
//! `base58(bytes[0]) ‖ base58(bytes[1]) ‖ base58(bytes[2..])`, three separately encoded parts. The
//! network and features bytes are below 58, so each is exactly one character.
//!
//! Source: `tari-project/tari@ae2296bc97f43979171981394253eedb5b1b9f5b` (BSD-3-Clause),
//! `base_layer/common_types/src/dammsum.rs` (`compute_checksum`, `validate_checksum`),
//! `base_layer/common_types/src/tari_address/dual_address.rs` (`to_vec`, `from_bytes_lenient`,
//! `to_base58`, `from_base58`) and `tari_address/mod.rs` (the sizes and the features flags). No
//! code is taken from it.

use super::base58;

/// Bytes in a dual address without a payment id: `TARI_ADDRESS_INTERNAL_DUAL_SIZE`.
pub const DUAL_LEN: usize = 67;

/// Longest payment id a dual address carries: `MAX_PAYMENT_ID_SIZE`.
pub const MAX_PAYMENT_ID_LEN: usize = 256;

/// Features flag: the address accepts one-sided payments (the form a coinbase can pay).
pub const FEATURE_ONE_SIDED: u8 = 0b001;
/// Features flag: the address accepts interactive payments.
pub const FEATURE_INTERACTIVE: u8 = 0b010;
/// Features flag: a payment id follows the spend key.
pub const FEATURE_PAYMENT_ID: u8 = 0b100;
/// Every bit `TariAddressFeatures::from_bits` accepts.
const FEATURES_ALL: u8 = FEATURE_ONE_SIDED | FEATURE_INTERACTIVE | FEATURE_PAYMENT_ID;

/// The DammSum reduction mask `1 + x + x^3 + x^4` (`0x1b`): `COEFFICIENTS = [4, 3, 1]` plus the
/// constant term.
const DAMM_MASK: u8 = 0x1b;

/// Tari's one-byte DammSum: for each byte, add it (xor), then double in GF(2^8) modulo
/// [`DAMM_MASK`].
pub fn dammsum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| {
        let r = acc ^ b;
        let doubled = r << 1;
        if r & 0x80 != 0 {
            doubled ^ DAMM_MASK
        } else {
            doubled
        }
    })
}

/// The 67 address bytes of a dual address without a payment id, checksum included.
pub fn dual_bytes(network: u8, features: u8, view: &[u8; 32], spend: &[u8; 32]) -> [u8; DUAL_LEN] {
    let mut out = [0u8; DUAL_LEN];
    out[0] = network;
    out[1] = features;
    out[2..34].copy_from_slice(view);
    out[34..66].copy_from_slice(spend);
    out[66] = dammsum(&out[..66]);
    out
}

/// The base58 text form of address bytes: three separately encoded parts.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = base58::encode(&bytes[..1]);
    s.push_str(&base58::encode(&bytes[1..2]));
    s.push_str(&base58::encode(&bytes[2..]));
    s
}

/// The address bytes of a base58 text form, when they have a dual address's layout: a length of
/// 67 to 323 bytes, a zero DammSum, features that are only known flags, and a payment id only
/// when the features say so. `None` otherwise. The network byte is returned as found, and the keys
/// are not checked to be valid Ristretto255 points: that needs curve arithmetic.
///
/// The input is bounded by [`base58::MAX_INPUT_LEN`], so an address with a payment id longer than
/// about 25 bytes is not decoded.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    if !s.is_ascii() || s.len() < 3 {
        return None;
    }
    let mut bytes = base58::decode(&s[..1])?;
    bytes.extend(base58::decode(&s[1..2])?);
    bytes.extend(base58::decode(&s[2..])?);
    if !(DUAL_LEN..=DUAL_LEN + MAX_PAYMENT_ID_LEN).contains(&bytes.len()) || dammsum(&bytes) != 0 {
        return None;
    }
    let features = bytes[1];
    if features & !FEATURES_ALL != 0 {
        return None;
    }
    if bytes.len() > DUAL_LEN && features & FEATURE_PAYMENT_ID == 0 {
        return None;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid DammSum string checksums to zero, and any single-byte change is caught.
    #[test]
    fn dammsum_detects_every_single_byte_change() {
        let mut data = *b"forager tari dammsum";
        let sum = dammsum(&data);
        let mut full = data.to_vec();
        full.push(sum);
        assert_eq!(dammsum(&full), 0);
        for i in 0..data.len() {
            for delta in 1..=255u8 {
                data[i] ^= delta;
                assert_ne!(dammsum(&data), sum);
                data[i] ^= delta;
            }
        }
    }

    #[test]
    fn single_bytes_encode_to_one_character() {
        assert_eq!(base58::encode(&[0]), "1");
        for b in 1..=FEATURES_ALL {
            assert_eq!(base58::encode(&[b]).len(), 1);
        }
    }
}
