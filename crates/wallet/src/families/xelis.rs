//! Xelis (XEL) address.
//!
//! `address = bech32(hrp, ':', compressed(s^-1 * H) ‖ 0x00)`, where `s` is the private key, a
//! curve25519 scalar written as 32 little-endian bytes, `H` is the Pedersen blinding generator on
//! Ristretto255, and `0x00` is the "normal address" type tag. The checksum is classic bech32
//! (constant 1), not bech32m, and the separator is `:` rather than BIP173's `1`. The HRP is `xel` on
//! mainnet and `xet` on testnet.
//!
//! Sources, all `xelis-project/xelis-blockchain@db59b5c2` (BSD-3-Clause):
//! `xelis_common/src/crypto/elgamal/key.rs` (`PublicKey::new`: `s.invert() * H`; `PrivateKey`
//! must be non-zero), `xelis_common/src/crypto/elgamal/compressed.rs` (a scalar reads only from
//! its canonical encoding), `xelis_common/src/crypto/proofs/mod.rs` (`H = PC_GENS.B_blinding`),
//! `xelis_common/src/crypto/address.rs` (`Address::as_string`) and
//! `xelis_common/src/crypto/bech32.rs` (`encode`). Xelis builds on a fork of `curve25519-dalek`; the
//! scalar inversion, the point multiplication and the Ristretto compression used here are upstream
//! `curve25519-dalek`'s, and the known-answer vectors below, produced by running the Xelis code,
//! pin the two as agreeing.
//!
//! The 25-word Xelis mnemonic is not implemented. The official wallet restores from the 64-hex key
//! printed here with its `recover_private_key` command (`xelis_wallet/src/main.rs`, which takes
//! exactly 64 characters).

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::Scalar;
use zeroize::Zeroize;

use crate::coins::{XELIS_HRP, XELIS_HRP_TESTNET, XELIS_SEPARATOR};

/// The Pedersen blinding generator `H`, compressed:
/// `hash_from_bytes::<Sha3_512>(RISTRETTO_BASEPOINT_COMPRESSED)` (`bulletproofs`'
/// `PedersenGens::default().B_blinding`, which Xelis uses as `H`). Kept as the published constant so
/// this crate needs no SHA-3. The test `private_key_one_is_h` shows that `s = 1` yields exactly this
/// point, so a wrong constant cannot pass the vectors.
const H_COMPRESSED: [u8; 32] = [
    0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc, 0x65, 0xc3, 0x77, 0xa1, 0x04, 0x8d, 0x74, 0x5f,
    0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd, 0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34,
];

/// `AddressType::Normal`'s tag byte: the key and nothing after it.
const TYPE_NORMAL: u8 = 0x00;

/// The private key as a scalar: `None` unless the bytes are a canonical little-endian encoding
/// (below the group order `l`) and the scalar is not zero. Xelis applies no clamping, and its
/// `PrivateKey::from_scalar` refuses zero.
fn scalar(sk: &[u8; 32]) -> Option<Scalar> {
    let s: Option<Scalar> = Scalar::from_canonical_bytes(*sk).into();
    s.filter(|s| *s != Scalar::ZERO)
}

/// The compressed Ristretto255 public key `s^-1 * H` of a valid private scalar.
fn public_key_of(s: &Scalar) -> [u8; 32] {
    let h = CompressedRistretto(H_COMPRESSED)
        .decompress()
        .expect("H_COMPRESSED is a valid Ristretto255 encoding");
    let mut inv = s.invert();
    let pk = (inv * h).compress().to_bytes();
    inv.zeroize();
    pk
}

/// The compressed public key for a 32-byte private key, or `None` if the key is not a valid Xelis
/// private key (see [`scalar`]).
pub(crate) fn public_key(sk: &[u8; 32]) -> Option<[u8; 32]> {
    let mut s = scalar(sk)?;
    let pk = public_key_of(&s);
    s.zeroize();
    Some(pk)
}

/// The normal Xelis address of a private key: 63 characters, `xel:` on mainnet and `xet:` on
/// testnet. `None` if the key is zero or not canonical.
pub(crate) fn address(sk: &[u8; 32], testnet: bool) -> Option<String> {
    let mut payload = public_key(sk)?.to_vec();
    payload.push(TYPE_NORMAL);
    let hrp = if testnet {
        XELIS_HRP_TESTNET
    } else {
        XELIS_HRP
    };
    Some(crate::codec::bech32::encode_bech32_bytes_with_separator(
        hrp,
        XELIS_SEPARATOR,
        &payload,
    ))
}

/// A private key from 64 uniform bytes, reduced modulo `l`: Xelis's own `Scalar::random`
/// (`from_bytes_mod_order_wide`). `None` for the zero scalar, which the caller redraws.
pub(crate) fn secret_from_wide(wide: &[u8; 64]) -> Option<[u8; 32]> {
    let mut s = Scalar::from_bytes_mod_order_wide(wide);
    let out = (s != Scalar::ZERO).then(|| s.to_bytes());
    s.zeroize();
    out
}

/// Parse a private key as 64 hex characters, whitespace ignored. The bytes are not range-checked
/// here; [`address`] does that.
pub(crate) fn parse_secret_key(input: &str) -> Option<[u8; 32]> {
    let mut compact: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let out = crate::hexbytes::decode_n::<32>(&compact);
    compact.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::{address, public_key, secret_from_wide, H_COMPRESSED};
    use crate::hexbytes::{encode as hex, hex32};

    /// `(private key hex, little-endian; public key; mainnet address; testnet address)`, produced
    /// by running `xelis-project/xelis-blockchain@db59b5c2`'s `PublicKey::new` and
    /// `Address::as_string` on each key.
    const VECTORS: [(&str, &str, &str, &str); 4] = [
        (
            "0100000000000000000000000000000000000000000000000000000000000000",
            "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134",
            "xel:3jfypdzk48ndcewrw7ssfrt5t722prxm0azvhntmgme5qjy8zy6qqckgjqg",
            "xet:3jfypdzk48ndcewrw7ssfrt5t722prxm0azvhntmgme5qjy8zy6qqq9zzvk",
        ),
        (
            "0200000000000000000000000000000000000000000000000000000000000000",
            "f05bc1df2831717c2992d85b57e0cf3d123fd6c254257de5f784be369747b249",
            "xel:7pdurhegx9chc2vjmpd40cx085frl4kz2sjhme0hsjlrd968kfysq434xga",
            "xet:7pdurhegx9chc2vjmpd40cx085frl4kz2sjhme0hsjlrd968kfysqdzlkyr",
        ),
        (
            "1111111111111111111111111111111111111111111111111111111111111101",
            "1685f8ba5b0c7265ef6f4d75f6a95429b3672383fa4fee7b0878b0b182243249",
            "xel:z6zl3wjmp3extmm0f46ld2259xekwgurlf87u7cg0zctrq3yxfysq4mrs2l",
            "xet:z6zl3wjmp3extmm0f46ld2259xekwgurlf87u7cg0zctrq3yxfysqdgfqxp",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e0f",
            "d09cf6c9043985e91e7616759aa8f5401cab18f0ee03f54457b5a8277e8b5b31",
            "xel:6zw0djgy8xz7j8nkze6e4284gqw2kx8sacpl23zhkk5zwl5ttvcsq4kpcqz",
            "xet:6zw0djgy8xz7j8nkze6e4284gqw2kx8sacpl23zhkk5zwl5ttvcsqd9tgvu",
        ),
    ];

    #[test]
    fn xelis_reference_vectors() {
        for (sk, pk, main, test) in VECTORS {
            let sk = hex32(sk);
            assert_eq!(hex(&public_key(&sk).unwrap()), pk);
            assert_eq!(address(&sk, false).unwrap(), main);
            assert_eq!(address(&sk, true).unwrap(), test);
            assert_eq!(main.len(), 63);
        }
    }

    /// `1^-1 * H = H`, so the private key 1 must yield the hard-coded generator itself. This is the
    /// check that `H_COMPRESSED` is the point the reference derives.
    #[test]
    fn private_key_one_is_h() {
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(public_key(&one).unwrap(), H_COMPRESSED);
    }

    /// Zero and any encoding at or above the group order `l` are refused, never reduced.
    #[test]
    fn zero_and_non_canonical_keys_are_refused() {
        assert_eq!(address(&[0u8; 32], false), None);
        // Top byte 0x11 puts the value above l = 2^252 + 27742317777372353535851937790883648493.
        assert_eq!(address(&[0x11; 32], false), None);
        // l itself, little-endian.
        let l = hex32("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        assert_eq!(address(&l, false), None);
        // l - 1 is the largest valid key.
        let mut l_minus_1 = l;
        l_minus_1[0] -= 1;
        assert!(address(&l_minus_1, false).is_some());
    }

    #[test]
    fn wide_reduction_refuses_only_zero() {
        assert_eq!(secret_from_wide(&[0u8; 64]), None);
        let mut wide = [0u8; 64];
        wide[0] = 2;
        assert_eq!(hex(&secret_from_wide(&wide).unwrap()), VECTORS[1].0);
        // A value above l reduces to a canonical key.
        let reduced = secret_from_wide(&[0xff; 64]).unwrap();
        assert!(address(&reduced, false).is_some());
    }
}
