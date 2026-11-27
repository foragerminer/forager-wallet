//! Neural Engine Byte (NEB) address.
//!
//! A wallet is a 32-byte Ed25519 seed (RFC 8032). The public key is the standard RFC 8032 one:
//! `SHA-512(seed)`, lower half clamped, times the base point, compressed. The lock is
//! `BLAKE3(public key)` (plain BLAKE3, 32-byte output). The address is
//! `bech32m("neb", lock)`: bech32m with the BIP350 constant, HRP `neb`, separator `1`, and the 32
//! lock bytes converted 8-to-5 bits with padding. There is **no** witness-version byte in front,
//! so this is not a SegWit address. NEB has one network, so there is no testnet form.
//!
//! Every 32-byte string is a valid seed, all-zero included: the official wallet applies no range
//! check, and neither does this code.
//!
//! Source: `SilasEigen/neb@v1.0.9` (Apache-2.0), `spec/node.md` section 5.2,
//! `node/crates/neb-wallet/src/wallet.rs` and `address.rs`. The official wallet restores a seed
//! with `neb-wallet --wallet wallet.txt import <64-hex>`, then `neb-wallet --wallet wallet.txt
//! address`. The known-answer vectors below were captured from that v1.0.9 binary, built from
//! source. Two of them are RFC 8032 section 7.1 tests 1 and 2, which pins the Ed25519 step
//! independently of the reference.

use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::coins::NEB_HRP;
use crate::curves::ed25519;

/// The RFC 8032 public key of a seed: `compress(clamp(SHA-512(seed)[..32]) * B)`.
pub(crate) fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::digest(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    h.as_mut_slice().zeroize();
    a[0] &= 0xF8;
    a[31] &= 0x7F;
    a[31] |= 0x40;
    let pk = ed25519::scalarmult_base(&a);
    a.zeroize();
    pk
}

/// The lock of a public key: `BLAKE3(public key)`, 32 bytes.
pub(crate) fn lock(public_key: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(public_key).as_bytes()
}

/// The NEB address of a seed: `bech32m("neb", BLAKE3(public key))`, 62 characters.
pub(crate) fn address(seed: &[u8; 32]) -> String {
    let pk = public_key(seed);
    crate::codec::bech32::encode_bech32m_bytes(NEB_HRP, &lock(&pk))
}

/// Parse a seed as 64 hex characters, whitespace ignored. Any 32 bytes are accepted.
pub(crate) fn parse_seed(input: &str) -> Option<[u8; 32]> {
    let mut compact: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let out = crate::hexbytes::decode_n::<32>(&compact);
    compact.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::{address, lock, parse_seed, public_key};
    use crate::hexbytes::{encode as hex, hex32};

    /// `(seed, public key, lock, address)` captured from the official `neb-wallet` v1.0.9. Rows 3
    /// and 4 are RFC 8032 section 7.1 tests 1 and 2.
    const VECTORS: [(&str, &str, &str, &str); 5] = [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
            "51f1365add907c3dcaead8fae90cfe55902638248377b4dd1db501b11554ac46",
            "neb128cnvkkajp7rmjh2mrawjr872kgzvwpysdmmfhgak5qmz92543rqcacfxq",
        ),
        (
            "0100000000000000000000000000000000000000000000000000000000000000",
            "cecc1507dc1ddd7295951c290888f095adb9044d1b73d696e6df065d683bd4fc",
            "444640e1c372df1e3cf6c2b1c09ceaded7d90b4b0ff381e4805cc8b4e8e96e09",
            "neb1g3rypcwrwt03u08kc2cup882mmtajz6tplecreyqtnytf68fdcys8lt0jw",
        ),
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "6c31041268f471609c79f5f2dbcc38e4a4ab2f4d416109a4e09fcf50fd0f0062",
            "neb1dscsgyng73ckp8re7hedhnpcujj2kt6dg9ssnf8qnl84plg0qp3qltgsvu",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "1027e035b26b605dc6d4b78d07dc29660fcc3498b598a2e57c4e6b1b673a1e95",
            "neb1zqn7qddjdds9m3k5k7xs0hpfvc8ucdyckkv29etufe43kee6r62su4aap5",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5",
            "80fa9d5daeb1a03d08b2e0366888564fe88108814709f8d9c05d0b906938ae63",
            "neb1sraf6hdwkxsr6z9juqmx3zzkfl5gzzypguyl3kwqt59eq6fc4e3sypfqm9",
        ),
    ];

    #[test]
    fn neb_reference_vectors() {
        for (seed, pk, lk, addr) in VECTORS {
            let seed = hex32(seed);
            let pub_key = public_key(&seed);
            assert_eq!(hex(&pub_key), pk);
            assert_eq!(hex(&lock(&pub_key)), lk);
            assert_eq!(address(&seed), addr);
            assert_eq!(addr.len(), 62);
        }
    }

    #[test]
    fn seeds_parse_like_the_official_import() {
        let (seed, _, _, _) = VECTORS[2];
        assert_eq!(parse_seed(seed), Some(hex32(seed)));
        let spaced = "9D61B19D EFFD5A60 BA844AF4 92EC2CC4 4449C569 7B326919 703BAC03 1CAE7F60";
        assert_eq!(parse_seed(spaced), Some(hex32(seed)));
        assert_eq!(parse_seed(&seed[..63]), None);
        assert_eq!(parse_seed("not hex"), None);
    }
}
