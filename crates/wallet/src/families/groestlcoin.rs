//! Groestlcoin (GRS): Bitcoin's SegWit v0 and P2PKH constructions with one primitive replaced.
//!
//! HASH160 and bech32 are Bitcoin's, so the default `grs1q…` address is [`super::segwitv0`] under
//! the HRP `grs`. Groestlcoin changed base58check itself: its checksum is
//! `Groestl512(Groestl512(payload))[..4]`, not double SHA-256, so the legacy `F…` address and the
//! WIF both go through [`base58::encode_check_groestl`]. Source:
//! `Groestlcoin/groestlcoin@17a57752c63bef11f316d57477f981ca6af79740` `src/base58.cpp` (L148,
//! L162), `src/groestlcoin.h` (`HashForAddress`), `src/groestlcoin-hash.cpp` and
//! `src/kernel/chainparams.cpp` (L176-L182 mainnet, L267-L273 testnet).

use crate::coins::{
    GROESTLCOIN_HRP, GROESTLCOIN_HRP_TESTNET, GROESTLCOIN_P2PKH_VERSION,
    GROESTLCOIN_P2PKH_VERSION_TESTNET, GROESTLCOIN_WIF, GROESTLCOIN_WIF_TESTNET,
};
use crate::{codec::base58, curves::secp256k1, hash};

/// The payout address for `d`: bech32 P2WPKH by default, the Groestl-checksummed P2PKH form when
/// `legacy` is set. Both hash the compressed public key.
pub(crate) fn address(d: &secp256k1::Secret, testnet: bool, legacy: bool) -> String {
    if legacy {
        address_p2pkh(&secp256k1::pubkey_compressed(d), testnet)
    } else {
        let hrp = if testnet {
            GROESTLCOIN_HRP_TESTNET
        } else {
            GROESTLCOIN_HRP
        };
        super::segwitv0::address(d, hrp)
    }
}

/// `base58check_groestl(version ‖ HASH160(pubkey))` for an already-serialised public key: the
/// shared tail of [`address`] and of the BIP44 derivation in [`crate::hd`].
pub(crate) fn address_p2pkh(pubkey: &[u8], testnet: bool) -> String {
    let version = if testnet {
        GROESTLCOIN_P2PKH_VERSION_TESTNET
    } else {
        GROESTLCOIN_P2PKH_VERSION
    };
    let mut payload = Vec::with_capacity(21);
    payload.push(version);
    payload.extend_from_slice(&hash::hash160(pubkey));
    base58::encode_check_groestl(&payload)
}

/// The compressed-key WIF, `base58check_groestl(wif ‖ key ‖ 0x01)`, the form Groestlcoin Core's
/// `importprivkey` and Electrum-GRS read.
pub(crate) fn wif(secret: &[u8; 32], testnet: bool) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.push(if testnet {
        GROESTLCOIN_WIF_TESTNET
    } else {
        GROESTLCOIN_WIF
    });
    payload.extend_from_slice(secret);
    payload.push(0x01);
    base58::encode_check_groestl(&payload)
}

/// Decode a Groestlcoin WIF (mainnet or testnet byte, compressed or not) to its 32-byte key.
///
/// `None` for anything else, a Bitcoin WIF included: its SHA256d checksum fails the Groestl one.
pub(crate) fn from_wif(s: &str) -> Option<[u8; 32]> {
    let payload = base58::decode_check_groestl(s.trim())?;
    if ![GROESTLCOIN_WIF, GROESTLCOIN_WIF_TESTNET].contains(payload.first()?) {
        return None;
    }
    let key = match payload.len() {
        34 if payload[33] == 0x01 => &payload[1..33],
        33 => &payload[1..33],
        _ => return None,
    };
    key.try_into().ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{address, from_wif, wif};
    use crate::curves::secp256k1::secret_from_hex;
    use crate::hexbytes::hex32;

    /// `(private key, WIF, P2PKH, P2WPKH)` on mainnet, from the `groestlcoinjs-lib` fixtures
    /// (`test/fixtures/ecpair.json`, `address.json`, `p2wpkh.json`), reproduced by Rust `groestl`
    /// and by the C `groestlcoin_hash` module behind a from-scratch Python oracle.
    pub(crate) const MAINNET: [(&str, &str, &str, &str); 2] = [
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sX6ptSt",
            "Ffqz14cyvZYJavD76t6oHNDJnGiWcZMVxR",
            "grs1qw508d6qejxtdg4y5r3zarvary0c5xw7k3k4sj5",
        ),
        (
            "2bfe58ab6d9fd575bdc3a624e4825dd2b375d64ac033fbc46ea79dbab4f69a3e",
            "KxhEDBQyyEFymvfJD96q8stMbJMbZUb6D1PmXqBWZDU2WvavoGbp",
            "Fqkb79441DFz6Tj95CkATJP9qYAwPic4Ps",
            "grs1qu89g059an9axesxp23ke8narm5g0t9vxd5uetv",
        ),
    ];

    /// The same two keys on testnet (version 111, WIF 239, HRP `tgrs`), from the Python oracle.
    pub(crate) const TESTNET: [(&str, &str, &str, &str); 2] = [
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcdXxF3p",
            "mrCDrCybB6J1vRfbwM5hemdJz73FuCDVWf",
            "tgrs1qw508d6qejxtdg4y5r3zarvary0c5xw7kxykep7",
        ),
        (
            "2bfe58ab6d9fd575bdc3a624e4825dd2b375d64ac033fbc46ea79dbab4f69a3e",
            "cP4Dg6QqQHxEwN8ZbYuxWCPRDXf1DvgnH3YEeFe24L82mffy6LN8",
            "n26pxHQfFk1hRyBdufj4phoA3NVggDcVNa",
            "tgrs1qu89g059an9axesxp23ke8narm5g0t9vx6xlscx",
        ),
    ];

    #[test]
    fn groestlcoin_vectors_on_both_networks() {
        for (testnet, vectors) in [(false, MAINNET), (true, TESTNET)] {
            for (key, w, p2pkh, p2wpkh) in vectors {
                let d = secret_from_hex(key);
                assert_eq!(address(&d, testnet, false), p2wpkh);
                assert_eq!(address(&d, testnet, true), p2pkh);
                assert_eq!(wif(&hex32(key), testnet), w);
                assert_eq!(from_wif(w), Some(hex32(key)));
            }
        }
    }

    /// A Bitcoin WIF for the same key is not a Groestlcoin WIF: its checksum is SHA256d.
    #[test]
    fn a_bitcoin_wif_is_refused() {
        assert_eq!(
            from_wif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
            None
        );
        assert_eq!(from_wif("Ffqz14cyvZYJavD76t6oHNDJnGiWcZMVxR"), None);
    }
}
