//! Quai: an Ethereum address that must also land in the right shard and ledger.
//!
//! The key and the address are Ethereum's: `Keccak256(pubkey[1..])[12..]` with the EIP-55 case
//! checksum ([`super::ethereum`]). Quai reads the first two bytes as routing. Byte 0 is the
//! location, region in the high nibble and zone in the low one, and bit 7 of byte 1 selects the
//! ledger: clear for Quai (account), set for Qi (UTXO). A Cyprus1 pool pays a Cyprus1 Quai-ledger
//! address only, so that is the only scope minted here ([`crate::coins::quai_payout_scope`]).
//! Source: `dominant-strategies/go-quai@6561a9f89a027fb5b76fbe75ecf48ffe93c8370d`
//! `common/address.go` (`AddressBytes.Location`, `IsInQuaiLedgerScope`), and quais.js
//! `@87e02f08` `src/wallet/utils.ts` (`isValidAddressForZone`) and `src/wallet/bip44/bip44.ts`
//! (`deriveNextAddressNode`).

use crate::{coins::quai_payout_scope, curves::secp256k1, hash::keccak256};

/// The 20 address bytes of `d`: Ethereum's derivation.
fn address_bytes(d: &secp256k1::Secret) -> [u8; 20] {
    let pk = secp256k1::pubkey_uncompressed(d);
    let mut out = [0u8; 20];
    out.copy_from_slice(&keccak256(&pk[1..])[12..]);
    out
}

/// The EIP-55 address of `d`, `Ok` when it is in Cyprus1 and the Quai ledger, else `Err` carrying
/// the out-of-scope address so the caller can name it.
pub(crate) fn address(d: &secp256k1::Secret) -> Result<String, String> {
    let bytes = address_bytes(d);
    let addr = format!(
        "0x{}",
        super::ethereum::eip55(&crate::hexbytes::encode(&bytes))
    );
    if quai_payout_scope(&bytes) {
        Ok(addr)
    } else {
        Err(addr)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::address;
    use crate::curves::secp256k1::secret_from_hex;

    /// The quais.js vector: `QuaiHDWallet.fromMnemonic("abandon … about").getNextAddress(0,
    /// Zone.Cyprus1)` returns index 139 with this private key and address, and `new
    /// Wallet(privateKey).address` agrees.
    pub(crate) const VECTOR_KEY: &str =
        "1fc6218883bef255c4a260ad754511db8ffa0fd9053c8ccfd7f9675682fc9233";
    pub(crate) const VECTOR_ADDRESS: &str = "0x000B2E36297c1b133Ca1DCA9881Dc820018f1F79";

    #[test]
    fn the_quais_vector_is_in_scope_and_key_one_is_not() {
        assert_eq!(
            address(&secret_from_hex(VECTOR_KEY)),
            Ok(VECTOR_ADDRESS.into())
        );
        // Ethereum's private-key-1 address opens 0x7e: zone 0x7e is no Quai zone at all.
        assert_eq!(
            address(&secret_from_hex("01")),
            Err("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf".into())
        );
    }
}
