use bip0039::Mnemonic;
use libsecp256k1::{PublicKey, SecretKey};
use tiny_hderive::bip32::ExtendedPrivKey;
use tiny_hderive::bip44::ChildNumber;
use tiny_keccak::{Hasher, Keccak};
use std::str::FromStr;

#[inline(always)]
pub fn keccak_hash(public_key: PublicKey, output: &mut [u8; 32]) {
    let input = &public_key.serialize()[1..65];
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(output);
}

#[inline(always)]
pub fn generate_eth_address(mnemonic: &Mnemonic) -> (Vec<u8>, PublicKey) {
    let seed = mnemonic.to_seed("");

    let hdwallet = ExtendedPrivKey::derive(&seed, "m/44'/60'/0'/0").unwrap();
    let account0 = hdwallet.child(ChildNumber::from_str("0").unwrap()).unwrap();

    let secret_key = SecretKey::parse(&account0.secret());
    let secret_key = match secret_key {
        Ok(sk) => sk,
        Err(_) => panic!("Failed to parse secret key"),
    };

    let public_key = PublicKey::from_secret_key(&secret_key);

    (account0.secret().to_vec(), public_key)
}