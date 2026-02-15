use std::str::FromStr;

use bitcoin::bip32::DerivationPath;
use trezor_client::{protos::NostrTag, utils::convert_path};

fn do_main() -> Result<(), trezor_client::Error> {
    let mut trezor = trezor_client::unique(false)?;
    trezor.init_device(None)?;

    // Nostr derivation path from NIP-06
    let path = convert_path(&DerivationPath::from_str("m/44'/1237'/0'/0/0").unwrap());

    // Get pubkey
    let pubkey = trezor.nostr_get_pubkey(path.clone())?;
    println!("nostr pubkey: {}", hex::encode(&pubkey));

    // Sign an event
    let mut tag = NostrTag::new();
    tag.set_key("t".to_owned());
    tag.set_value("test".to_owned());

    let sig = trezor.nostr_sign_event(
        path,
        1234567890,
        1,
        vec![tag],
        "Hello Nostr from Trezor!".to_owned(),
    )?;

    println!("event id: {}", hex::encode(&sig.id));
    println!("event pubkey: {}", hex::encode(&sig.pubkey));
    println!("event signature: {}", hex::encode(&sig.signature));

    Ok(())
}

fn main() {
    do_main().unwrap()
}
