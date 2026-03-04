use trezor_client::client::handle_interaction;

fn do_main() -> Result<(), trezor_client::Error> {
    let mut trezor = trezor_client::unique(false)?;
    trezor.init_device(None)?;

    // Set the commit hash on the device.
    let commit_hash =
        hex::decode("5fdba3602b41c19312862dc6c4aec0ca7aa5f45fe00ad310bbbb58bd139a48dc")
            .unwrap();
    handle_interaction(trezor.git_commit_update(commit_hash)?)?;
    println!("GitCommitUpdate: OK");

    // Verify a blob from that commit via its Merkle path.
    let commit = b"tree 7a3a25665e2743820a77a53956a56db312225b146c9f92ec821c98841acb79c6\n\
        author Roman Zeyde <roman.zeyde@satoshilabs.com> 1746850908 +0300\n\
        committer Roman Zeyde <roman.zeyde@satoshilabs.com> 1746850908 +0300\n\
        \n\
        init\n"
        .to_vec();

    let tree: Vec<u8> = [
        b"100644 FooBar\x00" as &[u8],
        &hex::decode("33b04182f3897fe7bad77bfeca53d2c9149d8b5dc44a8d09abf821257314db13")
            .unwrap(),
    ]
    .concat();

    let blob = b"13Hbso8zgV5Wmqn3uA7h3QVtmPzs47wcJ7\n".to_vec();

    handle_interaction(trezor.git_verify(
        commit,
        vec![tree],
        vec!["FooBar".to_string()],
        blob,
    )?)?;
    println!("GitVerify: OK");

    Ok(())
}

fn main() {
    do_main().unwrap()
}
