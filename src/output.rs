use sequoia_openpgp::armor::{Kind, Writer};
use sequoia_openpgp::packet::key::{SecretParts, SubordinateRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::serialize::Marshal;
use sequoia_openpgp::{Cert, Packet};
use std::io::Write;

/// Takes a `sequoia_openpgp` Cert, extracts all keys, and prints their ASCII-armored representation.
///
/// # Arguments
///
/// * `cert` - The Cert whose keys you wish to print.
pub fn print_keys(cert: &Cert) {
    for key in cert.keys() {
        let key = Key::<SecretParts, SubordinateRole>::from(
            key.key().clone().parts_into_secret().unwrap(),
        );
        let fingerprint = key.fingerprint();
        let algo = key.pk_algo();
        let key_packet = Packet::SecretSubkey(key);
        let mut writer = Writer::new(vec![], Kind::SecretKey).unwrap();
        key_packet.serialize(&mut writer).unwrap();
        let key_armored = writer.finalize().unwrap();
        print!(
            "\n\n\nKey ID {} ({}): \n\n{}",
            fingerprint,
            algo.to_string(),
            String::from_utf8(key_armored).unwrap()
        );
    }
}

/// Given a revocation Signature, applies ASCII-armor and prints it to the screen.
///
/// # Arguments
///
/// * `revocation` - The revocation Signature you wish to print.
pub fn print_revocation(revocation: &Signature) {
    let mut writer = Writer::new(vec![], Kind::Signature).unwrap();
    revocation.serialize(&mut writer).unwrap();
    let revocation_armored = writer.finalize().unwrap();
    println!("{}", String::from_utf8(revocation_armored).unwrap());
}

/// Given a valid `OpenPGP` certificate, applies ASCII-armor and prints its private and public
/// components to the screen.
///
/// # Arguments
///
/// * `cert` - The Cert you wish to print.
pub fn print_cert(cert: &Cert) {
    // finally, we can do stuff. for instance, lets get the ascii armored primary private key
    let mut private_armored: Vec<u8> = vec![];
    cert.as_tsk()
        .armored()
        .serialize(&mut private_armored)
        .unwrap();
    private_armored.flush().unwrap();
    println!("{}", String::from_utf8(private_armored).unwrap());

    // and now its public component
    let mut public_armored: Vec<u8> = vec![];
    cert.armored().serialize(&mut public_armored).unwrap();
    public_armored.flush().unwrap();
    println!("{}", String::from_utf8(public_armored).unwrap());
}
