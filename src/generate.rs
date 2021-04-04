use std::time::SystemTime;

use nettle::curve25519::private_key as cv25519_private_key;
use nettle::ed25519::private_key as ed25519_private_key;
use nettle::random::Yarrow;
use nettle::rsa::generate_keypair as rsa_generate_keypair;
use sequoia_openpgp::cert::CertRevocationBuilder;
use sequoia_openpgp::crypto::KeyPair;
use sequoia_openpgp::packet::key::{Key4, PrimaryRole, SecretParts, SubordinateRole};
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::packet::{signature, Key, Signature};
use sequoia_openpgp::types::{
    Features, HashAlgorithm, KeyFlags, ReasonForRevocation, SignatureType, SymmetricAlgorithm,
};
use sequoia_openpgp::{Cert, Packet};
use sha2::{Digest, Sha512};

use crate::{get_secret_phrase, get_userid, get_key_creation_time};

/// Given a salt, applies it to the global secret phrase and uses it as a seed value to generate a
/// Ed25519 key.
///
/// # Arguments
///
/// * `salt` - The salt you wish to have applied to the global secret.
pub fn ed25519_key_from_seed(salt: &str) -> Key<SecretParts, SubordinateRole> {
    let mut secret_phrase: String = get_secret_phrase();
    secret_phrase.push_str(salt);
    let key_from_seed = ed25519_private_key(&mut Yarrow::from_seed(&*Sha512::digest(
        secret_phrase.as_bytes(),
    )));
    Key::from(
        Key4::<SecretParts, SubordinateRole>::import_secret_ed25519(
            &*key_from_seed,
            get_key_creation_time(),
        )
        .unwrap(),
    )
}

/// Given a salt, applies it to the global secret phrase and uses it as a seed value to generate a
/// Cv25519 key.
///
/// # Arguments
///
/// * `salt` - The salt you wish to have applied to the global secret.
pub fn cv25519_key_from_seed(salt: &str) -> Key<SecretParts, SubordinateRole> {
    let mut secret_phrase: String = get_secret_phrase();
    secret_phrase.push_str(salt);
    let key_from_seed = cv25519_private_key(&mut Yarrow::from_seed(&*Sha512::digest(
        secret_phrase.as_bytes(),
    )));
    Key::from(
        Key4::<SecretParts, SubordinateRole>::import_secret_cv25519(
            &*key_from_seed,
            None,
            None,
            get_key_creation_time(),
        )
        .unwrap(),
    )
}

/// Given a salt, applies it to the global secret phrase and uses it as a seed value to generate an
/// RSA key.
///
/// # Arguments
///
/// * `salt` - The salt you wish to have applied to the global secret.
pub fn rsa_key_from_seed(salt: &str) -> Key<SecretParts, SubordinateRole> {
    let mut secret_phrase: String = get_secret_phrase();
    secret_phrase.push_str(salt);
    let (_rsa_public, rsa_secret) = rsa_generate_keypair(
        &mut Yarrow::from_seed(&*Sha512::digest(secret_phrase.as_bytes())),
        4096,
    )
    .unwrap();
    Key::from(
        Key4::<SecretParts, SubordinateRole>::import_secret_rsa(
            &rsa_secret.d(),
            &rsa_secret.primes().0,
            &rsa_secret.primes().1,
            get_key_creation_time(),
        )
        .unwrap(),
    )
}

/// Generates and signs subordinate keys, for the Cert. Creates a separate key for signing,
/// authentication, and two for encryption (RSA and ECDH). Each key is generated with a salt that is
/// applied to the main secret.
///
/// # Arguments
///
/// * `cert` - The Cert you wish to have the subordinate keys attached to.
pub fn signed_subkeys(mut cert: Cert) -> Cert {
    let primary_key: Key<SecretParts, PrimaryRole> = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap();
    let mut primary_keypair: KeyPair = primary_key.clone().into_keypair().unwrap();
    let salts = ["sign", "authenticate", "encrypt_ed", "encrypt_rsa"];
    for (i, salt) in salts.iter().enumerate() {
        let mut subkey = ed25519_key_from_seed(salt.to_owned());
        let key_flags: KeyFlags;
        match i {
            0 => key_flags = KeyFlags::empty().set_signing(),
            1 => key_flags = KeyFlags::empty().set_authentication(),
            2 => {
                subkey = cv25519_key_from_seed(salt.to_owned());
                key_flags = KeyFlags::empty()
                    .set_transport_encryption()
                    .set_storage_encryption();
            }
            3 => {
                subkey = rsa_key_from_seed(salt.to_owned());
                key_flags = KeyFlags::empty()
                    .set_transport_encryption()
                    .set_storage_encryption();
            }
            _ => key_flags = KeyFlags::empty(),
        }
        let mut subkey_kp = subkey
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let mut subkey_sb = signature::SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_hash_algo(HashAlgorithm::SHA512)
            .set_features(Features::sequoia())
            .unwrap()
            .set_key_flags(key_flags.clone())
            .unwrap();
        // .set_key_validity_period(blueprint.validity.or(self.primary.validity))?;
        if key_flags == KeyFlags::empty().set_signing() {
            let backsig = signature::SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                // GnuPG wants at least a 512-bit hash for P521 keys.
                .set_hash_algo(HashAlgorithm::SHA512)
                .sign_primary_key_binding(&mut subkey_kp, &primary_key, &subkey)
                .unwrap();
            subkey_sb = subkey_sb.set_embedded_signature(backsig).unwrap();
        }
        let subkey_s = subkey_sb
            .sign_subkey_binding(&mut primary_keypair, None, &subkey)
            .unwrap();
        cert = cert
            .insert_packets(vec![Packet::from(subkey), Packet::from(subkey_s)])
            .unwrap();
    }
    cert
}

/// Generates and signs a primary key, returning both the key Packet and Signature.
pub fn signed_primary_key() -> (Vec<Packet>, Signature) {
    let mut sequoia_packets: Vec<Packet> = vec![];

    let secret_phrase: String = get_secret_phrase();

    let key_from_seed = ed25519_private_key(&mut Yarrow::from_seed(&*Sha512::digest(
        secret_phrase.as_bytes(),
    )));
    let primary_key = Key::from(
        Key4::<SecretParts, PrimaryRole>::import_secret_ed25519(
            &*key_from_seed,
            get_key_creation_time(),
        )
        .unwrap(),
    );
    let mut primary_keypair = primary_key.clone().into_keypair().unwrap();
    let primary_key_sb = signature::SignatureBuilder::new(SignatureType::DirectKey)
        .set_hash_algo(HashAlgorithm::SHA512)
        .set_features(Features::sequoia())
        .unwrap()
        .set_key_flags(KeyFlags::empty().set_certification().set_signing())
        .unwrap()
        .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])
        .unwrap()
        .set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ])
        .unwrap();
    sequoia_packets.push(Packet::from(primary_key.clone()));
    (
        sequoia_packets,
        primary_key_sb
            .sign_direct_key(&mut primary_keypair, primary_key.parts_as_public())
            .unwrap(),
    )
}

/// Given a `Cert` and its corresponding `SignatureBuilder`, signs the `UserID` associated with it.
///
/// # Arguments
///
/// * `cert` - The `Cert` whose `UserID` you wish to sign.
/// * `cert_sb` - The `SignatureBuilder` associated with the `Cert`.
pub fn sign_cert_uid(cert: Cert, cert_sb: SignatureBuilder) -> Cert {
    let current_time = SystemTime::now();
    let mut primary_keypair: KeyPair = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();
    let uid_sb = cert_sb
        .set_signature_creation_time(current_time)
        .unwrap()
        .set_type(SignatureType::PositiveCertification)
        .set_hash_algo(HashAlgorithm::SHA512)
        .set_primary_userid(true)
        .unwrap();
    let uid_s = get_userid()
        .bind(&mut primary_keypair, &cert, uid_sb)
        .unwrap();
    cert.insert_packets(vec![Packet::Signature(uid_s)]).unwrap()
}

/// Generates a valid `OpenPGP`[ certificate and corresponding revocation signature.
pub fn cert_and_revoc() -> (Cert, Signature) {
    let (mut pgp_packets, sig) = signed_primary_key();
    pgp_packets.push(sig.clone().into());
    pgp_packets.push(get_userid().into());
    let mut pgp_cert = Cert::from_packets(pgp_packets.into_iter()).unwrap();
    let sig = signature::SignatureBuilder::from(sig)
        .set_revocation_key(vec![])
        .unwrap();
    pgp_cert = signed_subkeys(pgp_cert);
    pgp_cert = sign_cert_uid(pgp_cert, sig);
    let revocation = CertRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::Unspecified, b"Unspecified")
        .unwrap()
        .build(
            &mut pgp_cert
                .primary_key()
                .key()
                .clone()
                .parts_into_secret()
                .unwrap()
                .into_keypair()
                .unwrap(),
            &pgp_cert,
            None,
        )
        .unwrap();
    (pgp_cert, revocation)
}
