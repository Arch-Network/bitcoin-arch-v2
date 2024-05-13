use k256::{PublicKey as k256PublicKey, SecretKey};

use crate::{CryptoError, MaybePublicKey, PublicKey, Scalar, G};

/// Tweaks a [`SecretKey`] by adding `tweak` modulo the curve order.
///
/// # Errors
///
/// Returns an error if the resulting key would be invalid.
pub fn add_tweak(sk: SecretKey, tweak: Scalar) -> Result<SecretKey, CryptoError> {
    let sec_key = Scalar::from(sk);
    add_tweak_to_scalar(sec_key, tweak)?.to_secret_key()
}

pub fn add_tweak_to_scalar(s: Scalar, mut tweak: Scalar) -> Result<Scalar, CryptoError> {
    if s.greater_than_curve_order_minus_one() {
        eprintln!("Secret key must not be greater than SECP256k1 curve order");
        return Err(CryptoError::InvalidSecretKey);
    }

    if tweak.greater_than_curve_order_minus_one() {
        tweak = Scalar::reduce_from(&tweak.serialize());
    }

    // x' = (x + t) % CURVE_ORDER
    let tweaked_scalar = s + tweak;
    if tweaked_scalar.is_zero() {
        panic!(
            "The summed scalar is zero, this means either the secret key or the tweak is invalid"
        );
    }

    Ok(tweaked_scalar.unwrap())
}

/// Tweaks a [`PublicKey`] by adding `tweak * G` modulo the curve order.
///
/// # Errors
///
/// Returns an error if the resulting key would be invalid.
pub fn add_exp_tweak(pk: k256PublicKey, tweak: Scalar) -> Result<PublicKey, CryptoError> {
    let pub_key = match PublicKey::from_slice(&pk.to_sec1_bytes()) {
        Ok(p) => p,
        Err(_) => return Err(CryptoError::InvalidPublicKey),
    };

    // T = t * G
    let big_t = tweak * G;

    // P' = P + T
    let tweaked_pubkey = match pub_key + big_t {
        MaybePublicKey::Infinity => {
            eprintln!("Tweaked public key is at infinity");
            return Err(CryptoError::InvalidTweak);
        }
        MaybePublicKey::Valid(pk) => pk,
    };

    // Ok((tweaked_pubkey, parity))
    Ok(tweaked_pubkey)
}
