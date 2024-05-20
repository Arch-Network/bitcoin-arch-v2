// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin keys.
//!
//! This module provides keys used in Bitcoin that can be roundtrip
//! (de)serialized.

use crate::util::misc::add_tweak_to_scalar;
use crate::{prelude::*, CryptoError, Parity, Scalar};

use core::fmt::{self, Write};
use core::{ops, str::FromStr};
use k256::elliptic_curve::point::AffineCoordinates as _;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::subtle::Choice;
use k256::schnorr::{
    signature::Verifier as SchnorrVerifier, SigningKey as SchnorrSigningKey,
    VerifyingKey as SchnorrVerifyingKey,
};
use k256::SecretKey;
use once_cell::sync::Lazy;
use subtle::ConditionallySelectable;

use bitcoin_internals::write_err;

use crate::common::constants as common_constants;
use crate::hash_types::{PubkeyHash, WPubkeyHash};
use crate::hashes::{hash160, hex, hex::FromHex, Hash};
use crate::network::constants::Network;
use crate::taproot::{TapNodeHash, TapTweakHash};
use crate::{base58, io};

const GENERATOR_POINT_BYTES: [u8; 65] = [
    0x04, // The DER encoding tag
    //
    // The X coordinate of the generator.
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    //
    // The Y coordinate of the generator.
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
];

static GENERATOR_POINT: Lazy<PublicKey> =
    Lazy::new(|| PublicKey::try_from(&GENERATOR_POINT_BYTES).unwrap());

/// This struct type represents the secp256k1 generator point, and can be
/// used for scalar-point multiplication.
///
/// `G` dereferences as [`PublicKey`], allowing reuse of `PublicKey` methods and traits.
///
/// ```
/// # use bitcoin_arch_v2::G;
/// assert!(G.has_even_y());
/// assert_eq!(
///     G.serialize_uncompressed(),
///     [
///         0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
///         0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
///         0x5b, 0x16, 0xf8, 0x17, 0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d,
///         0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54,
///         0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
///     ]
/// );
/// ```
#[derive(Debug, Default)]
pub struct G;

impl std::ops::Deref for G {
    type Target = PublicKey;
    fn deref(&self) -> &Self::Target {
        &GENERATOR_POINT
    }
}

/// A key-related error.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Base58 encoding error
    Base58(base58::Error),
    /// secp256k1-related error
    Secp256k1(CryptoError),
    /// Invalid key prefix error
    InvalidKeyPrefix(u8),
    /// Hex decoding error
    Hex(hex::Error),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidHexLength(usize),
    InvalidLength(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Base58(ref e) => write_err!(f, "key base58 error"; e),
            Error::Secp256k1(ref e) => write_err!(f, "key secp256k1 error"; e),
            Error::InvalidKeyPrefix(ref b) => write!(f, "key prefix invalid: {}", b),
            Error::Hex(ref e) => write_err!(f, "key hex decoding error"; e),
            Error::InvalidHexLength(got) => write!(
                f,
                "PublicKey hex should be 66 or 130 digits long, got: {}",
                got
            ),
            Error::InvalidLength(got) => {
                write!(f, "slice length should be 33 or 65 bytes, got: {}", got)
            }
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Base58(e) => Some(e),
            Secp256k1(e) => Some(e),
            Hex(e) => Some(e),
            InvalidKeyPrefix(_) | InvalidHexLength(_) | InvalidLength(_) => None,
        }
    }
}

#[doc(hidden)]
impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Error {
        Error::Base58(e)
    }
}

#[doc(hidden)]
impl From<CryptoError> for Error {
    fn from(e: CryptoError) -> Error {
        Error::Secp256k1(e)
    }
}

#[doc(hidden)]
impl From<hex::Error> for Error {
    fn from(e: hex::Error) -> Self {
        Error::Hex(e)
    }
}

/// A Bitcoin ECDSA public key
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Whether this public key should be serialized as compressed
    pub compressed: bool,
    /// The actual ECDSA key
    pub inner: k256::PublicKey,
}

impl PublicKey {
    /// Returns the secp256k1 generator base point `G`.
    pub fn generator() -> PublicKey {
        *GENERATOR_POINT
    }

    /// Constructs a compressed ECDSA public key from the provided generic Secp256k1 public key
    pub fn new(key: impl Into<k256::PublicKey>) -> PublicKey {
        PublicKey {
            compressed: true,
            inner: key.into(),
        }
    }

    /// Constructs uncompressed (legacy) ECDSA public key from the provided generic Secp256k1
    /// public key
    pub fn new_uncompressed(key: impl Into<k256::PublicKey>) -> PublicKey {
        PublicKey {
            compressed: false,
            inner: key.into(),
        }
    }

    /// Serializes the `PublicKey` into compressed DER encoding. This consists of a parity
    /// byte at the beginning, which is either `0x02` (even parity) or `0x03` (odd parity),
    /// followed by the big-endian encoding of the point's X-coordinate.
    pub fn serialize(&self) -> [u8; 33] {
        let encoded_point = self.inner.as_affine().to_encoded_point(true);
        <[u8; 33]>::try_from(encoded_point.as_bytes()).unwrap()
    }

    /// Serializes the `PublicKey` into uncompressed DER encoding. This consists of a static tag
    /// byte `0x04`, followed by the point's  X-coordinate and Y-coordinate encoded sequentially
    /// (X then Y) as big-endian integers.
    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        let encoded_point = self.inner.as_affine().to_encoded_point(false);
        <[u8; 65]>::try_from(encoded_point.as_bytes()).unwrap()
    }

    /// Serializes the public key into BIP340 X-only representation. This consists solely of the
    /// big-endian encoding of the public key's X-coordinate.
    pub fn serialize_xonly(&self) -> [u8; 32] {
        <[u8; 32]>::from(self.inner.as_affine().x())
    }

    fn with_serialized<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        if self.compressed {
            f(&self.serialize())
        } else {
            f(&self.serialize_uncompressed())
        }
    }

    /// Returns bitcoin 160-bit hash of the public key
    pub fn pubkey_hash(&self) -> PubkeyHash {
        self.with_serialized(PubkeyHash::hash)
    }

    /// Returns bitcoin 160-bit hash of the public key for witness program
    pub fn wpubkey_hash(&self) -> Option<WPubkeyHash> {
        if self.compressed {
            Some(WPubkeyHash::from_byte_array(
                hash160::Hash::hash(&self.serialize()).to_byte_array(),
            ))
        } else {
            // We can't create witness pubkey hashes for an uncompressed
            // public keys
            None
        }
    }

    /// Write the public key into a writer
    pub fn write_into<W: io::Write>(&self, mut writer: W) -> Result<(), io::Error> {
        self.with_serialized(|bytes| writer.write_all(bytes))
    }

    /// Read the public key from a reader
    ///
    /// This internally reads the first byte before reading the rest, so
    /// use of a `BufReader` is recommended.
    pub fn read_from<R: io::Read>(mut reader: R) -> Result<Self, io::Error> {
        let mut bytes = [0; 65];

        reader.read_exact(&mut bytes[0..1])?;
        let bytes = if bytes[0] < 4 {
            &mut bytes[..33]
        } else {
            &mut bytes[..65]
        };

        reader.read_exact(&mut bytes[1..])?;
        Self::from_slice(bytes).map_err(|e| {
            // Need a static string for core2
            #[cfg(feature = "std")]
            let reason = e;
            #[cfg(not(feature = "std"))]
            let reason = match e {
                Error::Base58(_) => "base58 error",
                Error::Secp256k1(_) => "secp256k1 error",
                Error::InvalidKeyPrefix(_) => "invalid key prefix",
                Error::Hex(_) => "hex decoding error",
                Error::InvalidHexLength(_) => "invalid hex string length",
            };
            io::Error::new(io::ErrorKind::InvalidData, reason)
        })
    }

    /// Serialize the public key to bytes
    pub fn to_bytes(self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
    }

    /// Returns `subtle::Choice::from(0)` if the point's Y-coordinate is even, or
    /// `subtle::Choice::from(1)` if the Y-coordinate is odd.
    fn parity(&self) -> Choice {
        self.inner.as_affine().y_is_odd()
    }

    /// Serialize the public key into a `SortKey`.
    ///
    /// `SortKey` is not too useful by itself, but it can be used to sort a
    /// `[PublicKey]` slice using `sort_unstable_by_key`, `sort_by_cached_key`,
    /// `sort_by_key`, or any of the other `*_by_key` methods on slice.
    /// Pass the method into the sort method directly. (ie. `PublicKey::to_sort_key`)
    ///
    /// This method of sorting is in line with Bitcoin Core's implementation of
    /// sorting keys for output descriptors such as `sortedmulti()`.
    ///
    /// If every `PublicKey` in the slice is `compressed == true` then this will sort
    /// the keys in a
    /// [BIP67](https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki)
    /// compliant way.
    ///
    /// # Example: Using with `sort_unstable_by_key`
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use bitcoin::PublicKey;
    ///
    /// let pk = |s| PublicKey::from_str(s).unwrap();
    ///
    /// let mut unsorted = [
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc38e98ac269ffe028345c31ac8d0a365f29c8f7e7cfccac72f84e1acd02bc554f35"),
    ///     pk("038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354"),
    ///     pk("028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa"),
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc3816753d96001fd7cba3ce5372f5c9a0d63708183033538d07b1e532fc43aaacfa"),
    ///     pk("032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b"),
    ///     pk("045d753414fa292ea5b8f56e39cfb6a0287b2546231a5cb05c4b14ab4b463d171f5128148985b23eccb1e2905374873b1f09b9487f47afa6b1f2b0083ac8b4f7e8"),
    ///     pk("0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68"),
    /// ];
    /// let sorted = [
    ///     // These first 4 keys are in a BIP67 compatible sorted order
    ///     // (since they are compressed)
    ///     pk("0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68"),
    ///     pk("028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa"),
    ///     pk("032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b"),
    ///     pk("038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354"),
    ///     // Uncompressed keys are not BIP67 compliant, but are sorted
    ///     // after compressed keys in Bitcoin Core using `sortedmulti()`
    ///     pk("045d753414fa292ea5b8f56e39cfb6a0287b2546231a5cb05c4b14ab4b463d171f5128148985b23eccb1e2905374873b1f09b9487f47afa6b1f2b0083ac8b4f7e8"),
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc3816753d96001fd7cba3ce5372f5c9a0d63708183033538d07b1e532fc43aaacfa"),
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc38e98ac269ffe028345c31ac8d0a365f29c8f7e7cfccac72f84e1acd02bc554f35"),
    /// ];
    ///
    /// unsorted.sort_unstable_by_key(|k| PublicKey::to_sort_key(*k));
    ///
    /// assert_eq!(unsorted, sorted);
    /// ```
    pub fn to_sort_key(self) -> SortKey {
        if self.compressed {
            let bytes = self.serialize();
            let mut res = [0; 32];
            res[..].copy_from_slice(&bytes[1..33]);
            SortKey(bytes[0], res, [0; 32])
        } else {
            let bytes = self.serialize_uncompressed();
            let mut res_left = [0; 32];
            let mut res_right = [0; 32];
            res_left[..].copy_from_slice(&bytes[1..33]);
            res_right[..].copy_from_slice(&bytes[33..65]);
            SortKey(bytes[0], res_left, res_right)
        }
    }

    /// Deserialize a public key from a slice
    pub fn from_slice(data: &[u8]) -> Result<PublicKey, Error> {
        let compressed = match data.len() {
            33 => true,
            65 => false,
            len => {
                return Err(base58::Error::InvalidLength(len).into());
            }
        };

        if !compressed && data[0] != 0x04 {
            return Err(Error::InvalidKeyPrefix(data[0]));
        }

        let inner = match k256::PublicKey::from_sec1_bytes(data) {
            Ok(p) => p,
            Err(_) => return Err(Error::Secp256k1(CryptoError::InvalidPublicKey)),
        };

        Ok(PublicKey { compressed, inner })
    }

    /// Computes the public key as supposed to be used with this secret
    pub fn from_private_key(sk: &k256::SecretKey) -> PublicKey {
        let inner = sk.public_key();
        PublicKey::new(inner)
    }

    /// Tweaks the public key with a scalar.
    ///
    /// NB: Will not error if the tweaked public key has an odd value and can't be used for
    ///     BIP 340-342 purposes.
    ///
    /// Returns a String as Error if the tweak is at infinity or zero.
    /// This error type should be changed.
    pub fn add_tweak(self, tweak: Scalar) -> Result<(PublicKey, Parity), String> {
        // T = t * G
        let big_t = tweak * G;
        // P' = P + T
        let tweaked_pubkey = match self + big_t {
            Infinity => {
                return Err(String::from("Tweaked public key is at infinity"));
            }
            Valid(pk) => pk,
        };

        let parity = match tweaked_pubkey.has_odd_y() {
            true => Parity::Odd,
            false => Parity::Even,
        };

        Ok((tweaked_pubkey, parity))
    }

    /// Returns a public key with the same X-coordinate but with the Y-coordinate's parity set
    /// to the given parity, with `subtle::Choice::from(1)` indicating odd parity and
    /// `subtle::Choice::from(0)` indicating even parity.
    pub fn with_parity(self, parity: subtle::Choice) -> Self {
        let inner = {
            let mut affine = self.inner.as_affine().clone();
            let should_negate = affine.y_is_odd() ^ parity;
            affine.conditional_assign(&(-affine), should_negate);
            k256::PublicKey::from_affine(affine).unwrap()
        };
        PublicKey::from(inner)
    }

    pub fn to_odd_y(self) -> Self {
        self.with_parity(subtle::Choice::from(1))
    }

    /// Returns `true` if the point's Y-coordinate is even, or `false` if the Y-coordinate is odd.
    pub fn has_even_y(&self) -> bool {
        bool::from(!self.parity())
    }

    /// Returns `true` if the point's Y-coordinate is odd, or `false` if the Y-coordinate is even.
    pub fn has_odd_y(&self) -> bool {
        bool::from(self.parity())
    }

    /// Checks if a public key was correctly tweaked using the same
    /// tweaked key.
    ///
    /// NB: Will not error if the tweaked public key has an odd value and can't be used for
    ///     BIP 340-342 purposes.
    ///
    /// Returns a String as Error if the tweak is at infinity or zero.
    /// This error type should be changed.
    pub fn tweak_add_check(self, tweaked_key: PublicKey, tweak: Scalar) -> Result<bool, String> {
        // T_original = t * G
        let original_big_t = tweak * G;
        // T_recomputed = P' - P
        let recomputed_big_t = match tweaked_key - self {
            Infinity => {
                return Err(String::from("Tweaked public key is at infinity"));
            }
            Valid(pk) => pk,
        };

        // check that T_original == T_recomputed
        Ok(original_big_t == recomputed_big_t)
    }
}

/// Converts k256 PublicKey to PublicKey
/// Assumes the public key is compressed
impl From<k256::PublicKey> for PublicKey {
    fn from(pubkey: k256::PublicKey) -> Self {
        let inner = pubkey;
        PublicKey::new(inner)
    }
}

/// An opaque return type for PublicKey::to_sort_key
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct SortKey(u8, [u8; 32], [u8; 32]);

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: fast hex encoding
        self.with_serialized(|bytes| {
            for ch in bytes {
                write!(f, "{:02x}", ch)?;
            }
            Ok(())
        })
    }
}

impl FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PublicKey, Error> {
        match s.len() {
            66 => PublicKey::from_slice(&<[u8; 33]>::from_hex(s)?),
            130 => PublicKey::from_slice(&<[u8; 65]>::from_hex(s)?),
            len => Err(Error::InvalidHexLength(len)),
        }
    }
}

impl From<PublicKey> for PubkeyHash {
    fn from(key: PublicKey) -> PubkeyHash {
        key.pubkey_hash()
    }
}

/// This type is effectively the same as [`PublicKey`], except it can also
/// represent the public_key at infinity, exposed as [`MaybePublicKey::Infinity`].
/// This is the special 'zero-public_key', or 'identity element' on the curve
/// for which `MaybePublicKey::Infinity + X = X`  and
/// `MaybePublicKey::Infinity * X = MaybePublicKey::Infinity` for any other public_key `X`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MaybePublicKey {
    /// Represents the public_key at infinity, for which `MaybePublicKey::Infinity + X = X`
    /// and `MaybePublicKey::Infinity * X = MaybePublicKey::Infinity` for any other public_key `X`.
    Infinity,
    /// Represents a valid non-infinity curve public_key.
    Valid(PublicKey),
}

use MaybePublicKey::*;

impl MaybePublicKey {
    /// Serializes the public_key into compressed DER encoding. This consists of a parity
    /// byte at the beginning, which is either `0x02` (even parity) or `0x03` (odd parity),
    /// followed by the big-endian encoding of the public_key's X-coordinate.
    ///
    /// If `self == MaybePublicKey::Infinity`, this returns 33 zero bytes.
    pub fn serialize(&self) -> [u8; 33] {
        match self {
            Valid(public_key) => public_key.serialize(),
            Infinity => [0; 33],
        }
    }

    /// Serializes the public_key into uncompressed DER encoding. This consists of a static tag
    /// byte `0x04`, followed by the public_key's  X-coordinate and Y-coordinate encoded sequentially
    /// (X then Y) as big-endian integers.
    ///
    /// If `self == MaybePublicKey::Infinity`, this returns 65 zero bytes.
    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        match self {
            Valid(public_key) => public_key.serialize_uncompressed(),
            Infinity => [0; 65],
        }
    }

    /// Serializes the public_key into BIP340 X-only representation. This consists solely of the
    /// big-endian encoding of the public_key's X-coordinate.
    ///
    /// If `self == MaybePublicKey::Infinity`, this returns 32 zero bytes.
    pub fn serialize_xonly(&self) -> [u8; 32] {
        match self {
            Valid(public_key) => public_key.serialize_xonly(),
            Infinity => [0; 32],
        }
    }

    /// Returns `subtle::Choice::from(0)` if the public_key's Y-coordinate is even or infinity.
    /// Returns `subtle::Choice::from(1)` if the Y-coordinate is odd.
    pub fn parity(&self) -> Choice {
        match self {
            Infinity => Choice::from(0),
            Valid(p) => p.parity(),
        }
    }

    /// Returns `true` if the public_key's Y-coordinate is even, or `false` if the Y-coordinate is odd.
    /// Also returns true if the public_key is [`Infinity`].
    pub fn has_even_y(&self) -> bool {
        bool::from(!self.parity())
    }

    /// Returns `true` if the public_key's Y-coordinate is odd, or `false` if the Y-coordinate is even.
    /// Returns false if the public_key is [`Infinity`].
    pub fn has_odd_y(&self) -> bool {
        bool::from(self.parity())
    }

    /// Coerces the `MaybePublicKey` into a valid [`PublicKey`]. Panics if `self == MaybePublicKey::Infinity`.
    pub fn unwrap(self) -> PublicKey {
        match self {
            Valid(public_key) => public_key,
            Infinity => panic!("called unwrap on MaybePublicKey::Infinity"),
        }
    }

    /// Returns true if `self == MaybePublicKey::Infinity`.
    pub fn is_infinity(&self) -> bool {
        self == &Infinity
    }

    /// Returns an option which is `None` if `self == MaybePublicKey::Infinity`,
    /// or a `Some(PublicKey)` otherwise.
    pub fn into_option(self) -> Option<PublicKey> {
        Option::from(self)
    }
}

impl Default for MaybePublicKey {
    /// Returns the public key at infinity, which acts as an
    /// identity element in the additive curve group.
    fn default() -> Self {
        MaybePublicKey::Infinity
    }
}

impl From<k256::PublicKey> for MaybePublicKey {
    fn from(pubkey: k256::PublicKey) -> Self {
        MaybePublicKey::Valid(PublicKey::new(pubkey))
    }
}

/// Represents the X coordinates of [`PublicKey`]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct XOnlyPublicKey {
    inner: [u8; 32],
}

impl XOnlyPublicKey {
    /// Gets an [`XOnlyPublicKey`] from [`KeyPair`]
    pub fn from_keypair(keypair: &KeyPair) -> (Self, Parity) {
        let public_key = PublicKey::from(keypair);
        let x_only_public_key = Self::from(public_key);
        let parity =
            Parity::from_u8(public_key.parity().unwrap_u8()).expect("u8 parity should be valid");
        (x_only_public_key, parity)
    }

    /// Serializes [`XOnlyPublicKey`] to a 32 byte u8 array
    pub fn serialize(&self) -> [u8; 32] {
        self.inner.clone()
    }

    /// Tweaks an [`XOnlyPublicKey`] by a [`Scalar`]
    ///
    /// Returns the tweaked key and a [`Parity`]
    pub fn add_tweak(self, tweak: Scalar) -> Result<(XOnlyPublicKey, Parity), String> {
        let public_key = PublicKey::from(self);
        let (tweaked_public_key, parity) = public_key.add_tweak(tweak)?;
        let tweaked_x_only = XOnlyPublicKey::from(tweaked_public_key);
        Ok((tweaked_x_only, parity))
    }

    /// Checks if an [`XOnlyPublicKey`] was tweaked using the passed in tweak
    ///
    /// Performs a subtraction and equates the recomputed tweak with the original tweak
    pub fn tweak_add_check(
        &self,
        tweaked_key: XOnlyPublicKey,
        parity: Parity,
        tweak: Scalar,
    ) -> Result<bool, String> {
        let public_key = PublicKey::from(self);

        // Since [PublicKey::from] always returns an even parity,
        // we check if the original tweak parity was odd and set
        // it back to odd.
        let mut tweaked_public_key = PublicKey::from(tweaked_key);
        if let Parity::Odd = parity {
            tweaked_public_key = tweaked_public_key.to_odd_y();
        };

        public_key.tweak_add_check(tweaked_public_key, tweak)
    }

    /// Converts a slice of length 32 bytes to [XOnlyPublicKey]
    ///
    /// Returns a type of [FromSliceError] if the slice is invalid
    pub fn from_slice(value: &[u8]) -> Result<XOnlyPublicKey, Error> {
        let len = value.len();
        let bytes: [u8; 33] = match value.len() {
            32 => {
                let mut inner = [0u8; common_constants::PUBLIC_KEY_SIZE];
                // picking even parity
                inner[0] = 2;
                for i in 1..inner.len() {
                    inner[i] = value[i - 1];
                }
                inner
            }
            33 => {
                let prefix = value[0];
                if prefix != 2 && prefix != 3 {
                    return Err(Error::InvalidKeyPrefix(prefix));
                }
                value.try_into().expect("should not fail")
            }
            _ => return Err(Error::InvalidLength(len)),
        };

        XOnlyPublicKey::try_from(&bytes)
            .map_err(|_| Error::Secp256k1(CryptoError::InvalidPublicKey))
    }
}

impl fmt::LowerHex for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.inner.as_hex(), f)
    }
}

impl fmt::Display for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&format!("{:?}", &self.inner), f)
    }
}

/// A Bitcoin ECDSA private key
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct PrivateKey {
    /// Whether this private key should be serialized as compressed
    pub compressed: bool,
    /// The network on which this key should be used
    pub network: Network,
    /// The actual ECDSA key
    pub inner: k256::SecretKey,
}

impl PrivateKey {
    /// Constructs compressed ECDSA private key from the provided generic Secp256k1 private key
    /// and the specified network
    pub fn new(key: k256::SecretKey, network: Network) -> PrivateKey {
        PrivateKey {
            compressed: true,
            network,
            inner: key,
        }
    }

    /// Constructs uncompressed (legacy) ECDSA private key from the provided generic Secp256k1
    /// private key and the specified network
    pub fn new_uncompressed(key: k256::SecretKey, network: Network) -> PrivateKey {
        PrivateKey {
            compressed: false,
            network,
            inner: key,
        }
    }

    /// Creates a public key from this private key
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            compressed: self.compressed,
            inner: self.inner.public_key(),
        }
    }

    /// Serialize the private key to bytes
    pub fn to_bytes(self) -> Vec<u8> {
        self.inner.to_bytes()[..].to_vec()
    }

    /// Deserialize a private key from a slice
    pub fn from_slice(data: &[u8], network: Network) -> Result<PrivateKey, Error> {
        let sec_key = k256::SecretKey::from_slice(data)
            .map_err(|_| Error::Secp256k1(CryptoError::InvalidSecretKey))?;
        Ok(PrivateKey::new(sec_key, network))
    }

    /// Format the private key to WIF format.
    pub fn fmt_wif(&self, fmt: &mut dyn fmt::Write) -> fmt::Result {
        let mut ret = [0; 34];
        ret[0] = match self.network {
            Network::Bitcoin => 128,
            Network::Testnet | Network::Signet | Network::Regtest => 239,
        };
        ret[1..33].copy_from_slice(&self.inner.to_bytes()[..]);
        let privkey = if self.compressed {
            ret[33] = 1;
            base58::encode_check(&ret[..])
        } else {
            base58::encode_check(&ret[..33])
        };
        fmt.write_str(&privkey)
    }

    /// Get WIF encoding of this private key.
    pub fn to_wif(self) -> String {
        let mut buf = String::new();
        buf.write_fmt(format_args!("{}", self)).unwrap();
        buf.shrink_to_fit();
        buf
    }

    /// Parse WIF encoded private key.
    pub fn from_wif(wif: &str) -> Result<PrivateKey, Error> {
        let data = base58::decode_check(wif)?;

        let compressed = match data.len() {
            33 => false,
            34 => true,
            _ => {
                return Err(Error::Base58(base58::Error::InvalidLength(data.len())));
            }
        };

        let network = match data[0] {
            128 => Network::Bitcoin,
            239 => Network::Testnet,
            x => {
                return Err(Error::Base58(base58::Error::InvalidAddressVersion(x)));
            }
        };

        Ok(PrivateKey {
            compressed,
            network,
            inner: k256::SecretKey::from_slice(&data[1..33])
                .map_err(|_| Error::Secp256k1(CryptoError::InvalidSecretKey))?,
        })
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_wif(f)
    }
}

#[cfg(not(feature = "std"))]
impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[private key data]")
    }
}

impl FromStr for PrivateKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PrivateKey, Error> {
        PrivateKey::from_wif(s)
    }
}

// impl ops::Index<ops::RangeFull> for PrivateKey {
//     type Output = [u8];
//     fn index(&self, _: ops::RangeFull) -> &[u8] {
//         &self.inner.to_bytes()[..]
//     }
// }

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl serde::Serialize for PrivateKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> serde::Deserialize<'de> for PrivateKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PrivateKey, D::Error> {
        struct WifVisitor;

        impl<'de> serde::de::Visitor<'de> for WifVisitor {
            type Value = PrivateKey;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("an ASCII WIF string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Ok(s) = core::str::from_utf8(v) {
                    PrivateKey::from_str(s).map_err(E::custom)
                } else {
                    Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                PrivateKey::from_str(v).map_err(E::custom)
            }
        }

        d.deserialize_str(WifVisitor)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[allow(clippy::collapsible_else_if)] // Aids readability.
impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            self.with_serialized(|bytes| s.serialize_bytes(bytes))
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> serde::de::Visitor<'de> for HexVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    if let Ok(hex) = core::str::from_utf8(v) {
                        PublicKey::from_str(hex).map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    PublicKey::from_str(v).map_err(E::custom)
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    PublicKey::from_slice(v).map_err(E::custom)
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

/// Untweaked BIP-340 X-coord-only public key
pub type UntweakedPublicKey = XOnlyPublicKey;

/// Tweaked BIP-340 X-coord-only public key
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TweakedPublicKey(XOnlyPublicKey);

impl fmt::LowerHex for TweakedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::Display for TweakedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Untweaked BIP-340 key pair
pub type UntweakedKeypair = KeyPair;

/// Tweaked BIP-340 key pair
///
/// # Examples
/// ```
/// # #[cfg(feature = "rand-std")] {
/// # use bitcoin::key::{KeyPair, TweakedKeyPair, TweakedPublicKey};
/// # use bitcoin::k256::{rand, Secp256k1};
/// # let secp = k256::new();
/// # let keypair = TweakedKeyPair::dangerous_assume_tweaked(KeyPair::new(&secp, &mut rand::thread_rng()));
/// // There are various conversion methods available to get a tweaked pubkey from a tweaked keypair.
/// let (_pk, _parity) = keypair.public_parts();
/// let _pk  = TweakedPublicKey::from_keypair(keypair);
/// let _pk = TweakedPublicKey::from(keypair);
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TweakedKeyPair(KeyPair);

/// A trait for tweaking BIP340 key types (x-only public keys and key pairs).
pub trait TapTweak {
    /// Tweaked key type with optional auxiliary information
    type TweakedAux;
    /// Tweaked key type
    type TweakedKey;

    /// Tweaks an untweaked key with corresponding public key value and optional script tree merkle
    /// root. For the [`KeyPair`] type this also tweaks the private key in the pair.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked public key
    ///  * P is the internal public key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    /// The tweaked key and its parity.
    fn tap_tweak(self, merkle_root: Option<TapNodeHash>) -> Self::TweakedAux;

    /// Directly converts an [`UntweakedPublicKey`] to a [`TweakedPublicKey`]
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    fn dangerous_assume_tweaked(self) -> Self::TweakedKey;
}

impl TapTweak for UntweakedPublicKey {
    type TweakedAux = (TweakedPublicKey, Parity);
    type TweakedKey = TweakedPublicKey;

    /// Tweaks an untweaked public key with corresponding public key value and optional script tree
    /// merkle root.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked public key
    ///  * P is the internal public key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    /// The tweaked key and its parity.
    fn tap_tweak(self, merkle_root: Option<TapNodeHash>) -> (TweakedPublicKey, Parity) {
        let tweak = TapTweakHash::from_key_and_tweak(self, merkle_root).to_scalar();
        let (output_key, parity) = self.add_tweak(tweak).expect("Tap tweak failed");

        let is_valid = self
            .tweak_add_check(output_key, parity, tweak)
            .expect("checking tweaked public key should not fail");

        debug_assert!(is_valid);
        (TweakedPublicKey(output_key), parity)
    }

    fn dangerous_assume_tweaked(self) -> TweakedPublicKey {
        TweakedPublicKey(self)
    }
}

impl TapTweak for UntweakedKeypair {
    type TweakedAux = TweakedKeyPair;
    type TweakedKey = TweakedKeyPair;

    /// Tweaks private and public keys within an untweaked [`KeyPair`] with corresponding public key
    /// value and optional script tree merkle root.
    ///
    /// This is done by tweaking private key within the pair using the equation q = p + H(P|c), where
    ///  * q is the tweaked private key
    ///  * p is the internal private key
    ///  * H is the hash function
    ///  * c is the commitment data
    /// The public key is generated from a private key by multiplying with generator point, Q = qG.
    ///
    /// # Returns
    /// The tweaked key and its parity.
    fn tap_tweak(self, merkle_root: Option<TapNodeHash>) -> TweakedKeyPair {
        let (pubkey, _parity) = XOnlyPublicKey::from_keypair(&self);
        let tweak = TapTweakHash::from_key_and_tweak(pubkey, merkle_root).to_scalar();
        let tweaked = self.add_xonly_tweak(tweak).expect("Tap tweak failed");
        TweakedKeyPair(tweaked)
    }

    fn dangerous_assume_tweaked(self) -> TweakedKeyPair {
        TweakedKeyPair(self)
    }
}

impl TweakedPublicKey {
    /// Returns the [`TweakedPublicKey`] for `keypair`.
    #[inline]
    pub fn from_keypair(keypair: TweakedKeyPair) -> Self {
        let (xonly, _parity) = keypair.0.x_only_public_key();
        TweakedPublicKey(xonly)
    }

    /// Creates a new [`TweakedPublicKey`] from a [`XOnlyPublicKey`]. No tweak is applied, consider
    /// calling `tap_tweak` on an [`UntweakedPublicKey`] instead of using this constructor.
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    #[inline]
    pub fn dangerous_assume_tweaked(key: XOnlyPublicKey) -> TweakedPublicKey {
        TweakedPublicKey(key)
    }

    /// Returns the underlying public key.
    pub fn to_inner(self) -> XOnlyPublicKey {
        self.0
    }

    /// Serialize the key as a byte-encoded pair of values. In compressed form
    /// the y-coordinate is represented by only a single bit, as x determines
    /// it up to one bit.
    #[inline]
    pub fn serialize(&self) -> [u8; common_constants::SCHNORR_PUBLIC_KEY_SIZE] {
        self.0.serialize()
    }
}

/// KeyPair representation of a Signing and VerifyingKey.
///
/// Composes [`k256::schnorr::SigningKey`]
#[derive(Clone)]
pub struct KeyPair {
    signing_key: SchnorrSigningKey,
}

impl k256::schnorr::signature::Keypair for KeyPair {
    type VerifyingKey = SchnorrVerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.signing_key.verifying_key().clone()
    }
}

impl KeyPair {
    #[cfg(feature = "rand")]
    pub fn new<R: rand_core::CryptoRngCore + Sized>(rng: &mut R) -> Self {
        let signing_key = SigningKey::random(rng);
        let verifying_key = signing_key.verifying_key().clone();
        Self { signing_key }
    }

    /// Returns a [`k256::schnorr::VerifyingKey`] from a [`KeyPair`]
    pub fn verifying_key(&self) -> &SchnorrVerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Gets a [`KeyPair`] from a secret key
    pub fn from_secret_key(sec_key: &SecretKey) -> Self {
        let signing_key = SchnorrSigningKey::from(sec_key);
        Self { signing_key }
    }

    /// Returns the [`XOnlyPublicKey`] (and it's [`Parity`]) for this [`KeyPair`].
    ///
    /// This is equivalent to using [`XOnlyPublicKey::from_keypair`].
    #[inline]
    pub fn x_only_public_key(&self) -> (XOnlyPublicKey, Parity) {
        XOnlyPublicKey::from_keypair(self)
    }

    /// Returns the [`k256::schnorr::SigningKey`] associated with this [`KeyPair`].
    ///
    /// # Warning
    ///
    /// The [`k256::schnorr::SigningKey`] contains secrets so this method should
    /// be used with caution.
    pub fn to_signing_key(self) -> SchnorrSigningKey {
        self.signing_key
    }

    /// Tweaks the [`KeyPair`] with a tweak
    pub fn add_xonly_tweak(self, tweak: Scalar) -> Result<Self, CryptoError> {
        let sec_key = Scalar::from(self.signing_key.as_nonzero_scalar());

        let mut tweaked_scalar_bytes = add_tweak_to_scalar(sec_key, tweak)?.serialize();
        tweaked_scalar_bytes = Scalar::reduce_from(&tweaked_scalar_bytes).serialize();

        let signing_key = match SchnorrSigningKey::from_bytes(&tweaked_scalar_bytes) {
            Ok(s) => s,
            Err(_) => return Err(CryptoError::InvalidTweak),
        };

        Ok(KeyPair { signing_key })
    }

    /// Gets a [`KeyPair`] from a secret key string
    pub fn from_seckey_str(s: &str) -> Result<KeyPair, CryptoError> {
        let mut res = [0u8; common_constants::SECRET_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(common_constants::SECRET_KEY_SIZE) => {
                KeyPair::from_seckey_slice(&res[0..common_constants::SECRET_KEY_SIZE])
            }
            _ => Err(CryptoError::InvalidPublicKey),
        }
    }

    /// Gets a [`KeyPair`] from a secret key slice
    pub fn from_seckey_slice(data: &[u8]) -> Result<KeyPair, CryptoError> {
        Ok(KeyPair::from_secret_key(
            &SecretKey::from_slice(data).map_err(|_| CryptoError::InvalidSecretKey)?,
        ))
    }

    /// Gets a [`k256::SecretKey`] from a [`KeyPair`]
    pub fn secret_key(&self) -> k256::SecretKey {
        k256::SecretKey::from(self.signing_key.as_nonzero_scalar())
    }
}

impl TweakedKeyPair {
    /// Creates a new [`TweakedKeyPair`] from a [`KeyPair`]. No tweak is applied, consider
    /// calling `tap_tweak` on an [`UntweakedKeyPair`] instead of using this constructor.
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    #[inline]
    pub fn dangerous_assume_tweaked(pair: KeyPair) -> TweakedKeyPair {
        TweakedKeyPair(pair)
    }

    /// Returns the underlying key pair.
    #[inline]
    pub fn to_inner(self) -> KeyPair {
        self.0
    }

    /// Returns the [`TweakedPublicKey`] and its [`Parity`] for this [`TweakedKeyPair`].
    #[inline]
    pub fn public_parts(&self) -> (TweakedPublicKey, Parity) {
        let (xonly, parity) = self.0.x_only_public_key();
        (TweakedPublicKey(xonly), parity)
    }
}

impl From<TweakedPublicKey> for XOnlyPublicKey {
    #[inline]
    fn from(pair: TweakedPublicKey) -> Self {
        pair.0
    }
}

impl From<TweakedKeyPair> for KeyPair {
    #[inline]
    fn from(pair: TweakedKeyPair) -> Self {
        pair.0
    }
}

impl From<TweakedKeyPair> for TweakedPublicKey {
    #[inline]
    fn from(pair: TweakedKeyPair) -> Self {
        TweakedPublicKey::from_keypair(pair)
    }
}

/// Utility function used to parse hex into a target u8 buffer. Returns
/// the number of bytes converted or an error if it encounters an invalid
/// character or unexpected end of string.
pub(crate) fn from_hex(hex: &str, target: &mut [u8]) -> Result<usize, ()> {
    if hex.len() % 2 == 1 || hex.len() > target.len() * 2 {
        return Err(());
    }

    let mut b = 0;
    let mut idx = 0;
    for c in hex.bytes() {
        b <<= 4;
        match c {
            b'A'..=b'F' => b |= c - b'A' + 10,
            b'a'..=b'f' => b |= c - b'a' + 10,
            b'0'..=b'9' => b |= c - b'0',
            _ => return Err(()),
        }
        if (idx & 1) == 1 {
            target[idx / 2] = b;
            b = 0;
        }
        idx += 1;
    }
    Ok(idx / 2)
}

mod conversions {
    use super::*;

    mod internal_conversions {
        use crate::crypto::error::InfinityPointError;

        use super::*;

        impl From<MaybePublicKey> for Option<PublicKey> {
            /// Converts the `MaybePublicKey` into an `Option`, returning `None` if
            /// `maybe_point == MaybePublicKey::Infinity` or `Some(p)` if
            /// `maybe_point == MaybePublicKey::Valid(p)`.
            fn from(maybe_point: MaybePublicKey) -> Self {
                match maybe_point {
                    Valid(point) => Some(point),
                    Infinity => None,
                }
            }
        }

        impl From<PublicKey> for MaybePublicKey {
            /// Converts the point into a [`MaybePublicKey::Valid`] instance.
            fn from(point: PublicKey) -> MaybePublicKey {
                MaybePublicKey::Valid(point)
            }
        }

        impl TryFrom<MaybePublicKey> for PublicKey {
            type Error = InfinityPointError;

            /// Converts the `MaybePublicKey` into a `Result<Point, InfinityPointError>`,
            /// returning `Ok(Point)` if the point is a valid non-infinity point,
            /// or `Err(InfinityPointError)` if `maybe_point == MaybePublicKey::Infinity`.
            fn try_from(maybe_point: MaybePublicKey) -> Result<Self, Self::Error> {
                match maybe_point {
                    Valid(point) => Ok(point),
                    Infinity => Err(InfinityPointError),
                }
            }
        }

        impl From<PublicKey> for XOnlyPublicKey {
            fn from(value: PublicKey) -> Self {
                Self::from(value.inner)
            }
        }

        impl From<XOnlyPublicKey> for PublicKey {
            fn from(value: XOnlyPublicKey) -> Self {
                Self::from(&value)
            }
        }

        impl From<&XOnlyPublicKey> for PublicKey {
            fn from(value: &XOnlyPublicKey) -> PublicKey {
                let mut inner = [0u8; common_constants::PUBLIC_KEY_SIZE];
                inner[0] = 2;
                for i in 1..inner.len() {
                    inner[i] = value.inner[i - 1];
                }
                PublicKey::try_from(inner).expect("Improbable that this should fail")
            }
        }
    }

    mod external_conversions {
        use crate::crypto::error::InvalidPointBytes;

        use super::*;

        impl FromStr for XOnlyPublicKey {
            type Err = Error;
            fn from_str(s: &str) -> Result<XOnlyPublicKey, Error> {
                let mut res = [0u8; common_constants::SCHNORR_PUBLIC_KEY_SIZE];
                match from_hex(s, &mut res) {
                    Ok(common_constants::SCHNORR_PUBLIC_KEY_SIZE) => XOnlyPublicKey::from_slice(
                        &res[0..common_constants::SCHNORR_PUBLIC_KEY_SIZE],
                    ),
                    _ => Err(Error::Secp256k1(CryptoError::InvalidPublicKey)),
                }
            }
        }

        impl From<&k256::SecretKey> for KeyPair {
            fn from(value: &k256::SecretKey) -> Self {
                Self {
                    signing_key: SchnorrSigningKey::from(value),
                }
            }
        }

        impl From<k256::PublicKey> for XOnlyPublicKey {
            fn from(value: k256::PublicKey) -> Self {
                let s = value.to_sec1_bytes().to_vec();
                let s = &s[1..];
                XOnlyPublicKey {
                    inner: s.try_into().expect("XOnlyPublicKey should have 32 bytes"),
                }
            }
        }

        /// Converts a KeyPair to a PublicKey
        ///
        /// Assumes the keypair is compressed
        impl From<KeyPair> for PublicKey {
            fn from(value: KeyPair) -> Self {
                Self::from(&value)
            }
        }

        /// Converts a &KeyPair to a PublicKey
        ///
        /// Assumes the keypair is compressed
        impl From<&KeyPair> for PublicKey {
            fn from(value: &KeyPair) -> Self {
                let inner = k256::PublicKey::from(value.verifying_key());
                Self {
                    compressed: true,
                    inner,
                }
            }
        }

        impl From<KeyPair> for XOnlyPublicKey {
            fn from(value: KeyPair) -> Self {
                let public_key = PublicKey::from(value);
                Self::from(public_key)
            }
        }

        impl TryInto<SchnorrVerifyingKey> for PublicKey {
            type Error = String;

            fn try_into(self) -> Result<SchnorrVerifyingKey, Self::Error> {
                SchnorrVerifyingKey::try_from(self.inner)
                    .map_err(|err| format!("cannot convert to VerifyingKey: {:?}", err))
            }
        }

        impl TryInto<SchnorrVerifyingKey> for XOnlyPublicKey {
            type Error = String;

            fn try_into(self) -> Result<SchnorrVerifyingKey, Self::Error> {
                let public_key = PublicKey::from(self);
                public_key.try_into()
            }
        }

        impl TryFrom<&[u8; 65]> for PublicKey {
            type Error = InvalidPointBytes;

            /// Parses an uncompressed DER encoding of a point. See [`PublicKey::serialize_uncompressed`].
            ///
            /// Returns a String as Error, should replace with proper Error.
            fn try_from(bytes: &[u8; 65]) -> Result<Self, Self::Error> {
                Self::try_from(bytes as &[u8])
            }
        }

        impl TryFrom<&[u8; 33]> for PublicKey {
            type Error = InvalidPointBytes;

            /// Parses a compressed DER encoding of a point. See [`PublicKey::serialize`].
            ///
            /// Returns a String as Error, should replace with proper Error.
            fn try_from(bytes: &[u8; 33]) -> Result<Self, Self::Error> {
                Self::try_from(bytes as &[u8])
            }
        }

        impl TryFrom<[u8; 33]> for PublicKey {
            type Error = InvalidPointBytes;

            /// Parses a compressed DER encoding of a point. See [`PublicKey::serialize`].
            ///
            /// Returns a String as Error, should replace with proper Error.
            fn try_from(bytes: [u8; 33]) -> Result<Self, Self::Error> {
                Self::try_from(bytes.as_slice())
            }
        }

        impl TryFrom<&[u8]> for PublicKey {
            type Error = InvalidPointBytes;

            /// Parses a compressed or uncompressed DER encoding of a public key. See
            /// [`PublicKey::serialize`] and [`PublicKey::serialize_uncompressed`]. The slice
            /// length should be either 33 or 65 for compressed and uncompressed
            /// encodings respectively.
            ///
            /// Returns a [`InvalidPointBytes`] if it fails.
            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                let len = bytes.len();
                match k256::PublicKey::from_sec1_bytes(bytes) {
                    Ok(public_key) => match len {
                        33 => Ok(PublicKey::new(public_key)),
                        65 => Ok(PublicKey::new_uncompressed(public_key)),
                        _ => {
                            return Err(InvalidPointBytes);
                        }
                    },
                    Err(_) => {
                        return Err(InvalidPointBytes);
                    }
                }
            }
        }

        impl TryFrom<&[u8; 33]> for XOnlyPublicKey {
            type Error = InvalidPointBytes;

            /// Parses a compressed or uncompressed DER encoding of a public key. See
            /// [`XOnlyPublicKey::serialize`]. The slice length should be 32 bytes.
            ///
            /// Returns a [`InvalidPointBytes`] if it fails.
            fn try_from(bytes: &[u8; 33]) -> Result<Self, Self::Error> {
                // ensure it converts to a SEC1 public key
                let _ = PublicKey::try_from(bytes)?;
                Ok(XOnlyPublicKey {
                    inner: bytes[1..].try_into().expect("should coerce to 32 bytes"),
                })
            }
        }
    }
}

mod std_traits {
    use super::*;

    impl Ord for PublicKey {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            // The `k256` crate implements `Ord` based on uncompressed encoding.
            // To match BIP327, we must sort keys based on their compressed encoding.
            self.inner
                .to_encoded_point(true)
                .cmp(&other.inner.to_encoded_point(true))
        }
    }

    impl PartialOrd for PublicKey {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    /// Need to implement this manually because [`k256::PublicKey`] does not implement `Hash`.
    impl std::hash::Hash for PublicKey {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.serialize().hash(state);
        }
    }

    /// Need to implement this manually because [`k256::schnorr::SigningKey`] does not implement `Hash`.
    impl std::hash::Hash for KeyPair {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.signing_key.to_bytes().hash(state);
        }
    }

    impl PartialEq for KeyPair {
        fn eq(&self, other: &Self) -> bool {
            self.signing_key.to_bytes() == other.signing_key.to_bytes()
        }
    }

    impl Eq for KeyPair {}

    impl Ord for KeyPair {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.signing_key
                .as_nonzero_scalar()
                .cmp(&other.signing_key.as_nonzero_scalar())
        }
    }

    impl PartialOrd for KeyPair {
        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl fmt::Debug for KeyPair {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Keypair")
                .field("signing_key", &self.signing_key.to_bytes())
                .finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use crate::address::Address;
    use crate::hashes::hex::FromHex;
    use crate::io;
    use crate::network::constants::Network::Bitcoin;
    use crate::network::constants::Network::Testnet;

    #[test]
    fn test_key_derivation() {
        // testnet compressed
        let sk =
            PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(sk.network, Testnet);
        assert!(sk.compressed);
        assert_eq!(
            &sk.clone().to_wif(),
            "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy"
        );

        let pk = Address::p2pkh(&sk.public_key(), sk.network);
        assert_eq!(&pk.to_string(), "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx");

        // test string conversion
        assert_eq!(
            &sk.to_string(),
            "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy"
        );
        let sk_str =
            PrivateKey::from_str("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(&sk.to_wif(), &sk_str.to_wif());

        // mainnet uncompressed
        let sk =
            PrivateKey::from_wif("5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3").unwrap();
        assert_eq!(sk.network, Bitcoin);
        assert!(!sk.compressed);
        assert_eq!(
            &sk.clone().to_wif(),
            "5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3"
        );

        let mut pk = sk.public_key();
        assert!(!pk.compressed);
        assert_eq!(&pk.to_string(), "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133");
        assert_eq!(pk, PublicKey::from_str("042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133").unwrap());
        let addr = Address::p2pkh(&pk, sk.network);
        assert_eq!(&addr.to_string(), "1GhQvF6dL8xa6wBxLnWmHcQsurx9RxiMc8");
        pk.compressed = true;
        assert_eq!(
            &pk.to_string(),
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        );
        assert_eq!(
            pk,
            PublicKey::from_str(
                "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_pubkey_hash() {
        let pk = PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();
        let upk = PublicKey::from_str("042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133").unwrap();
        assert_eq!(
            pk.pubkey_hash().to_string(),
            "9511aa27ef39bbfa4e4f3dd15f4d66ea57f475b4"
        );
        assert_eq!(
            upk.pubkey_hash().to_string(),
            "ac2e7daf42d2c97418fd9f78af2de552bb9c6a7a"
        );
    }

    #[test]
    fn test_wpubkey_hash() {
        let pk = PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();
        let upk = PublicKey::from_str("042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133").unwrap();
        assert_eq!(
            pk.wpubkey_hash().unwrap().to_string(),
            "9511aa27ef39bbfa4e4f3dd15f4d66ea57f475b4"
        );
        assert_eq!(upk.wpubkey_hash(), None);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_key_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        static KEY_WIF: &str = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
        static PK_STR: &str = "039b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef";
        static PK_STR_U: &str = "\
            04\
            9b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef\
            87288ed73ce47fc4f5c79d19ebfa57da7cff3aff6e819e4ee971d86b5e61875d\
        ";
        static PK_BYTES: [u8; 33] = [
            0x03, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82, 0x6d, 0xc6, 0x1c,
            0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32,
            0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        static PK_BYTES_U: [u8; 65] = [
            0x04, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82, 0x6d, 0xc6, 0x1c,
            0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32,
            0x5a, 0x0f, 0x46, 0x79, 0xef, 0x87, 0x28, 0x8e, 0xd7, 0x3c, 0xe4, 0x7f, 0xc4, 0xf5,
            0xc7, 0x9d, 0x19, 0xeb, 0xfa, 0x57, 0xda, 0x7c, 0xff, 0x3a, 0xff, 0x6e, 0x81, 0x9e,
            0x4e, 0xe9, 0x71, 0xd8, 0x6b, 0x5e, 0x61, 0x87, 0x5d,
        ];

        let s = k256::new();
        let sk = PrivateKey::from_str(KEY_WIF).unwrap();
        let pk = PublicKey::from_private_key(&s, &sk);
        let pk_u = PublicKey {
            inner: pk.inner,
            compressed: false,
        };

        assert_tokens(&sk, &[Token::BorrowedStr(KEY_WIF)]);
        assert_tokens(&pk.compact(), &[Token::BorrowedBytes(&PK_BYTES[..])]);
        assert_tokens(&pk.readable(), &[Token::BorrowedStr(PK_STR)]);
        assert_tokens(&pk_u.compact(), &[Token::BorrowedBytes(&PK_BYTES_U[..])]);
        assert_tokens(&pk_u.readable(), &[Token::BorrowedStr(PK_STR_U)]);
    }

    fn random_key(mut seed: u8) -> PublicKey {
        loop {
            let mut data = [0; 65];
            for byte in &mut data[..] {
                *byte = seed;
                // totally a rng
                seed = seed.wrapping_mul(41).wrapping_add(43);
            }
            if data[0] % 2 == 0 {
                data[0] = 4;
                if let Ok(key) = PublicKey::from_slice(&data[..]) {
                    return key;
                }
            } else {
                data[0] = 2 + (data[0] >> 7);
                if let Ok(key) = PublicKey::from_slice(&data[..33]) {
                    return key;
                }
            }
        }
    }

    #[test]
    fn pubkey_read_write() {
        const N_KEYS: usize = 20;
        let keys: Vec<_> = (0..N_KEYS).map(|i| random_key(i as u8)).collect();

        let mut v = vec![];
        for k in &keys {
            k.write_into(&mut v).expect("writing into vec");
        }

        let mut dec_keys = vec![];
        let mut cursor = io::Cursor::new(&v);
        for _ in 0..N_KEYS {
            dec_keys.push(PublicKey::read_from(&mut cursor).expect("reading from vec"));
        }

        assert_eq!(keys, dec_keys);

        // sanity checks
        assert!(PublicKey::read_from(&mut cursor).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[0; 33][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[2; 32][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[0; 65][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[4; 64][..])).is_err());
    }

    #[test]
    fn pubkey_to_sort_key() {
        let key1 = PublicKey::from_str(
            "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
        )
        .unwrap();
        let key2 = PublicKey {
            inner: key1.inner,
            compressed: false,
        };
        let expected1 = SortKey(
            2,
            <[u8; 32]>::from_hex(
                "ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
            )
            .unwrap(),
            [0_u8; 32],
        );
        let expected2 = SortKey(
            4,
            <[u8; 32]>::from_hex(
                "ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
            )
            .unwrap(),
            <[u8; 32]>::from_hex(
                "1794e7f3d5e420641a3bc690067df5541470c966cbca8c694bf39aa16d836918",
            )
            .unwrap(),
        );
        assert_eq!(key1.to_sort_key(), expected1);
        assert_eq!(key2.to_sort_key(), expected2);
    }

    #[test]
    fn pubkey_sort() {
        struct Vector {
            input: Vec<PublicKey>,
            expect: Vec<PublicKey>,
        }
        let fmt = |v: Vec<_>| {
            v.into_iter()
                .map(|s| PublicKey::from_str(s).unwrap())
                .collect::<Vec<_>>()
        };
        let vectors = vec![
            // Start BIP67 vectors
            // Vector 1
            Vector {
                input: fmt(vec![
                    "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
                    "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f",
                ]),
                expect: fmt(vec![
                    "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f",
                    "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
                ]),
            },
            // Vector 2 (Already sorted, no action required)
            Vector {
                input: fmt(vec![
                    "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
                    "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
                    "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404",
                ]),
                expect: fmt(vec![
                    "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
                    "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
                    "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404",
                ]),
            },
            // Vector 3
            Vector {
                input: fmt(vec![
                    "030000000000000000000000000000000000004141414141414141414141414141",
                    "020000000000000000000000000000000000004141414141414141414141414141",
                    "020000000000000000000000000000000000004141414141414141414141414140",
                    "030000000000000000000000000000000000004141414141414141414141414140",
                ]),
                expect: fmt(vec![
                    "020000000000000000000000000000000000004141414141414141414141414140",
                    "020000000000000000000000000000000000004141414141414141414141414141",
                    "030000000000000000000000000000000000004141414141414141414141414140",
                    "030000000000000000000000000000000000004141414141414141414141414141",
                ]),
            },
            // Vector 4: (from bitcore)
            Vector {
                input: fmt(vec![
                    "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
                    "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
                    "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18",
                ]),
                expect: fmt(vec![
                    "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18",
                    "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
                    "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
                ]),
            },
            // Non-BIP67 vectors
            Vector {
                input: fmt(vec![
                    "02c690d642c1310f3a1ababad94e3930e4023c930ea472e7f37f660fe485263b88",
                    "0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68",
                    "041a181bd0e79974bd7ca552e09fc42ba9c3d5dbb3753741d6f0ab3015dbfd9a22d6b001a32f5f51ac6f2c0f35e73a6a62f59e848fa854d3d21f3f231594eeaa46",
                    "032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b",
                    "04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc3816753d96001fd7cba3ce5372f5c9a0d63708183033538d07b1e532fc43aaacfa",
                    "028e1c947c8c0b8ed021088b8e981491ac7af2b8fabebea1abdb448424c8ed75b7",
                    "045d753414fa292ea5b8f56e39cfb6a0287b2546231a5cb05c4b14ab4b463d171f5128148985b23eccb1e2905374873b1f09b9487f47afa6b1f2b0083ac8b4f7e8",
                    "03004a8a3d242d7957c0b60fb7208d386fa6a0193aabd1f3f095ffd0ac097e447b",
                    "04eb0db2d71ccbb0edd8fb35092cbcae2f7fa1f06d4c170804bf52007924b569a8d2d6f6bc8fd2b3caa3253fa1bb674443743bf7fb9f94f9c0b0831a252894cfa8",
                    "04516cde23e14f2319423b7a4a7ae48b1dadceb5e9c123198d417d10895684c42eb05e210f90ccbc72448803a22312e3f122ff2939956ccef4f7316f836295ddd5",
                    "038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354",
                    "04c6bec3b07586a4b085a78cbb97e9bab6f1d3c9ebf299b65dec85213c5eacd44487de86017183120bb7ea3b6c6660c5037615fe1add2a73f800cbeeae22c60438",
                    "03e1a1cfa9eaff604ae237b7af31ffe4c01be22eb96f3da0e62c5850dd4b4386c1",
                    "028d3a2d9f1b1c5c75845944f93bc183ba23aecde53f1978b8aa1b77661be6114f",
                    "028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa",
                    "04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc38e98ac269ffe028345c31ac8d0a365f29c8f7e7cfccac72f84e1acd02bc554f35",
                ]),
                expect: fmt(vec![
                    "0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68",
                    "028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa",
                    "028d3a2d9f1b1c5c75845944f93bc183ba23aecde53f1978b8aa1b77661be6114f",
                    "028e1c947c8c0b8ed021088b8e981491ac7af2b8fabebea1abdb448424c8ed75b7",
                    "02c690d642c1310f3a1ababad94e3930e4023c930ea472e7f37f660fe485263b88",
                    "03004a8a3d242d7957c0b60fb7208d386fa6a0193aabd1f3f095ffd0ac097e447b",
                    "032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b",
                    "038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354",
                    "03e1a1cfa9eaff604ae237b7af31ffe4c01be22eb96f3da0e62c5850dd4b4386c1",
                    "041a181bd0e79974bd7ca552e09fc42ba9c3d5dbb3753741d6f0ab3015dbfd9a22d6b001a32f5f51ac6f2c0f35e73a6a62f59e848fa854d3d21f3f231594eeaa46",
                    "04516cde23e14f2319423b7a4a7ae48b1dadceb5e9c123198d417d10895684c42eb05e210f90ccbc72448803a22312e3f122ff2939956ccef4f7316f836295ddd5",
                    "045d753414fa292ea5b8f56e39cfb6a0287b2546231a5cb05c4b14ab4b463d171f5128148985b23eccb1e2905374873b1f09b9487f47afa6b1f2b0083ac8b4f7e8",
                    // These two pubkeys are mirrored. This helps verify the sort past the x value.
                    "04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc3816753d96001fd7cba3ce5372f5c9a0d63708183033538d07b1e532fc43aaacfa",
                    "04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc38e98ac269ffe028345c31ac8d0a365f29c8f7e7cfccac72f84e1acd02bc554f35",
                    "04c6bec3b07586a4b085a78cbb97e9bab6f1d3c9ebf299b65dec85213c5eacd44487de86017183120bb7ea3b6c6660c5037615fe1add2a73f800cbeeae22c60438",
                    "04eb0db2d71ccbb0edd8fb35092cbcae2f7fa1f06d4c170804bf52007924b569a8d2d6f6bc8fd2b3caa3253fa1bb674443743bf7fb9f94f9c0b0831a252894cfa8",
                ]),
            },
        ];
        for mut vector in vectors {
            vector
                .input
                .sort_by_cached_key(|k| PublicKey::to_sort_key(*k));
            assert_eq!(vector.input, vector.expect);
        }
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn public_key_constructors() {
        use crate::k256::rand;

        let secp = k256::new();
        let kp = KeyPair::new(&secp, &mut rand::thread_rng());

        let _ = PublicKey::new(kp);
        let _ = PublicKey::new_uncompressed(kp);
    }

    #[test]
    fn public_key_from_str_wrong_length() {
        // Sanity checks, we accept string length 130 digits.
        let s = "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133";
        assert_eq!(s.len(), 130);
        assert!(PublicKey::from_str(s).is_ok());
        // And 66 digits.
        let s = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";
        assert_eq!(s.len(), 66);
        assert!(PublicKey::from_str(s).is_ok());

        let s = "aoeusthb";
        assert_eq!(s.len(), 8);
        let res = PublicKey::from_str(s);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::InvalidHexLength(8));
    }
}
