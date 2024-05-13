use k256::SecretKey;
use once_cell::sync::Lazy;
use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

use crate::{
    crypto::{
        key::PublicKey,
        utils::{ct_slice_lex_cmp, xor_arrays},
    },
    CryptoError,
};

/// The largest possible 256-bit integer, represented as a byte array.
const MAX_U256: [u8; 32] = [0xFF; 32];

/// Represents an elliptic curve scalar value which might be zero.
/// Supports all the same constant-time arithmetic operators supported
/// by [`Scalar`].
///
/// `MaybeScalar` should only be used in cases where it is possible for
/// an input to be zero. In all possible cases, using [`Scalar`] is more
/// appropriate. The output of arithmetic operations with non-zero `Scalar`s
/// can result in a `MaybeScalar` - for example, adding two scalars together
/// linearly.
///
/// ```
/// use secp::{MaybeScalar, Scalar};
///
/// let maybe_scalar: MaybeScalar = Scalar::one() + Scalar::one();
/// ```
///
/// This is because the two scalars might represent values which are additive
/// inverses of each other (i.e. `x + (-x)`), so the output of their addition
/// can result in zero, which must be checked for by the caller where
/// appropriate.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MaybeScalar {
    /// Represents the zero form of a scalar
    Zero,
    /// Represents a non-zero scalar. Composes [`Scalar`]
    Valid(Scalar),
}

use MaybeScalar::*;

use super::error::{InvalidScalarBytes, ZeroScalarError};

impl MaybeScalar {
    /// Returns a valid `MaybeScalar` with a value of 1.
    pub fn one() -> MaybeScalar {
        Valid(Scalar::one())
    }

    /// Returns a valid `MaybeScalar` with a value of two.
    pub fn two() -> MaybeScalar {
        Valid(Scalar::two())
    }

    /// Returns half of the curve order `n`, specifically `n >> 1`.
    pub fn half_order() -> MaybeScalar {
        Valid(Scalar::half_order())
    }

    /// Returns a valid `MaybeScalar` with the maximum possible value less
    /// than the curve order, `n - 1`.
    pub fn max() -> MaybeScalar {
        Valid(Scalar::max())
    }

    /// Returns true if this scalar represents zero.
    pub fn is_zero(&self) -> bool {
        self == &Zero
    }

    /// Serializes the scalar to a big-endian byte array representation.
    ///
    /// # Warning
    ///
    /// Use cautiously. Non-constant time operations on these bytes
    /// could reveal secret key material.
    pub fn serialize(&self) -> [u8; 32] {
        match self {
            Valid(scalar) => scalar.serialize(),
            Zero => [0; 32],
        }
    }

    /// Returns an option which is `None` if `self == MaybeScalar::Zero`,
    /// or a `Some(Scalar)` otherwise.
    pub fn into_option(self) -> Option<Scalar> {
        Option::from(self)
    }

    /// Converts the `MaybeScalar` into a `Result<Scalar, String>`,
    /// returning `Ok(Scalar)` if the scalar is a valid non-zero number, or
    /// `Err(ZeroScalarError)` if `maybe_scalar == MaybeScalar::Zero`.
    pub fn not_zero(self) -> Result<Scalar, ZeroScalarError> {
        Scalar::try_from(self)
    }

    /// Parses a non-zero scalar in the range `[0, n)` from a given byte slice,
    /// which must be exactly 32-byte long and must represent the scalar in
    /// big-endian format.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, InvalidScalarBytes> {
        Scalar::try_from(bytes)
            .map(MaybeScalar::Valid)
            .or_else(|e| {
                if bool::from(bytes.ct_eq(&[0; 32])) {
                    Ok(MaybeScalar::Zero)
                } else {
                    Err(e)
                }
            })
    }

    /// Coerces the `MaybeScalar` into a [`Scalar`]. Panics if `self == MaybeScalar::Zero`.
    pub fn unwrap(self) -> Scalar {
        match self {
            Valid(point) => point,
            Zero => panic!("called unwrap on MaybeScalar::Zero"),
        }
    }

    /// This impl is a courtesy of the secp crate.
    ///
    /// Converts a 32-byte array into a `MaybeScalar` by interpreting it as
    /// a big-endian integer `z` and reducing `z` modulo some given `modulus`
    /// in constant time. This modulus must less than or equal to the secp256k1
    /// curve order `n`.
    ///
    /// Unfortunately libsecp256k1 does not expose this functionality, so we have done
    /// our best to reimplement modular reduction in constant time using only scalar
    /// arithmetic on numbers in the  range `[0, n)`.
    ///
    /// Instead of taking the remainder `z % modulus` directly (which we can't do with
    /// libsecp256k1), we use XOR to compute the relative distances from `z` and `modulus`
    /// to some independent constant, specifically `MAX_U256`. We denote the distances as:
    ///
    /// - `q = MAX_U256 - z` and
    /// - `r = MAX_U256 - modulus`
    ///
    /// As long as both distances are guaranteed to be smaller than the curve order `n`, this
    /// gives us a way to compute `z % modulus` safely in constant time: by computing the
    /// difference of the two relative distances:
    ///
    /// ```notrust
    /// r - q = (MAX_U256 - modulus) - (MAX_U256 - z)
    ///       = z - modulus
    /// ```
    ///
    /// The above is only needed when `z` might be greater than the `modulus`. If instead
    /// `z < modulus`, we set `q = z` and return `q` in constant time, throwing away the
    /// result of subtracting `r - q`.
    fn reduce_from_internal(z_bytes: &[u8; 32], modulus: &[u8; 32]) -> MaybeScalar {
        // Modulus must be less than or equal to `n`, as `n-1` is the largest number we can represent.
        debug_assert!(modulus <= &CURVE_ORDER_BYTES);

        let modulus_neg_bytes = xor_arrays(&modulus, &MAX_U256);

        // Modulus must not be too small either, or we won't be able
        // to represent the distance to MAX_U256.
        debug_assert!(modulus_neg_bytes <= CURVE_ORDER_BYTES);

        // Although we cannot operate arithmetically on numbers larger than `n-1`, we can
        // still use XOR to subtract from a number represented by all one-bits, such as
        // MAX_U256.
        let z_bytes_neg = xor_arrays(z_bytes, &MAX_U256);

        let z_needs_reduction = ct_slice_lex_cmp(z_bytes, modulus).ct_gt(&std::cmp::Ordering::Less);

        let q_bytes = <[u8; 32]>::conditional_select(
            z_bytes,      // `z < modulus`; set `q = z`
            &z_bytes_neg, // `z >= modulus`; set `q = MAX_U256 - z` (implies q <= modulus)
            z_needs_reduction,
        );

        // By this point, we know for sure that `q_bytes` represents an integer less than `n`,
        // so `try_from` should always work here.
        let q = MaybeScalar::try_from(&q_bytes).unwrap();

        // Modulus distance `r` should also always be less than the curve order.
        let r = MaybeScalar::try_from(&modulus_neg_bytes).unwrap();

        // if z < modulus
        //   return q = z
        //
        // else
        //  return r - q = (MAX_U256 - modulus) - (MAX_U256 - z)
        //               = MAX_U256 - modulus - MAX_U256 + z
        //               = z - modulus
        MaybeScalar::conditional_select(&q, &(r - q), z_needs_reduction)
    }
}

impl From<k256::NonZeroScalar> for MaybeScalar {
    fn from(nz_scalar: k256::NonZeroScalar) -> Self {
        MaybeScalar::from(Scalar::from(nz_scalar))
    }
}

impl From<Scalar> for MaybeScalar {
    /// Converts the scalar into a [`MaybeScalar::Valid`] instance.
    fn from(scalar: Scalar) -> Self {
        MaybeScalar::Valid(scalar)
    }
}

static SCALAR_ONE: Lazy<Scalar> = Lazy::new(|| {
    Scalar::try_from(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1u8,
    ])
    .unwrap()
});

static SCALAR_TWO: Lazy<Scalar> = Lazy::new(|| {
    Scalar::try_from(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2u8,
    ])
    .unwrap()
});

static SCALAR_HALF_ORDER: Lazy<Scalar> = Lazy::new(|| {
    Scalar::try_from(&[
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0u8,
    ])
    .unwrap()
});

static SCALAR_MAX: Lazy<Scalar> =
    Lazy::new(|| Scalar::try_from(&CURVE_ORDER_MINUS_ONE_BYTES).unwrap());

/// This is a big-endian representation of the secp256k1 curve order `n`.
const CURVE_ORDER_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// This is a big-endian representation of the secp256k1 curve order `n` minus one.
const CURVE_ORDER_MINUS_ONE_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
];

/// Represents a Non-zero scalar.
/// Composes [`k256::NonZeroScalar`]
#[derive(Copy, Clone)]
pub struct Scalar {
    pub(crate) inner: k256::NonZeroScalar,
}

impl Scalar {
    /// Returns a valid `Scalar` with a value of 1.
    pub fn one() -> Scalar {
        *SCALAR_ONE
    }

    /// Returns a valid `Scalar` with a value of two.
    pub fn two() -> Scalar {
        *SCALAR_TWO
    }

    /// Returns half of the curve order `n`, specifically `n >> 1`.
    pub fn half_order() -> Scalar {
        *SCALAR_HALF_ORDER
    }

    /// Returns a valid `Scalar` with the maximum possible value less
    /// than the curve order, `n - 1`.
    pub fn max() -> Scalar {
        *SCALAR_MAX
    }

    /// Generates a new random scalar from the given CSPRNG.
    #[cfg(feature = "rand")]
    pub fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Scalar {
        let inner = k256::NonZeroScalar::random(rng);
        Scalar::from(inner)
    }

    /// Serializes the scalar to a big-endian byte array representation.
    ///
    /// # Warning
    ///
    /// Use cautiously. Non-constant time operations on these bytes
    /// could reveal secret key material.
    pub fn serialize(&self) -> [u8; 32] {
        return self.inner.to_bytes().into();
    }

    /// Parses a non-zero scalar in the range `[1, n)` from a given byte slice,
    /// which must be exactly 32-byte long and must represent the scalar in
    /// big-endian format.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, InvalidScalarBytes> {
        let inner = k256::NonZeroScalar::try_from(bytes).map_err(|_| InvalidScalarBytes)?;
        Ok(Scalar::from(inner))
    }

    /// Multiplies the secp256k1 base point by this scalar. This is how
    /// public keys (points) are derived from private keys (scalars).
    /// Since this scalar is non-zero, the point derived from base-point
    /// multiplication is also guaranteed to be valid.
    ///
    /// Assumes the public key is compressed
    pub fn base_point_mul(&self) -> PublicKey {
        let inner = k256::PublicKey::from_secret_scalar(&self.inner);
        PublicKey::new(inner)
    }

    /// Checks if the scalar is greater than the SECP256k1 curve - 1
    pub fn greater_than_curve_order_minus_one(&self) -> bool {
        bool::from(self.ct_gt(&Self::max()))
    }

    /// Converts this scalar to a [`k256::SecretKey`]
    pub fn to_secret_key(self) -> Result<SecretKey, CryptoError> {
        k256::SecretKey::from_slice(&self.serialize()).map_err(|_| CryptoError::InvalidSecretKey)
    }

    /// Converts a 32-byte array into a `Scalar` by interpreting it as a big-endian
    /// integer `z` and returning `(z % (n-1)) + 1`, where `n` is the secp256k1
    /// curve order. This always returns a valid non-zero scalar in the range `[1, n)`.
    /// All operations are constant-time, except if `z` works out to be zero.
    ///
    /// The probability that `z_bytes` represents an integer `z` larger than the
    /// curve order is only about 1 in 2^128, but nonetheless this function makes a
    /// best-effort attempt to parse all inputs in constant time and reduce them to
    /// an integer in the range `[1, n)`.
    pub fn reduce_from(z_bytes: &[u8; 32]) -> Self {
        let reduced = MaybeScalar::reduce_from_internal(z_bytes, &CURVE_ORDER_MINUS_ONE_BYTES);

        // this will never be zero, because `z` is in the range `[0, n-1)`
        (reduced + Scalar::one()).unwrap()
    }
}

mod conversions {
    use super::*;

    mod internal_conversions {
        use crate::crypto::error::ZeroScalarError;

        use super::*;

        impl TryFrom<MaybeScalar> for Scalar {
            type Error = ZeroScalarError;

            /// Converts the `MaybeScalar` into a `Result<Scalar, ZeroScalarError>`,
            /// returning `Ok(Scalar)` if the scalar is a valid non-zero number,
            /// or `Err(ZeroScalarError)` if `maybe_scalar == MaybeScalar::Zero`.
            fn try_from(maybe_scalar: MaybeScalar) -> Result<Self, Self::Error> {
                match maybe_scalar {
                    Valid(scalar) => Ok(scalar),
                    Zero => Err(ZeroScalarError),
                }
            }
        }

        impl From<MaybeScalar> for Option<Scalar> {
            /// Converts [`MaybeScalar::Zero`] into `None` and a valid [`Scalar`] into `Some`.
            fn from(maybe_scalar: MaybeScalar) -> Self {
                match maybe_scalar {
                    Valid(scalar) => Some(scalar),
                    Zero => None,
                }
            }
        }

        impl TryFrom<&[u8]> for MaybeScalar {
            type Error = InvalidScalarBytes;

            /// Attempts to parse a 32-byte slice as a scalar in the range `[0, n)`
            /// in constant time, where `n` is the curve order. Timing information
            /// may be leaked if `bytes` is all zeros or not the right length.
            ///
            /// Returns [`InvalidScalarBytes`] if the integer represented by the bytes
            /// is greater than or equal to the curve order, or if `bytes.len() != 32`.
            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                Self::from_slice(bytes)
            }
        }

        impl TryFrom<&[u8; 32]> for MaybeScalar {
            type Error = InvalidScalarBytes;

            /// Attempts to parse a 32-byte array as a scalar in the range `[0, n)`
            /// in constant time, where `n` is the curve order. Timing information
            /// may be leaked if `bytes` is the zero array, but then that's not a
            /// very secret value, is it?
            ///
            /// Returns [`InvalidScalarBytes`] if the integer represented by the bytes
            /// is greater than or equal to the curve order.
            fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
                Self::from_slice(bytes as &[u8])
            }
        }
    }

    mod external_conversions {
        use crate::crypto::error::InvalidScalarBytes;

        use super::*;

        impl TryFrom<&[u8]> for Scalar {
            type Error = InvalidScalarBytes;
            /// Attempts to parse a 32-byte slice as a scalar in the range `[1, n)`
            /// in constant time, where `n` is the curve order.
            ///
            /// Returns [`InvalidScalarBytes`] if the integer represented by the bytes
            /// is greater than or equal to the curve order, or if the bytes are all zero.
            ///
            /// Fails if `bytes.len() != 32`.
            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                Self::from_slice(bytes)
            }
        }

        impl TryFrom<&[u8; 32]> for Scalar {
            type Error = InvalidScalarBytes;

            /// Attempts to parse a 32-byte array as a scalar in the range `[1, n)`
            /// in constant time, where `n` is the curve order.
            ///
            /// Returns [`InvalidScalarBytes`] if the integer represented by the bytes
            /// is greater than or equal to the curve order, or if the bytes are all zero.
            fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
                Self::from_slice(bytes as &[u8])
            }
        }

        impl From<k256::SecretKey> for Scalar {
            fn from(value: k256::SecretKey) -> Self {
                Scalar::from(&value)
            }
        }

        impl From<&k256::SecretKey> for Scalar {
            fn from(value: &k256::SecretKey) -> Self {
                Scalar::from(value.to_nonzero_scalar())
            }
        }

        impl From<k256::NonZeroScalar> for Scalar {
            fn from(nz_scalar: k256::NonZeroScalar) -> Self {
                return Scalar { inner: nz_scalar };
            }
        }

        impl From<&k256::NonZeroScalar> for Scalar {
            fn from(nz_scalar: &k256::NonZeroScalar) -> Self {
                return Scalar {
                    inner: nz_scalar.to_owned(),
                };
            }
        }

        impl From<k256::schnorr::SigningKey> for Scalar {
            fn from(value: k256::schnorr::SigningKey) -> Self {
                Scalar::from(value.as_nonzero_scalar().clone())
            }
        }
    }
}

mod subtle_traits {
    use super::*;

    impl ConstantTimeGreater for Scalar {
        /// Compares this scalar against another in constant time.
        /// Returns `subtle::Choice::from(1)` if `self` is strictly
        /// lexicographically greater than `other`.
        #[inline]
        fn ct_gt(&self, other: &Self) -> subtle::Choice {
            ct_slice_lex_cmp(&self.serialize(), &other.serialize())
                .ct_eq(&std::cmp::Ordering::Greater)
        }
    }

    impl ConditionallySelectable for MaybeScalar {
        /// Conditionally selects one of two scalars in constant time. The exception is if
        /// either `a` or `b` are [`MaybeScalar::Zero`], in which case timing information
        /// about this fact may be leaked. No timing information about the value
        /// of a non-zero scalar will be leaked.
        fn conditional_select(&a: &Self, &b: &Self, choice: subtle::Choice) -> Self {
            let a_inner = a
                .into_option()
                .map(|scalar| scalar.inner.as_ref().clone())
                .unwrap_or(k256::Scalar::ZERO);
            let b_inner = b
                .into_option()
                .map(|scalar| scalar.inner.as_ref().clone())
                .unwrap_or(k256::Scalar::ZERO);

            let inner_scalar = k256::Scalar::conditional_select(&a_inner, &b_inner, choice);

            Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::new(inner_scalar))
                .map(MaybeScalar::from)
                .unwrap_or(MaybeScalar::Zero)
        }
    }
}

mod std_traits {
    use super::*;

    /// This implementation was duplicated from the [`secp256k1`] crate, because
    /// [`k256::NonZeroScalar`] doesn't implement `Debug`.
    impl std::fmt::Debug for Scalar {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            use std::hash::Hasher as _;
            const DEBUG_HASH_TAG: &[u8] = &[
                0x66, 0xa6, 0x77, 0x1b, 0x9b, 0x6d, 0xae, 0xa1, 0xb2, 0xee, 0x4e, 0x07, 0x49, 0x4a,
                0xac, 0x87, 0xa9, 0xb8, 0x5b, 0x4b, 0x35, 0x02, 0xaa, 0x6d, 0x0f, 0x79, 0xcb, 0x63,
                0xe6, 0xf8, 0x66, 0x22,
            ]; // =SHA256(b"rust-secp256k1DEBUG");

            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            hasher.write(DEBUG_HASH_TAG);
            hasher.write(DEBUG_HASH_TAG);
            hasher.write(&self.serialize());
            let hash = hasher.finish();

            f.debug_tuple(stringify!(Scalar))
                .field(&format_args!("#{:016x}", hash))
                .finish()
        }
    }

    /// Reimplemented manually, because [`k256::NonZeroScalar`] doesn't implement
    /// `PartialEq`.
    impl PartialEq for Scalar {
        fn eq(&self, rhs: &Self) -> bool {
            self.inner.ct_eq(&rhs.inner).into()
        }
    }

    impl Eq for Scalar {}

    impl Default for MaybeScalar {
        /// Returns [`MaybeScalar::Zero`].
        fn default() -> Self {
            MaybeScalar::Zero
        }
    }
}
