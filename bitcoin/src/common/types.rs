//! This module contains common types.

use core::fmt;
use core::ops::BitXor;
use internals::impl_array_newtype;

/// Represents the parity passed between FFI function calls.
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum Parity {
    /// Even parity.
    Even = 0,
    /// Odd parity.
    Odd = 1,
}

impl Parity {
    /// Converts parity into an integer (byte) value.
    ///
    /// This returns `0` for even parity and `1` for odd parity.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Converts parity into an integer value.
    ///
    /// This returns `0` for even parity and `1` for odd parity.
    pub fn to_i32(self) -> i32 {
        self as i32
    }

    /// Constructs a [`Parity`] from a byte.
    ///
    /// The only allowed values are `0` meaning even parity and `1` meaning odd.
    /// Other values result in error being returned.
    pub fn from_u8(parity: u8) -> Result<Parity, InvalidParityValue> {
        Parity::from_i32(parity.into())
    }

    /// Constructs a [`Parity`] from a signed integer.
    ///
    /// The only allowed values are `0` meaning even parity and `1` meaning odd.
    /// Other values result in error being returned.
    pub fn from_i32(parity: i32) -> Result<Parity, InvalidParityValue> {
        match parity {
            0 => Ok(Parity::Even),
            1 => Ok(Parity::Odd),
            _ => Err(InvalidParityValue(parity)),
        }
    }
}

/// `Even` for `0`, `Odd` for `1`, error for anything else
impl TryFrom<i32> for Parity {
    type Error = InvalidParityValue;

    fn try_from(parity: i32) -> Result<Self, Self::Error> {
        Self::from_i32(parity)
    }
}

/// `Even` for `0`, `Odd` for `1`, error for anything else
impl TryFrom<u8> for Parity {
    type Error = InvalidParityValue;

    fn try_from(parity: u8) -> Result<Self, Self::Error> {
        Self::from_u8(parity)
    }
}

/// The conversion returns `0` for even parity and `1` for odd.
impl From<Parity> for i32 {
    fn from(parity: Parity) -> i32 {
        parity.to_i32()
    }
}

/// The conversion returns `0` for even parity and `1` for odd.
impl From<Parity> for u8 {
    fn from(parity: Parity) -> u8 {
        parity.to_u8()
    }
}

/// Returns even parity if the operands are equal, odd otherwise.
impl BitXor for Parity {
    type Output = Parity;

    fn bitxor(self, rhs: Parity) -> Self::Output {
        // This works because Parity has only two values (i.e. only 1 bit of information).
        if self == rhs {
            Parity::Even // 1^1==0 and 0^0==0
        } else {
            Parity::Odd // 1^0==1 and 0^1==1
        }
    }
}

/// Error returned when conversion from an integer to `Parity` fails.
//
// Note that we don't allow inspecting the value because we may change the type.
// Yes, this comment is intentionally NOT doc comment.
// Too many derives for compatibility with current Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct InvalidParityValue(i32);

impl fmt::Display for InvalidParityValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid value {} for Parity - must be 0 or 1", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidParityValue {}

/// The parity is serialized as `u8` - `0` for even, `1` for odd.
#[cfg(feature = "serde")]
impl serde::Serialize for Parity {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(self.to_u8())
    }
}

/// The parity is deserialized as `u8` - `0` for even, `1` for odd.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Parity {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Parity;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("8-bit integer (byte) with value 0 or 1")
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                use serde::de::Unexpected;

                Parity::from_u8(v)
                    .map_err(|_| E::invalid_value(Unexpected::Unsigned(v.into()), &"0 or 1"))
            }
        }

        d.deserialize_u8(Visitor)
    }
}

use crate::CryptoError;

use super::constants::MESSAGE_SIZE;

/// Trait describing something that promises to be a 32-byte random number; in particular,
/// it has negligible probability of being zero or overflowing the group order. Such objects
/// may be converted to `Message`s without any error paths.
pub trait ThirtyTwoByteHash {
    /// Converts the object into a 32-byte array
    fn into_32(self) -> [u8; 32];
}

/// Implements the ThirtyTwoByteHash crate for code
#[macro_export]
macro_rules! impl_thirty_two_byte_hash {
    ($ty:ident) => {
        impl crate::common::types::ThirtyTwoByteHash for $ty {
            fn into_32(self) -> [u8; 32] {
                self.to_byte_array()
            }
        }
    };
}

#[cfg(feature = "hashes")]
impl ThirtyTwoByteHash for hashes::sha256::Hash {
    fn into_32(self) -> [u8; 32] {
        self.to_byte_array()
    }
}

#[cfg(feature = "hashes")]
impl ThirtyTwoByteHash for hashes::sha256d::Hash {
    fn into_32(self) -> [u8; 32] {
        self.to_byte_array()
    }
}

#[cfg(feature = "hashes")]
impl<T: hashes::sha256t::Tag> ThirtyTwoByteHash for hashes::sha256t::Hash<T> {
    fn into_32(self) -> [u8; 32] {
        self.to_byte_array()
    }
}

macro_rules! impl_pretty_debug {
    ($thing:ident) => {
        impl core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{}(", stringify!($thing))?;
                for i in &self[..] {
                    write!(f, "{:02x}", i)?;
                }
                f.write_str(")")
            }
        }
    };
}

/// A (hashed) message input to an ECDSA signature.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Message([u8; MESSAGE_SIZE]);
// TODO(chinonso): hardcoding MESSAGE_SIZE to hack around the compiler
impl_array_newtype!(Message, u8, 32);
impl_pretty_debug!(Message);

impl Message {
    /// **If you just want to sign an arbitrary message use `Message::from_hashed_data` instead.**
    ///
    /// Converts a `MESSAGE_SIZE`-byte slice to a message object. **WARNING:** the slice has to be a
    /// cryptographically secure hash of the actual message that's going to be signed. Otherwise
    /// the result of signing isn't a
    /// [secure signature](https://twitter.com/pwuille/status/1063582706288586752).
    #[inline]
    #[deprecated(since = "0.28.0", note = "use from_digest_slice instead")]
    pub fn from_slice(digest: &[u8]) -> Result<Message, CryptoError> {
        Message::from_digest_slice(digest)
    }

    /// Creates a [`Message`] from a `digest`.
    ///
    /// **If you just want to sign an arbitrary message use `Message::from_hashed_data` instead.**
    ///
    /// The `digest` array has to be a cryptographically secure hash of the actual message that's
    /// going to be signed. Otherwise the result of signing isn't a [secure signature].
    ///
    /// [secure signature]: https://twitter.com/pwuille/status/1063582706288586752
    #[inline]
    pub fn from_digest(digest: [u8; 32]) -> Message {
        Message(digest)
    }

    /// Creates a [`Message`] from a 32 byte slice `digest`.
    ///
    /// **If you just want to sign an arbitrary message use `Message::from_hashed_data` instead.**
    ///
    /// The slice has to be 32 bytes long and be a cryptographically secure hash of the actual
    /// message that's going to be signed. Otherwise the result of signing isn't a [secure
    /// signature].
    ///
    /// # Errors
    ///
    /// If `digest` is not exactly 32 bytes long.
    ///
    /// [secure signature]: https://twitter.com/pwuille/status/1063582706288586752
    #[inline]
    pub fn from_digest_slice(digest: &[u8]) -> Result<Message, CryptoError> {
        match digest.len() {
            MESSAGE_SIZE => {
                let mut ret = [0u8; MESSAGE_SIZE];
                ret[..].copy_from_slice(digest);
                Ok(Message(ret))
            }
            _ => Err(CryptoError::InvalidMessage),
        }
    }

    /// Returns a message as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Constructs a [`Message`] by hashing `data` with hash algorithm `H`.
    ///
    /// Requires the feature `hashes` to be enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "hashes")] {
    /// use secp256k1::hashes::{sha256, Hash};
    /// use secp256k1::Message;
    ///
    /// let m1 = Message::from_hashed_data::<sha256::Hash>("Hello world!".as_bytes());
    /// // is equivalent to
    /// let m2 = Message::from(sha256::Hash::hash("Hello world!".as_bytes()));
    ///
    /// assert_eq!(m1, m2);
    /// # }
    /// ```
    #[cfg(feature = "hashes")]
    pub fn from_hashed_data<H: ThirtyTwoByteHash + hashes::Hash>(data: &[u8]) -> Self {
        <H as hashes::Hash>::hash(data).into()
    }
}

impl<T: ThirtyTwoByteHash> From<T> for Message {
    /// Converts a 32-byte hash directly to a message without error paths.
    fn from(t: T) -> Message {
        Message(t.into_32())
    }
}

impl fmt::LowerHex for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}
