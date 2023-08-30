//! This module provides some cryptographic primitives such as 1-way hashes like
//! SHA256.
pub mod sha256;

#[derive(Clone, Copy)]
pub(crate) enum DigestErrorKind {
  BadChar(char),
  BadLength(usize),
}

/// An error raised when attempting to convert a [`str`] into a [`Digest`].
#[derive(Clone, Copy)]
pub struct ParseDigestError(pub(crate) DigestErrorKind);

impl core::fmt::Display for ParseDigestError {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match &self.0 {
      DigestErrorKind::BadChar(ch) => write!(
        f,
        "bad character in digest string; '{}' is not hexadecimal",
        ch
      ),
      DigestErrorKind::BadLength(len) => write!(
        f,
        "bad length of digest string; expected 64-chars, found {}",
        len
      ),
    }
  }
}

impl core::fmt::Debug for ParseDigestError {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    <Self as core::fmt::Display>::fmt(&self, f)
  }
}

/// A representation of some cryptographic hash function.
///
/// [`Hasher`] objects must be capable of incrementally updating the hash from
/// different byte-sequences that may or may not be the length of the internal
/// block-size. All `Hasher` objects must return a [`Hasher::Digest`] type,
/// which encodes the binary representation of the hashed object.
pub trait Hasher {
  // Digest is the type of hash representation produced by a given Hasher
  // implementation.
  type Digest;

  // Updates the hasher to include the state of the specified `bytes`.
  //
  // # Arguments
  //
  // * `bytes` - the bytes to include in the hash
  fn update(&mut self, bytes: &[u8]);

  // Produces a digest from the Hasher which represents the current hash state.
  fn digest(self) -> Self::Digest;
}

/// A trait that standardizes hashing objects in a sim
pub trait Hashable {
  /// Updates the hash in the specified hasher.
  ///
  /// # Arguments
  ///
  /// * `hasher` - the hasher to update.
  fn update_hash<H: Hasher>(&self, hasher: &mut H);
}

macro_rules! def_primitive_update_hash {
  ($($T:ty $(,)?)+) => {
    $(
      impl Hashable for $T {
        /// Appends the big-endian byte-representation of this primitive type
        /// into the hash.
        ///
        /// # Arguments
        ///
        /// * `hasher` - the hasher to update
        fn update_hash<H: Hasher>(&self, hasher: &mut H) {
          hasher.update(&self.to_be_bytes());
        }
      }
    )+
  };
}

def_primitive_update_hash![
  u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, f32, f64
];

impl Hashable for bool {
  /// Appends the boolean value as a byte into the hasher.
  ///
  /// # Arguments
  ///
  /// * `hasher` - the hasher to update
  fn update_hash<H: Hasher>(&self, hasher: &mut H) {
    hasher.update(&[*self as u8])
  }
}

impl Hashable for str {
  /// Appends the byte-sequence of the string into the hasher.
  ///
  /// # Arguments
  ///
  /// * `hasher` - the hasher to update
  fn update_hash<H: Hasher>(&self, hasher: &mut H) {
    hasher.update(self.as_bytes())
  }
}

impl<T: Hashable> Hashable for [T] {
  /// Invokes `update_hash` on all elements of the array.
  ///
  /// # Arguments
  ///
  /// * `hasher` - the hasher to update
  fn update_hash<H: Hasher>(&self, hasher: &mut H) {
    for v in self {
      v.update_hash(hasher)
    }
  }
}

/// A 32-byte SHA256 digest, which contains the state of a SHA256 hash
/// operation.
///
/// This type is aligned to a 16-byte boundary so that the compiler may take
/// advantage of this for better code-generation.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
#[repr(align(16))]
pub struct FixedDigest<const N: usize>([u8; N]);

impl<const N: usize> FixedDigest<N> {
  /// Constructs a [`Digest`] containing only zero values.
  #[inline(always)]
  const fn zeroed() -> Self {
    Self([0; N])
  }

  /// Constructs this Digest from a string representation of the digest,
  /// without doing any error checking on the input.
  ///
  /// # Arguments
  ///
  /// * `s` - the string to parse
  ///
  /// # Safety
  ///
  /// This function is unsafe because it does not check that the string passed
  /// to it form a valid hex Digest. If the input string `s` is not a 2 * N
  /// character ascii hexadecimal string, this will cause memory unsafety
  /// issues such as possible out-of-bounds access or buffer overflow issues.
  ///
  /// Ensure that the input string is valid before using, or prefer the
  /// [`Digest::from_str`] instead.
  ///
  /// # Examples
  ///
  /// Basic usage:
  ///
  /// ```rust
  /// # use core::crypto::FixedDigest;
  /// let digest = unsafe {
  ///   // Digest for "Hello, world!"
  ///   FixedDigest::<32>::from_str_unchecked("315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3")
  /// };
  /// ```
  pub unsafe fn from_str_unchecked(s: &str) -> Self {
    let mut result = Self::zeroed();
    let bytes = s.as_bytes();
    for i in 0..N {
      let c0 = bytes[i * 2];
      let c1 = bytes[i * 2 + 1];

      result.0[i] = Self::hex_digit_to_u8_unchecked(c0) << 4
        | Self::hex_digit_to_u8_unchecked(c1);
    }
    result
  }

  /// Constructs this Digest from a string representation of the digest,
  /// with error checking.
  ///
  /// Returns a [`ParseDigestError`] on failure if the supplied string either
  /// does not contain 64 characters, or if any of the digits are not valid
  /// hexadecimal values.
  ///
  /// # Arguments
  ///
  /// * `s` - the string to parse
  ///
  /// # Examples
  ///
  /// Basic usage:
  ///
  /// ```rust
  /// # use core::crypto::FixedDigest;
  /// let sha = "invalid"
  /// let digest = FixedDigest::<32>::from_str(sha);
  ///
  /// assert!(sha.is_err());
  /// ```
  pub fn from_str(s: &str) -> Result<Self, ParseDigestError> {
    if s.len() != 2 * N {
      return Err(ParseDigestError(DigestErrorKind::BadLength(s.len())));
    }
    let mut result = Self::zeroed();
    let bytes = s.as_bytes();
    for i in 0..N {
      let c0 = bytes[i * 2];
      let c1 = bytes[i * 2 + 1];

      result.0[i] =
        Self::hex_digit_to_u8(c0)? << 4 | Self::hex_digit_to_u8(c1)?;
    }

    Ok(result)
  }

  /// Converts an 8-bit ascii hexadecimal value into its corresponding integer
  /// form without checking.
  ///
  /// # Arguments
  ///
  /// * `ascii` - the 8-bit ascii value
  ///
  /// # Safety
  ///
  /// This function is unsafe because it assumes that the input values are
  /// valid ASCII characters -- and anything outside this range may corrupt the
  /// computation.
  unsafe fn hex_digit_to_u8_unchecked(ascii: u8) -> u8 {
    let ch = char::from(ascii);
    match ch {
      '0'..='9' => {
        let ord: u32 = ch.into();
        let zero: u32 = '0'.into();
        (ord - zero) as u8
      }
      'a' | 'A' => 10u8,
      'b' | 'B' => 11u8,
      'c' | 'C' => 12u8,
      'd' | 'D' => 13u8,
      'e' | 'E' => 14u8,
      'f' | 'F' => 15u8,
      _ => unreachable!(),
    }
  }

  /// Converts an 8-bit ascii hexadecimal value into its corresponding integer
  /// form.
  ///
  /// This function returns a [`ParseDigestError`] on failure.
  ///
  /// # Arguments
  ///
  /// * `ascii` - the 8-bit ascii value
  fn hex_digit_to_u8(ascii: u8) -> Result<u8, ParseDigestError> {
    let ch = char::from(ascii);
    match ch {
      '0'..='9' => {
        let ord: u32 = ch.into();
        let zero: u32 = '0'.into();
        Ok((ord - zero) as u8)
      }
      'a' | 'A' => Ok(10u8),
      'b' | 'B' => Ok(11u8),
      'c' | 'C' => Ok(12u8),
      'd' | 'D' => Ok(13u8),
      'e' | 'E' => Ok(14u8),
      'f' | 'F' => Ok(15u8),
      _ => Err(ParseDigestError(DigestErrorKind::BadChar(ch))),
    }
  }

  /// Returns an iterator over the bytes within the digest.
  ///
  /// The iterator yields all items from start to end.
  pub fn iter(&self) -> impl Iterator<Item = &u8> {
    self.0.iter()
  }

  /// Creates a consuming iterator, that is, one that moves each value out of
  /// the digest (from start to end). Since each value is a [`u8`] which
  /// satisfies [`Copy`], this mostly exists for APIs that expect values
  /// rather than references.
  pub fn into_iter(self) -> impl IntoIterator<Item = u8> {
    self.0.into_iter()
  }
}

impl<const N: usize> core::fmt::Display for FixedDigest<N> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    for v in &self.0 {
      write!(f, "{:02x}", v)?;
    }
    Ok(())
  }
}

impl<const N: usize> core::fmt::Debug for FixedDigest<N> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    <Self as core::fmt::Display>::fmt(self, f)
  }
}

impl<const N: usize> Hashable for FixedDigest<N> {
  /// Updates the hasher by feeding the bytes of this digest into it.
  ///
  /// # Arguments
  ///
  /// * `hasher` - the hasher to update
  #[inline]
  fn update_hash<H: Hasher>(&self, hasher: &mut H) {
    hasher.update(&self.0)
  }
}
