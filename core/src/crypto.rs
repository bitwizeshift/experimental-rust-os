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
