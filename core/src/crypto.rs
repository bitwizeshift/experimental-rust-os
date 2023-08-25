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

trait Hasher {
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
