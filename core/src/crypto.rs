//! This module provides some cryptographic primitives such as 1-way hashes like
//! SHA256.
pub mod sha256;

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
