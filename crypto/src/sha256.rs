//! This module provides utilities for implementing SHA256 1-way hashing.
//!

use crate::{FixedDigest, Hashable, Hasher};

/// A 32-byte SHA256 digest, which contains the state of a SHA256 hash
/// operation.
pub type Digest = FixedDigest<32>;

/// A 64-byte Block of data that is hashed in the SHA256 algorithm.
///
/// This is largely a thin-wrapper of an array of 64-bytes, with added alignment
/// to help along code-generation so that it may leverage better registers or
/// loading calls.
///
/// Block objects can deref directly into slices of [`u8`] for convenience.
#[derive(Clone)]
#[repr(align(32))]
pub struct Block([u8; 64]);

impl Block {
  /// The size of all [`Block`] instances.
  pub const SIZE: usize = 64;

  /// Constructs a [`Block`] containing only zeros.
  #[inline]
  pub const fn zeroed() -> Self {
    Self([0; 64])
  }

  /// Constructs a [`Block`] from an array of the same size.
  ///
  /// # Arguments
  ///
  /// * `value` - the array value to use.
  #[inline(always)]
  pub const fn from_array(value: [u8; 64]) -> Self {
    Self(value)
  }
}

impl From<[u8; 64]> for Block {
  #[inline(always)]
  fn from(value: [u8; 64]) -> Self {
    Self::from_array(value)
  }
}

impl core::ops::Deref for Block {
  type Target = [u8];

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl core::ops::DerefMut for Block {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.0
  }
}

pub struct SHA256 {
  len: u64,
  buffer: Block,
  hash: [u32; 8],
}

impl SHA256 {
  // The default seed for an empty SHA256 hash.
  const SEED: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
  ];

  const CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  /// Constructs a new [`SHA256`] instance.
  pub const fn new() -> Self {
    Self {
      len: 0,
      hash: Self::SEED,
      buffer: Block::zeroed(),
    }
  }

  #[inline]
  fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
  }

  #[inline]
  fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
  }

  #[inline]
  fn sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
  }

  #[inline]
  fn sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
  }

  #[inline]
  fn gamma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
  }

  #[inline]
  fn gamma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
  }

  /// Updates this hash with a full block value.
  ///
  /// # Arguments
  ///
  /// * `block` - the block to update the hash with.
  pub fn update_block(&mut self, block: &Block) {
    let mut words = [0u32; 64];

    for i in 0..16 {
      words[i] = u32::from_be_bytes([
        block[i * 4],
        block[i * 4 + 1],
        block[i * 4 + 2],
        block[i * 4 + 3],
      ]);
    }

    for i in 16..64 {
      let s0 = Self::gamma0(words[i - 15]);
      let s1 = Self::gamma1(words[i - 2]);
      words[i] = words[i - 16]
        .wrapping_add(s0)
        .wrapping_add(words[i - 7])
        .wrapping_add(s1);
    }

    let mut a = self.hash[0];
    let mut b = self.hash[1];
    let mut c = self.hash[2];
    let mut d = self.hash[3];
    let mut e = self.hash[4];
    let mut f = self.hash[5];
    let mut g = self.hash[6];
    let mut h = self.hash[7];

    // Clippy erroneously states that this is only used to index 'words', but it
    // also is used to index Self::CONSTANTS as well.
    // This could also be done with a zip range, but there is less guarantees on
    // the generated code this compiles into, and it's cleaner to keep an index
    // for the symmetry with the above loops.
    #[allow(clippy::needless_range_loop)]
    for i in 0..64 {
      let s1 = Self::sigma1(e);
      let ch = Self::ch(e, f, g);
      let temp1 = h
        .wrapping_add(s1)
        .wrapping_add(ch)
        .wrapping_add(Self::CONSTANTS[i])
        .wrapping_add(words[i]);
      let s0 = Self::sigma0(a);
      let maj = Self::maj(a, b, c);
      let temp2 = s0.wrapping_add(maj);

      h = g;
      g = f;
      f = e;
      e = d.wrapping_add(temp1);
      d = c;
      c = b;
      b = a;
      a = temp1.wrapping_add(temp2);
    }

    self.hash[0] = self.hash[0].wrapping_add(a);
    self.hash[1] = self.hash[1].wrapping_add(b);
    self.hash[2] = self.hash[2].wrapping_add(c);
    self.hash[3] = self.hash[3].wrapping_add(d);
    self.hash[4] = self.hash[4].wrapping_add(e);
    self.hash[5] = self.hash[5].wrapping_add(f);
    self.hash[6] = self.hash[6].wrapping_add(g);
    self.hash[7] = self.hash[7].wrapping_add(h);
  }
}

impl super::Hasher for SHA256 {
  type Digest = Digest;

  fn update(&mut self, data: &[u8]) {
    let mut data_idx = 0;

    while data_idx < data.len() {
      let len = self.len as usize;
      let space_in_buffer = 64 - (len % 64);
      let remaining_data = data.len() - data_idx;

      let copy_len = core::cmp::min(space_in_buffer, remaining_data);

      let buffer_idx = len % 64;
      self.buffer[buffer_idx..buffer_idx + copy_len]
        .copy_from_slice(&data[data_idx..data_idx + copy_len]);

      self.len += copy_len as u64;
      data_idx += copy_len;

      if self.len % 64 == 0 {
        let block = self.buffer.clone();
        self.update_block(&block);
      }
    }
  }

  // Access the digest from this
  fn digest(mut self) -> Self::Digest {
    let length = self.len * 8;
    let buffer = &self.buffer[..self.len as usize % Block::SIZE];
    let mut padded = Block::zeroed();
    padded[..buffer.len()].copy_from_slice(buffer);
    padded[buffer.len()] = 0x80;

    if buffer.len() >= 56 {
      self.update_block(&padded);
      padded = Block::zeroed();
    }

    padded[56..].copy_from_slice(&length.to_be_bytes());

    self.update_block(&padded);
    let final_state = self.hash;

    let mut result = Digest::zeroed();
    for (i, &word) in final_state.iter().enumerate() {
      result.0[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }

    result
  }
}

/// Hash the input byte sequence and return a SHA256 [`Digest`] representing
/// the hashed bytes.
///
/// # Arguments
///
/// * `bytes` - a slice of bytes to hash
pub fn hash_bytes(bytes: &[u8]) -> Digest {
  let mut hasher = SHA256::new();
  hasher.update(bytes);
  hasher.digest()
}

/// Hash the object and return a SHA256 [`Digest`] representing this hashed
/// object.
///
/// # Arguments
///
/// * `obj` - the object to hash
pub fn hash<T: Hashable>(obj: T) -> Digest {
  let mut hasher = SHA256::new();
  obj.update_hash(&mut hasher);
  hasher.digest()
}

#[cfg(test)]
mod test {

  #[test]
  fn sha256_input_less_than_block_size() {
    use crate::sha256;
    use crate::Hasher;

    let mut hasher = sha256::SHA256::new();
    hasher.update(b"Hello, world!");

    let digest = hasher.digest();
    let expect = unsafe {
      sha256::Digest::from_str_unchecked(
        "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3",
      )
    };

    assert_eq!(digest, expect);
  }

  #[test]
  fn sha256_input_less_than_block_size_multiple_parts() {
    use crate::sha256;
    use crate::Hasher;

    let mut hasher = sha256::SHA256::new();
    hasher.update(b"Hello");
    hasher.update(b", ");
    hasher.update(b"world!");

    let digest = hasher.digest();
    let expect = unsafe {
      sha256::Digest::from_str_unchecked(
        "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3",
      )
    };

    assert_eq!(digest, expect);
  }

  #[test]
  fn sha256_input_greater_than_block_size() {
    use crate::sha256;
    use crate::Hasher;

    let input = br#"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed faucibus magna sed ipsum malesuada ornare. Nunc accumsan id nibh in congue. Praesent placerat feugiat sem sed auctor. Etiam a cursus magna, vel dictum neque. Aliquam erat volutpat. Fusce rhoncus nisl facilisis, viverra eros a, sodales libero. Pellentesque pellentesque nunc sit amet ex congue aliquet. Suspendisse vel dui ac dui convallis faucibus. Donec semper mi eu mollis sagittis. Maecenas tempor nibh congue lectus pretium iaculis. Proin vitae massa sed justo euismod suscipit ac ut turpis. Vivamus leo metus, accumsan ac risus vel, tempor faucibus tellus."#;

    let mut hasher = sha256::SHA256::new();
    hasher.update(input);

    let digest = hasher.digest();
    let expect = unsafe {
      sha256::Digest::from_str_unchecked(
        "9802ab88834314ec41abcd75326e7e3007d55a4ff80ff0355c52e992a0e06582",
      )
    };

    assert_eq!(digest, expect);
  }

  #[test]
  fn sha256_input_greater_than_block_size_multiple_parts() {
    use crate::sha256;
    use crate::Hasher;

    let input = br#"consectetur adipiscing elit. Sed faucibus magna sed ipsum malesuada ornare. Nunc accumsan id nibh in congue. Praesent placerat feugiat sem sed auctor. Etiam a cursus magna, vel dictum neque. Aliquam erat volutpat. Fusce rhoncus nisl facilisis, viverra eros a, sodales libero. Pellentesque pellentesque nunc sit amet ex congue aliquet. Suspendisse vel dui ac dui convallis faucibus. Donec semper mi eu mollis sagittis. Maecenas tempor nibh congue lectus pretium iaculis. Proin vitae massa sed justo euismod suscipit ac ut turpis. Vivamus leo metus, accumsan ac risus vel, tempor faucibus tellus."#;

    let mut hasher = sha256::SHA256::new();
    hasher.update(b"Lorem ipsum dolor sit amet");
    hasher.update(b", ");
    hasher.update(input);

    let digest = hasher.digest();
    let expect = unsafe {
      sha256::Digest::from_str_unchecked(
        "9802ab88834314ec41abcd75326e7e3007d55a4ff80ff0355c52e992a0e06582",
      )
    };

    assert_eq!(digest, expect);
  }
  #[test]
  fn sha256_input_exact_block_length() {
    use crate::sha256;
    use crate::Hasher;
    let input =
      b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed at.";

    let mut hasher = sha256::SHA256::new();
    hasher.update(input);

    let digest = hasher.digest();
    let expect = unsafe {
      sha256::Digest::from_str_unchecked(
        "43ad7ee7440e29047288790007180beb6bba6a667579f055e9dcdca221e4161d",
      )
    };

    assert_eq!(digest, expect);
  }

  #[test]
  fn sha256_input_exact_block_length_multiple_parts() {
    use crate::sha256;
    use crate::Hasher;

    let mut hasher = sha256::SHA256::new();
    hasher.update(b"Lorem ipsum dolor sit amet");
    hasher.update(b", ");
    hasher.update(b"consectetur adipiscing elit. Sed at.");

    let digest = hasher.digest();
    let expect = unsafe {
      sha256::Digest::from_str_unchecked(
        "43ad7ee7440e29047288790007180beb6bba6a667579f055e9dcdca221e4161d",
      )
    };

    assert_eq!(digest, expect);
  }
}
