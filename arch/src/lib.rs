#![no_std]

macro_rules! define_arch {
  ($mod_name:ident, $arch_str:tt) => {
    #[cfg(target_arch = $arch_str)]
    pub mod $mod_name;

    #[cfg(target_arch = $arch_str)]
    pub(crate) mod target_impl {
      pub use super::$mod_name::*;
    }
  };
}

define_arch!(aarch64, "aarch64");
define_arch!(x86_64, "x86_64");

/// A module that buckets functionality that exists for the architecture being
/// targeted for compilation.
///
/// This is effectively a logical "alias" of the currently active architecture.
///
/// # Note
///
/// This should only really be relied on for common sets of functions whose
/// functionality can reliably be shared across different systems.
pub mod target {
  pub use super::target_impl::*;
}

// Halts the CPU's execution, hanging the system in the process.
//
// This function fundamentally _never returns_ to the caller, and should be
// used very sparingly.
pub fn halt() -> ! {
  target::halt()
}
