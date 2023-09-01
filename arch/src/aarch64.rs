#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn halt() -> ! {
  loop {}
}
