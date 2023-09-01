#![no_std]
#![no_main]

use uefi::table::{Boot, SystemTable};
use uefi::{cstr16, entry, Handle, Status};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
  arch::halt()
}

const BOOT_SPLASH: &'static uefi::CStr16 = cstr16!(
  r"______                _    _                    _
| ___ \              | |  | |                  | |
| |_/ /  ___    ___  | |_ | |  ___    __ _   __| |  ___  _ __
| ___ \ / _ \  / _ \ | __|| | / _ \  / _` | / _` | / _ \| '__|
| |_/ /| (_) || (_) || |_ | || (_) || (_| || (_| ||  __/| |
\____/  \___/  \___/  \__||_| \___/  \__,_| \__,_| \___||_|
"
);

#[entry]
fn uefi_main(image: Handle, mut system_table: SystemTable<Boot>) -> Status {
  let stdout = system_table.stdout();
  if let Err(err) = stdout.output_string(BOOT_SPLASH) {
    return err.status();
  }
  let bs = system_table.boot_services();
  bs.stall(10_000_000);

  Status::SUCCESS
}
