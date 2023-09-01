# Introduction

**Untitled Rust OS** is an exploratory and hobby OS project written in [Rust]
which aims to rethink the way Operating Systems work from its foundations.

## Planned Features

**Note:** This is largely a brain-dump/wish-list of what will be implemented,
and is not necessarily representative of what is, or will ever be, fully
explored.

* **Enhanced cryptographic-security**
  * **[Secure Boot]** from the Bootloader into the kernel.
  * **[Blockchain]** records for application activity to securely record software
    installation.
  * **[Merkle Trees]** used to verify authenticity of software installations.
  * **[Certificate Signing]** of all applications that require any form of
    privilege escalation.
* **Virtualization**
  * **Containers** have first-class support in the kernel.
  * **Sandboxing** can be done with sets of applications by launching them in
    shared containers that lack access to the root file system.
* **Strongly-typed IPC**
  * **Structured IPC Messages** are used for communication between processes,
    which contain sets of reusable functionality (e.g. `Path`, `File`, etc).
  * **Format Registry** is used to communicate shared-formats between binaries,
    and is extensible for newer communicable formats.
* **Linking and Loading**
  * **Applications** live in scoped-registries.
  * **Execution** offers alternative non-standard entry-point for applications
    which provide contextual information for the operating-system (experimental).
* **Kernel**
  * **Hybrid-design** which follows micro-kernel philosophy but with
    kernel-rooted subsystems.
  * **Multi-Kernel** support, leveraged for in-memory upgrades and rollback,
    which avoids the need for reboots.

[Rust]: https://rustlang.org
[Merkle Trees]: https://en.wikipedia.org/wiki/Merkle_tree
[Secure Boot]: https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot
[Blockchain]: https://en.wikipedia.org/wiki/Blockchain
[Certificate Signing]: https://en.wikipedia.org/wiki/PKCS_12