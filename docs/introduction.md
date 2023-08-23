# Introduction

**No Name OS** is an exploratory and hobby OS project written in [Rust] which
aims to rethink the way Operating Systems work from its foundations. There are
several important goals that this intends to explore:

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
  * **Applications** live in scoped-registries

[Rust]: https://rustlang.org
[Merkle Trees]: https://en.wikipedia.org/wiki/Merkle_tree
[Secure Boot]: https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot
[Blockchain]: https://en.wikipedia.org/wiki/Blockchain
[Certificate Signing]: https://en.wikipedia.org/wiki/PKCS_12