# Binary Safety

* All binaries that require any unsafe access must be digitally signed
  * For binaries that do not require any permissions, these do not require
    signatures. This enables basic command-line utilities without the hassle of
    signing
  * Dev-signing is possible, which will grant permissions -- but are shared for
    an entire computer-instance. Dev-signed instances are signed by the machine,
    rather than by an entity -- meaning sharing a dev-signed binary across
    systems will have different identities.
* The entire binary ecosystem is hashed to form a [Merkle Tree]. This is the
  "source of truth" for installations and detecting tampered binaries.
  * Subsections of the ecosystem may form different trees (e.g. "admin" vs
    "user" binaries)
  * This tree can be used to authenticate installations and verify integrity.
* All actions are recorded and stored in digitally-secure [Blockchain],
  signed by the authorizing party. This means that all installations, upgrades,
  and uninstallations will be digitally finger-printed by the system that
  authorizes the installation.

[Merkle Tree]: https://en.wikipedia.org/wiki/Merkle_tree
[Blockchain]: https://en.wikipedia.org/wiki/Blockchain