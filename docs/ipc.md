# IPC

## Planned Features

* IPC is managed by a custom binary protocol which manages schema definitions.
* Containers have schema type repositories which are used to identify valid
  payload entries, which can then be leveraged in supporting shell commands.
  * Containers (and sub-containers) enable scoping of definitions (e.g. so that
    User X only see schema Foo, and User Y does not).
* Raw is a valid schema for POSIX-style IPC, in which raw bytes are communicated.
