# PROCESS_ANYWHERE

This rust module provides a unified API for running processes on either the
local computer & operating system or remotely via SSH.

**Install:** `cargo add process_anywhere`

[**Documentation**](https://docs.rs/process_anywhere)

[**Crates.io**](https://crates.io/crates/process_anywhere)


## Prerequisites

Supported platforms: Posix

Required libraries: OpenSSL

Feature "vendored-openssl" statically links with the OpenSSH library,
which bundles the dependency into the compiled binary.


## Development

The unit tests run a local OpenSSH server.

Install OpenSSH on Ubuntu using: `sudo apt-get install openssh-server`


## License

This project is licensed under the MIT-0 license.

