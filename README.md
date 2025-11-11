# NZ2 Proof-of-Concept

A (hopefully) spec-compliant proof-of-concept implementation of the NZ2 specification in Rust.

## Related Repositories

- [NZ2 Specification](https://github.com/cryeprecision/nz2-spec)
- [**NZ2 Proof-of-Concept (Rust)**](https://github.com/cryeprecision/nz2-poc-rs)
- [NNTP Client Library (Rust)](https://github.com/cryeprecision/nntp-rs)
- [rapidyenc (Fork)](https://github.com/cryeprecision/rapidyenc)
- [rapidyenc Rust Bindings](https://github.com/cryeprecision/rapidyenc-rs)
- [sabctools (Fork)](https://github.com/cryeprecision/sabctools)
- [sabnzbd (Fork)](https://github.com/cryeprecision/sabnzbd)

## Building

Build the project using `cargo build --release`, then you can find the build executable at `./target/release/...`.

### Build Requirements

- Clang for [bindgen](https://docs.rs/bindgen/latest/bindgen/) (see [rust-lang.github.io/rust-bindgen/requirements](https://rust-lang.github.io/rust-bindgen/requirements))
- CMake for [cmake](https://docs.rs/cmake/latest/cmake/)

## Usage

This project uses [tracing](https://docs.rs/tracing/latest/tracing/) for logging. You can set the logging level using the `RUST_LOG` environment variable (see [`EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html)).

## NNTP RFCs

- [RFC 3977 - Network News Transfer Protocol (NNTP)](https://datatracker.ietf.org/doc/html/rfc3977)
- [RFC 4642 - Using Transport Layer Security (TLS) with Network News Transfer Protocol (NNTP)](https://datatracker.ietf.org/doc/html/rfc4642)
- [RFC 4643 - Network News Transfer Protocol (NNTP) Extension for Authentication](https://datatracker.ietf.org/doc/html/rfc4643)
- [RFC 5322 - Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322)
- [RFC 5536 - Netnews Article Format](https://datatracker.ietf.org/doc/html/rfc5536)

## NZ2 File Integrity

Assuming the a given NZ2 file is trusted, i.e., has not been tampered with, the downloaded files are guaranteed to be identical to the uploaded files.
Verifying the integrity of the NZ2 file itself is currently out of the scope for this project.

If the integrity of NZ2 files is a concern, existing tools like [`minisign`](https://jedisct1.github.io/minisign/) can be used.
Someone posting NZ2 files would have their public key available for download and include the corresponding `.nz2.minisig` files alongside the NZ2 files.
Tools like [`SABnzbd`](https://sabnzbd.org/) could store a list of trusted minisign public keys, and would verify the NZ2 files against those keys.

## Credits

- [animetosho/rapidyenc](https://github.com/animetosho/rapidyenc): A SIMD implementation of yEnc.