# Contributing

Issues and pull requests are welcome. For a larger change, open an issue first so we can agree on the approach.

## Principles

- The crate stays sans-IO: no sockets, files, environment variables, clock or randomness. Time and random bytes come
  from the caller.
- No `unsafe` code and no FFI.
- Untrusted input (XML, JSON, headers, URLs) is bounded and validated before use. Credentials never appear in `Debug`
  output or error messages.
- Every provider keeps the same semantics for each operation. Where a provider lacks a feature (conditional writes on
  Google Drive, for example), it is emulated and the remaining race is documented.
- New provider behavior comes with tests against the in-memory servers in `src/testing*.rs`, shaped after the
  provider's official documentation, and with responses in `golden/` where they help.

## Before you open a pull request

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --no-deps --all-features
cargo +1.88 test --all-features --lib --tests   # the minimum supported Rust version
```

Add a line under `## [Unreleased]` in `CHANGELOG.md` for any change callers can notice.

## Compatibility

- Versions follow semantic versioning. Before 1.0, a breaking change bumps the minor version.
- Public enums and structs that may grow are `#[non_exhaustive]`; adding a variant or field to them is not breaking.
- Raising the minimum supported Rust version (1.88) is a minor version change.

## Releasing

1. Move the `[Unreleased]` entries under a new version and date in `CHANGELOG.md`, and update the links at the bottom.
2. Set `version` in `Cargo.toml`. Run `cargo semver-checks` against the previous release and `cargo package --list`.
3. Commit, tag `vX.Y.Z`, push the tag, and wait for CI.
4. `cargo publish`, then create the GitHub release from the changelog section.
