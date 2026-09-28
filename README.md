# attested-proxy

Verification of World App **attested-key canonical requests**, as Rust crates and as a sidecar
container that sits in front of a service.

A World App request is signed by a device key that the [Attestation Gateway] attested. The
gateway's JWT (`Integrity-Token`) carries that key as `cnf.jwk`. The app signs an [RFC 9421]
signature base covering the method, scheme, authority, path, query, body digest and the token
itself; a verifier rebuilds the same base from the request it received and checks the signature
with the attested key. The wire format is the TFH [RFC 9421 Integrity Request Signing Profile].

Verification proves that **an attested app on an attested device signed this exact request**. It
does not identify a user, a PCP owner or a relying party, and it authorizes nothing. See
[Authorized Principal] for that layer.

## Development

```sh
nix develop            # or install the toolchain in rust-toolchain.toml
cargo test --workspace --all-features
nix flake check        # clippy, tests and fmt, as in CI
```

[Attestation Gateway]: https://github.com/worldcoin/attestation-gateway
[RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421.html
[RFC 9421 Integrity Request Signing Profile]: https://app.notion.com/p/3888614bdf8c819b8cc3f9a3a05b10a7
[Authorized Principal]: https://app.notion.com/p/36e8614bdf8c80d797fff43a85f8853d
