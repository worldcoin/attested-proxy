{
  description = "attested-proxy: attested-key canonical request verification for World App";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      crane,
      rust-overlay,
      ...
    }:
    let
      lib = nixpkgs.lib;
      forAllSystems = lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      perSystem = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          craneLib = (crane.mkLib pkgs).overrideToolchain (_: toolchain);

          # The shared vectors are read by the tests, so they are part of the source.
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              (craneLib.fileset.commonCargoSources ./.)
              ./test-vectors
            ];
          };
          commonArgs = {
            inherit src;
            strictDeps = true;
            pname = "attested-proxy";
            buildInputs = lib.optionals pkgs.stdenv.isDarwin [ pkgs.libiconv ];
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        in
        {
          checks = {
            clippy = craneLib.cargoClippy (
              commonArgs
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--workspace --all-targets --all-features -- --deny warnings";
              }
            );
            test = craneLib.cargoTest (
              commonArgs
              // {
                inherit cargoArtifacts;
                cargoTestExtraArgs = "--workspace --all-features";
              }
            );
            fmt = craneLib.cargoFmt { inherit (commonArgs) src pname; };
          };

          devShells.default = craneLib.devShell {
            packages = [
              pkgs.python3 # test-vectors/generate_signature_base.py
            ];
          };
        }
      );
    in
    {
      checks = lib.mapAttrs (_: outputs: outputs.checks) perSystem;
      devShells = lib.mapAttrs (_: outputs: outputs.devShells) perSystem;
    };
}
