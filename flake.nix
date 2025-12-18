{
  description = "rawgrep";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
  };

  outputs = {
    nixpkgs,
    crane,
    ...
  }: let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};
    craneLib = crane.mkLib pkgs;

    src = craneLib.cleanCargoSource ./.;

    commonArgs = {
      inherit src;
      strictDeps = true;

      nativeBuildInputs = [
        pkgs.capnproto
      ];

      buildInputs = [];
    };

    cargoArtifacts = craneLib.buildDepsOnly commonArgs;

    rawgrep = craneLib.buildPackage (commonArgs // {
      inherit cargoArtifacts;
    });
  in {
    packages.${system} = {
      default = rawgrep;
    };

    devShells.${system}.default = pkgs.mkShell {
      inputsFrom = [rawgrep];

      buildInputs = with pkgs; [
        rustc
        cargo
        rust-analyzer
        rustfmt
        clippy
      ];
    };
  };
}
