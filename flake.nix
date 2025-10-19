{
  description = "A basic Go development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            gopls
            gotools
            go-tools

            gh
          ];

          shellHook = ''
            export $(cat .env | xargs)
            export PRIVATE_KEY=$(cat ca)
            export PUBLIC_KEY=$(cat ca.pub)
          '';
        };

        packages.default = pkgs.buildGoModule {
          pname = "cert-issue";
          version = "0.1.0";
          src = ./.;
          vendorHash = "sha256-VX9/AmfNTUhX4nbwSsC4MvAAch5DjslVG8Kai3bQyNQ=";
        };
      }
    );
}
