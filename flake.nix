{
  description = "KeyRA Alpha Landing Page";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    nix2container.url = "github:nlewo/nix2container";
    nix2container.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, nix2container, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      packages = forAllSystems (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs { inherit system overlays; };
          n2c = nix2container.packages.${system}.nix2container;

          rustToolchain = pkgs.rust-bin.stable.latest.minimal;

          alpha = pkgs.rustPlatform.buildRustPackage {
            pname = "alpha";
            version = "0.1.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            nativeBuildInputs = [ rustToolchain ];
          };

          alphaImage = n2c.buildImage {
            name = "ghcr.io/klazomenai/keyra/alpha";
            tag = "latest";

            copyToRoot = pkgs.buildEnv {
              name = "alpha-root";
              paths = [ alpha pkgs.cacert ];
              pathsToLink = [ "/bin" "/etc" ];
            };

            config = {
              entrypoint = [ "${alpha}/bin/alpha" ];
              exposedPorts = {
                "8080/tcp" = {};
              };
              env = [
                "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
              ];
              user = "65534:65534";
            };
          };
        in
        {
          default = alpha;
          alpha = alpha;
          alpha-image = alphaImage;
        }
      );

      devShells = forAllSystems (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs { inherit system overlays; };
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" "rust-analyzer" ];
          };
        in
        {
          default = pkgs.mkShell {
            buildInputs = [
              rustToolchain
              pkgs.cargo-watch
              pkgs.helm-docs
              pkgs.kubernetes-helm
            ];

            shellHook = ''
              echo "KeyRA Alpha Development Shell"
              echo ""
              echo "Commands:"
              echo "  cargo build          - Build binary"
              echo "  cargo run            - Run locally (default port 8080)"
              echo "  cargo watch -x run   - Auto-reload on changes"
              echo "  nix build .#alpha    - Build with Nix"
              echo "  nix build .#alpha-image - Build OCI image"
              echo "  helm lint helm/alpha - Lint Helm chart"
              echo ""
            '';
          };
        }
      );
    };
}
