{ pkgs, ... }:

{
  languages.rust = {
    enable = true;
    channel = "stable";
  };

  packages = [
    pkgs.cargo-watch
    pkgs.kubernetes-helm
    pkgs.foundry
    pkgs.openssl
    pkgs.pkg-config
  ];

  env = {
    AUTONITY_BIN = "./autonity/build/bin/autonity";
  };

  enterShell = ''
    echo "KeyRA Alpha Development Shell"
    echo ""
    echo "Prerequisites (if not done):"
    echo "  git clone git@github.com:autonity/autonity.git"
    echo "  cd autonity && go build -o ./build/bin/autonity ./cmd/autonity && cd .."
    echo ""
    echo "Quick Start:"
    echo "  1. ./scripts/start-autonity.sh     - Start local blockchain"
    echo "  2. ./scripts/deploy-contract.sh    - Deploy contract & create accounts"
    echo "  3. CONTRACT_ADDRESS=0x... CHAIN_ID=65111111 cargo run"
    echo ""
    echo "Blockchain:"
    echo "  forge build / forge test           - Build/test Solidity contracts"
    echo "  cast call <addr> 'hasAccess(address)(bool)' <user>"
    echo ""
    echo "Rust:"
    echo "  cargo build / cargo test           - Build/test Rust server"
    echo "  cargo watch -x run                 - Auto-reload on changes"
    echo ""
    echo "Nix:"
    echo "  nix build .#alpha                  - Build binary"
    echo "  nix build .#alpha-image            - Build OCI image"
    echo ""
  '';
}
