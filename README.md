# KeyRA Alpha

KeyRA (Key Resource Authority), EVM wallet authentication and on-chain authorisation.

## Features

### Authentication
- **EVM Wallet Authentication**: Sign-In with Ethereum (SIWE) using MetaMask or compatible wallets
- **Session Management**: Secure cookie-based sessions with configurable TTL

### Authorisation
- **On-Chain Access Control**: Smart contract-based allowlist for fine-grained access management
- **Multi-Admin**: Multiple admins can independently grant and revoke access
- **Audit Trail**: All access changes emit on-chain events

### Infrastructure
- **Security Headers**: CSP, X-Frame-Options, X-Content-Type-Options
- **Health Endpoint**: Kubernetes-ready health probes
- **Deterministic Builds**: Reproducible via Nix flakes

## Requirements

- [Nix](https://nixos.org/) with flakes enabled
- [devenv](https://devenv.sh/) (recommended)

## Quick Start

### 1. Enter Development Shell

```bash
devenv shell
```

This provides: Rust toolchain, Foundry (forge, cast), Helm, and other tools.

### 2. Build Autonity

Clone and build the Autonity client (requires Go):

```bash
git clone git@github.com:autonity/autonity.git
cd autonity
go build -o ./build/bin/autonity ./cmd/autonity
cd ..
```

### 3. Start Local Blockchain

```bash
./scripts/start-autonity.sh
```

Starts a single-node Autonity instance in `--dev` mode with HTTP RPC on `127.0.0.1:8545` and WebSocket on `127.0.0.1:8546`. Enables `eth,web3,net,debug,admin,personal` APIs with open CORS. The script funds the Foundry default test account (`0xf39F...2266`) with 10 ETH. Chain ID is determined by the Autonity dev configuration.

### 4. Deploy Access Control Contract

```bash
./scripts/deploy-contract.sh --show-keys
```

This will:
- Create admin and read-only test accounts
- Fund both accounts from the dev account
- Deploy the `KeyRAAccessControl` contract
- Grant access to the read-only account
- Output private keys for MetaMask import

### 5. Run the Server

Use the command from the deploy script output:

```bash
CONTRACT_ADDRESS=0x... CHAIN_ID=65111111 cargo run
```

### 6. Test Authentication

1. Import the read-only private key into MetaMask
2. Add the Autonity dev network to MetaMask (RPC: `http://127.0.0.1:8545`, Chain ID: `65111111`)
3. Visit `http://localhost:8080`
4. Click "Sign In" and approve the signature request

## Development

### Run with Auto-Reload

```bash
CONTRACT_ADDRESS=0x... CHAIN_ID=65111111 cargo watch -x run
```

### Run Tests

```bash
cargo test
```

### Build Contracts

```bash
cd contracts && forge build
```

### Test Contracts

```bash
cd contracts && forge test
```

## Building

### Binary

```bash
nix build .#alpha
./result/bin/alpha
```

### OCI Image

```bash
nix build .#alpha-image
nix run .#alpha-image.copyToRegistry
```

## Deployment

### Helm

```bash
helm install alpha helm/alpha -f helm/alpha/values-dev.yaml
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `RPC_URL` | `http://127.0.0.1:8545` | Ethereum JSON-RPC endpoint |
| `CONTRACT_ADDRESS` | `0x0...0` | KeyRAAccessControl contract address |
| `CHAIN_ID` | `1337` | Ethereum chain ID for SIWE messages |
| `DOMAIN` | `localhost` | Domain for SIWE messages |
| `SESSION_SECRET` | (random) | Secret for session cookie signing |
| `SESSION_TTL_SECS` | `3600` | Session lifetime in seconds |

### Deploy Script Options

```
./scripts/deploy-contract.sh [OPTIONS]

Options:
  --rpc URL       RPC endpoint (default: http://127.0.0.1:8545)
  --show-keys     Display private keys in output
  --clean         Remove existing keys and start fresh
  --help          Show help message
```

Keys are stored in `.keys/` (git-ignored).

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/` | GET | Landing page (requires auth) |
| `/healthz` | GET | Health check |
| `/auth` | GET | Authentication page |
| `/auth/challenge` | POST | Get SIWE challenge message |
| `/auth/verify` | POST | Verify SIWE signature, set session cookie |
| `/style.css` | GET | Stylesheet |

## Smart Contract

The `KeyRAAccessControl` contract provides:

- **Multi-admin support**: Multiple admins can manage access
- **Access grants**: Admins grant/revoke access to addresses
- **On-chain audit trail**: All changes emit events

### Contract Functions

| Function | Description |
|----------|-------------|
| `isAdmin(address)` | Check if address is admin |
| `hasAccess(address)` | Check if address has access |
| `grantAccess(address)` | Grant access (admin only) |
| `revokeAccess(address)` | Revoke access (admin only) |
| `addAdmin(address)` | Add new admin (admin only) |
| `removeAdmin(address)` | Remove admin (admin only) |

## Security

- Content-Security-Policy with strict directives
- X-Content-Type-Options: `nosniff`
- X-Frame-Options: `DENY`
- Secure session cookies (HttpOnly, SameSite=Strict)
- On-chain access control verification
- Runs as non-root user (65534) in containers
- Read-only root filesystem in containers

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐
│   Browser   │────▶│ KeyRA Alpha │────▶│ Ethereum/Autonity   │
│  (MetaMask) │◀────│   Server    │◀────│   (RPC + Contract)  │
└─────────────┘     └─────────────┘     └─────────────────────┘
      │                    │
      │  1. Get nonce      │
      │  2. Sign message   │
      │  3. Verify sig ────┼──▶ 4. Check hasAccess()
      │  5. Set cookie     │
      └────────────────────┘
```

## License

MIT
