# KeyRAAccessControl Deployment Guide

## Gas Estimates

Based on compiled bytecode (2,137 bytes, Solidity 0.8.20, Paris EVM, optimizer 10k runs).

| Operation | Gas (approx) | Type | Frequency |
|-----------|-------------|------|-----------|
| Deploy `KeyRAAccessControl` | ~600,000 | Transaction | Once |
| `grantAccess(address)` | ~50,000 | Transaction | Per user |
| `revokeAccess(address)` | ~30,000 | Transaction | Rare |
| `addAdmin(address)` | ~50,000 | Transaction | Rare |
| `removeAdmin(address)` | ~30,000 | Transaction | Rare |
| `hasAccess(address)` | 0 | View call | Every auth request |
| `isAdmin(address)` | 0 | View call | On demand |

### ATN Cost

| Gas Price | Deploy | grantAccess | Deploy + 5 users |
|-----------|--------|-------------|------------------|
| 1 gwei | 0.0006 ATN | 0.00005 ATN | 0.0009 ATN |
| 5 gwei | 0.003 ATN | 0.00025 ATN | 0.004 ATN |
| 10 gwei | 0.006 ATN | 0.0005 ATN | 0.009 ATN |

> These are EVM-level estimates from bytecode analysis. Actual gas may vary
> slightly. Run `forge test --gas-report` in `devenv shell` for precise
> per-function measurements, or use `--dry-run` to simulate without broadcasting.

## Prerequisites

- Foundry (`forge`, `cast`) — available via `devenv shell`
- Private key with ATN balance for gas
- RPC endpoint for target network

## Local Testing (Autonity single-node)

```bash
# Enter dev environment
devenv shell

# Start local Autonity node
./scripts/start-autonity.sh

# Deploy with dev account (pre-funded, auto-creates admin/readonly accounts)
./scripts/deploy-contract.sh --show-keys

# Run Foundry tests with gas report
cd contracts && forge test --gas-report
```

## Dry Run (simulate without broadcasting)

Estimate gas on any network without spending ATN. In dry-run mode the script
generates a throwaway keypair and skips account creation and funding — only the
`forge create` simulation runs:

```bash
# Dry run against mainnet — shows gas estimate, does NOT broadcast
./scripts/deploy-contract.sh --rpc https://rpc1.bakerloo.autonity.org --dry-run

# Or manually with forge:
forge create \
  --root contracts \
  --rpc-url <RPC_URL> \
  --private-key <PRIVATE_KEY> \
  src/AccessList.sol:KeyRAAccessControl \
  --constructor-args <ADMIN_ADDRESS>
  # Note: without --broadcast, forge simulates only
```

## Mainnet Deployment

```bash
# 1. Check gas price
cast gas-price --rpc-url <MAINNET_RPC>

# 2. Check deployer balance
cast balance --rpc-url <MAINNET_RPC> <DEPLOYER_ADDRESS> --ether

# 3. Deploy (forge create WITHOUT --broadcast simulates first)
export DEPLOYER_KEY="<private-key>"
export MAINNET_RPC="<rpc-url>"
export ADMIN_ADDRESS="<your-address>"

forge create \
  --root contracts \
  --rpc-url "$MAINNET_RPC" \
  --private-key "$DEPLOYER_KEY" \
  --broadcast \
  src/AccessList.sol:KeyRAAccessControl \
  --constructor-args "$ADMIN_ADDRESS"

# 4. Verify deployment
export CONTRACT="<deployed-address>"
cast call --rpc-url "$MAINNET_RPC" "$CONTRACT" "isAdmin(address)(bool)" "$ADMIN_ADDRESS"
# Should return: true

# 5. Grant access to wallet(s)
cast send --rpc-url "$MAINNET_RPC" --private-key "$DEPLOYER_KEY" \
  "$CONTRACT" "grantAccess(address)" "<USER_ADDRESS>"

# 6. Verify access
cast call --rpc-url "$MAINNET_RPC" "$CONTRACT" "hasAccess(address)(bool)" "<USER_ADDRESS>"
# Should return: true
```

## Post-Deployment

1. Store contract address in Vault:
   ```bash
   vault kv put secret/alpha/contract-address value=<CONTRACT_ADDRESS>
   ```
2. Update AKeyRA Helm values with contract address
3. Verify KeyRA can call `hasAccess()` via the RPC endpoint
