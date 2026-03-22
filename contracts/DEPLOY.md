# KeyRAAccessControl Deployment Guide

## Gas Costs

Measured via `forge test --gas-report` (Solidity 0.8.20, Paris EVM, optimizer 10k runs).

| Operation | Gas (median) | Type | Frequency |
|-----------|-------------|------|-----------|
| Deploy `KeyRAAccessControl` | 517,479 | Transaction | Once |
| `grantAccess(address)` | 47,813 | Transaction | Per user |
| `revokeAccess(address)` | 25,935 | Transaction | Rare |
| `addAdmin(address)` | 52,926 | Transaction | Rare |
| `removeAdmin(address)` | 28,699 | Transaction | Rare |
| `hasAccess(address)` | 2,545 | View (`eth_call`) | Every auth request |
| `isAdmin(address)` | 2,527 | View (`eth_call`) | On demand |

### ATN Cost

| Gas Price | Deploy | grantAccess | Deploy + 5 users |
|-----------|--------|-------------|------------------|
| 1 gwei | 0.000517 ATN | 0.000048 ATN | 0.000757 ATN |
| 5 gwei | 0.002587 ATN | 0.000239 ATN | 0.003783 ATN |
| 10 gwei | 0.005175 ATN | 0.000478 ATN | 0.007565 ATN |

> Measured from `forge test --gas-report` (24 tests, median values).
> Off-chain view calls (e.g., `eth_call`, `forge test`) consume gas for EVM
> execution but cost zero ATN because they are not sent as transactions; calling
> the same `view` functions via a transaction still costs gas/ATN.
> Use `--dry-run` to simulate deployment without broadcasting.

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
# Dry run — shows gas estimate, does NOT broadcast
./scripts/deploy-contract.sh --rpc <RPC_URL> --dry-run

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

# 3. Set deployer credentials
export DEPLOYER_KEY="<private-key>"
export MAINNET_RPC="<rpc-url>"
export ADMIN_ADDRESS="<your-address>"

# 4. Simulate first (no --broadcast = dry run)
forge create \
  --root contracts \
  --rpc-url "$MAINNET_RPC" \
  --private-key "$DEPLOYER_KEY" \
  src/AccessList.sol:KeyRAAccessControl \
  --constructor-args "$ADMIN_ADDRESS"

# 5. If simulation looks good, broadcast for real
forge create \
  --root contracts \
  --rpc-url "$MAINNET_RPC" \
  --private-key "$DEPLOYER_KEY" \
  --broadcast \
  src/AccessList.sol:KeyRAAccessControl \
  --constructor-args "$ADMIN_ADDRESS"

# 6. Verify deployment
export CONTRACT="<deployed-address>"
cast call --rpc-url "$MAINNET_RPC" "$CONTRACT" "isAdmin(address)(bool)" "$ADMIN_ADDRESS"
# Should return: true

# 7. Grant access to wallet(s)
cast send --rpc-url "$MAINNET_RPC" --private-key "$DEPLOYER_KEY" \
  "$CONTRACT" "grantAccess(address)" "<USER_ADDRESS>"

# 8. Verify access
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
