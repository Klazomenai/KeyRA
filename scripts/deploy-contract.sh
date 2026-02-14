#!/usr/bin/env bash
# Deploy KeyRAAccessControl contract to local Autonity dev node
#
# This script:
#   1. Creates admin and read-only accounts (or uses existing)
#   2. Funds both accounts from the Autonity dev account
#   3. Deploys the KeyRAAccessControl contract
#   4. Grants access to the read-only account
#   5. Outputs account details for MetaMask import
#
# Usage:
#   ./scripts/deploy-contract.sh [OPTIONS]
#
# Options:
#   --rpc URL           RPC endpoint (default: http://127.0.0.1:8545)
#   --show-keys         Display private keys in output (for MetaMask import)
#   --clean             Remove existing keys and start fresh
#   --help              Show this help message
#
# Requires: Foundry (cast, forge) - available via `devenv shell`

set -euo pipefail

# Constants
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTRACTS_DIR="$PROJECT_DIR/contracts"
CONTRACT_SRC="src/AccessList.sol:KeyRAAccessControl"
KEYS_DIR="$PROJECT_DIR/.keys"

# Defaults
RPC_URL="http://127.0.0.1:8545"
SHOW_KEYS=false
CLEAN=false

# Key file names
ADMIN_KEY_FILE="$KEYS_DIR/admin.key"
READONLY_KEY_FILE="$KEYS_DIR/readonly.key"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --rpc)
            RPC_URL="$2"
            shift 2
            ;;
        --show-keys)
            SHOW_KEYS=true
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --help|-h)
            sed -n '2,20p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Utility functions
log() {
    echo "[deploy] $*" >&2
}

error() {
    echo "[deploy] ERROR: $*" >&2
    exit 1
}

# Check if RPC is available
check_rpc() {
    log "Checking RPC endpoint: $RPC_URL"
    if ! cast client --rpc-url "$RPC_URL" &>/dev/null; then
        error "Autonity node not reachable at $RPC_URL. Start it with: ./scripts/start-autonity.sh"
    fi
    log "RPC is ready"
}

# Check prerequisites
check_prerequisites() {
    # Check cast
    if ! command -v cast &>/dev/null; then
        error "cast not found. Enter devenv shell: devenv shell"
    fi

    # Check forge
    if ! command -v forge &>/dev/null; then
        error "forge not found. Enter devenv shell: devenv shell"
    fi

    # Check RPC
    check_rpc

    # Ensure keys directory exists
    mkdir -p "$KEYS_DIR"

    # Add .keys to .gitignore if not already there
    if [[ -f "$PROJECT_DIR/.gitignore" ]]; then
        if ! grep -q "^\.keys" "$PROJECT_DIR/.gitignore"; then
            echo ".keys/" >> "$PROJECT_DIR/.gitignore"
            log "Added .keys/ to .gitignore"
        fi
    fi
}

# Get dev account from Autonity (pre-funded, unlocked)
get_dev_account() {
    cast rpc --rpc-url "$RPC_URL" eth_accounts | jq -r '.[0]'
}

# Create or load account
# Returns: address
# Side effect: writes private key to file
ensure_account() {
    local name="$1"
    local key_file="$2"

    if [[ -f "$key_file" && "$CLEAN" != "true" ]]; then
        log "Loading existing $name account"
        local privkey
        privkey=$(cat "$key_file")
        cast wallet address "$privkey"
        return
    fi

    log "Creating new $name account"
    local wallet_output
    wallet_output=$(cast wallet new)

    # Parse output: "Successfully created new keypair.\nAddress: 0x...\nPrivate key: 0x..."
    local address privkey
    address=$(echo "$wallet_output" | grep "Address:" | awk '{print $2}')
    privkey=$(echo "$wallet_output" | grep "Private key:" | awk '{print $3}')

    # Save private key
    echo "$privkey" > "$key_file"
    chmod 600 "$key_file"

    log "Created $name: $address"
    echo "$address"
}

# Fund account from dev account
fund_account() {
    local to_address="$1"
    local dev_account="$2"
    local amount="10ether"

    # Check current balance
    local balance
    balance=$(cast balance --rpc-url "$RPC_URL" "$to_address")

    # If balance > 1 ETH, skip funding
    if [[ $(echo "$balance" | cut -d'.' -f1) -gt 0 ]]; then
        log "Account $to_address already funded (balance: $balance)"
        return
    fi

    log "Funding $to_address with 10 ETH..."

    # Send from unlocked dev account (value must be hex)
    local value_hex tx_hash
    value_hex=$(cast to-wei 10 ether | cast to-hex)
    tx_hash=$(cast rpc --rpc-url "$RPC_URL" eth_sendTransaction \
        "{\"from\":\"$dev_account\",\"to\":\"$to_address\",\"value\":\"$value_hex\"}" | jq -r '.')

    log "Funding tx: $tx_hash"

    # Wait for confirmation
    cast receipt --rpc-url "$RPC_URL" "$tx_hash" --confirmations 1 &>/dev/null
    log "Funded!"
}

# Deploy contract using forge
deploy_contract() {
    local privkey="$1"
    local admin_address="$2"

    log "Deploying KeyRAAccessControl contract..."
    log "  Admin: $admin_address"

    # Deploy using forge create (CONTRACT must come before --constructor-args)
    local output
    output=$(forge create \
        --root "$CONTRACTS_DIR" \
        --rpc-url "$RPC_URL" \
        --private-key "$privkey" \
        --broadcast \
        "$CONTRACT_SRC" \
        --constructor-args "$admin_address" 2>&1)

    # Extract deployed address
    local contract_address
    contract_address=$(echo "$output" | grep "Deployed to:" | awk '{print $3}')

    if [[ -z "$contract_address" ]]; then
        error "Failed to deploy contract. Output:\n$output"
    fi

    log "Contract deployed at: $contract_address"

    # Save contract address for reuse
    echo "$contract_address" > "$KEYS_DIR/contract.address"
    log "Saved contract address to $KEYS_DIR/contract.address"

    echo "$contract_address"
}

# Grant access to an address
grant_access() {
    local contract_address="$1"
    local privkey="$2"
    local target_address="$3"

    log "Granting access to: $target_address"

    cast send \
        --rpc-url "$RPC_URL" \
        --private-key "$privkey" \
        "$contract_address" \
        "grantAccess(address)" \
        "$target_address" \
        &>/dev/null

    log "Access granted!"
}

# Verify contract deployment
verify_deployment() {
    local contract_address="$1"
    local admin_address="$2"
    local readonly_address="$3"

    log "Verifying deployment..."

    # Check isAdmin
    local is_admin
    is_admin=$(cast call --rpc-url "$RPC_URL" "$contract_address" "isAdmin(address)(bool)" "$admin_address")

    if [[ "$is_admin" != "true" ]]; then
        error "Admin verification failed. isAdmin($admin_address) = $is_admin"
    fi
    log "Admin verified: $admin_address"

    # Check hasAccess for readonly
    local has_access
    has_access=$(cast call --rpc-url "$RPC_URL" "$contract_address" "hasAccess(address)(bool)" "$readonly_address")

    if [[ "$has_access" != "true" ]]; then
        error "Access verification failed. hasAccess($readonly_address) = $has_access"
    fi
    log "Read-only access verified: $readonly_address"
}

# Main
main() {
    log "KeyRA Contract Deployment"
    log "========================="

    # Clean if requested
    if [[ "$CLEAN" == "true" && -d "$KEYS_DIR" ]]; then
        log "Cleaning existing keys..."
        rm -rf "$KEYS_DIR"
    fi

    # Check prerequisites
    check_prerequisites

    # Get dev account
    local dev_account
    dev_account=$(get_dev_account)
    if [[ -z "$dev_account" || "$dev_account" == "null" ]]; then
        error "Could not get dev account from Autonity"
    fi
    log "Dev account: $dev_account"

    # Create/load accounts
    local admin_address readonly_address
    admin_address=$(ensure_account "admin" "$ADMIN_KEY_FILE")
    readonly_address=$(ensure_account "readonly" "$READONLY_KEY_FILE")

    log "Admin address: $admin_address"
    log "Read-only address: $readonly_address"

    # Load private keys
    local admin_privkey readonly_privkey
    admin_privkey=$(cat "$ADMIN_KEY_FILE")
    readonly_privkey=$(cat "$READONLY_KEY_FILE")

    # Fund accounts
    fund_account "$admin_address" "$dev_account"
    fund_account "$readonly_address" "$dev_account"

    # Deploy contract
    local contract_address
    contract_address=$(deploy_contract "$admin_privkey" "$admin_address")

    # Grant access to read-only account
    grant_access "$contract_address" "$admin_privkey" "$readonly_address"

    # Verify
    verify_deployment "$contract_address" "$admin_address" "$readonly_address"

    # Output summary
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "KeyRA Contract Deployment Complete"
    echo "═══════════════════════════════════════════════════"
    echo ""
    echo "Contract Address: $contract_address"
    echo "  Saved to: $KEYS_DIR/contract.address"
    echo ""
    echo "Admin Account:"
    echo "  Address: $admin_address"
    echo "  Keyfile: $ADMIN_KEY_FILE"
    echo ""
    echo "Read-Only Account (for MetaMask):"
    echo "  Address: $readonly_address"
    echo "  Keyfile: $READONLY_KEY_FILE"
    echo ""

    if [[ "$SHOW_KEYS" == "true" ]]; then
        echo "Private Keys (SAVE THESE SECURELY):"
        echo "  Admin:     $admin_privkey"
        echo "  Read-Only: $readonly_privkey"
        echo ""
    else
        echo "To show private keys, run with --show-keys"
        echo ""
    fi

    # Get chain ID from the node
    local chain_id
    chain_id=$(cast chain-id --rpc-url "$RPC_URL")

    echo "To run the server with this contract:"
    echo "  CONTRACT_ADDRESS=$contract_address CHAIN_ID=$chain_id cargo run"
    echo ""
    echo "═══════════════════════════════════════════════════"
}

main "$@"
