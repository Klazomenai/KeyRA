#!/usr/bin/env bash
# Start Autonity node in dev mode for local development
#
# This script starts a single-node Autonity network suitable for testing
# the KeyRA auth flow. The dev account is pre-funded with ETH.
#
# Usage:
#   ./scripts/start-autonity.sh
#
# The node will listen on:
#   - HTTP RPC: http://127.0.0.1:8545
#   - WebSocket: ws://127.0.0.1:8546
#
# The script automatically funds the Foundry default test account
# (0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266) with 10 ETH for E2E tests.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

AUTONITY_BIN="${AUTONITY_BIN:-$PROJECT_DIR/autonity/build/bin/autonity}"
RPC_URL="http://127.0.0.1:8545"
TEST_ACCOUNT="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
FUND_AMOUNT="0x8ac7230489e80000"  # 10 ETH in wei

if [[ ! -x "$AUTONITY_BIN" ]]; then
    echo "Error: Autonity binary not found at $AUTONITY_BIN"
    echo ""
    echo "Clone and build Autonity:"
    echo "  git clone git@github.com:autonity/autonity.git $PROJECT_DIR/autonity"
    echo "  cd $PROJECT_DIR/autonity"
    echo "  go build -o ./build/bin/autonity ./cmd/autonity"
    exit 1
fi

echo "Starting Autonity dev node..."
echo "  HTTP RPC: $RPC_URL"
echo "  WebSocket: ws://127.0.0.1:8546"
echo ""

# Start Autonity in background
"$AUTONITY_BIN" --dev \
    --http \
    --http.port 8545 \
    --http.addr 127.0.0.1 \
    --http.api "eth,web3,net,debug,admin,personal" \
    --http.corsdomain "*" \
    --ws \
    --ws.port 8546 \
    --ws.addr 127.0.0.1 \
    --ws.api "eth,web3,net" \
    --verbosity 3 &

AUTONITY_PID=$!

# Cleanup on exit
cleanup() {
    echo ""
    echo "Stopping Autonity (PID: $AUTONITY_PID)..."
    kill $AUTONITY_PID 2>/dev/null || true
    wait $AUTONITY_PID 2>/dev/null || true
    echo "Stopped."
}
trap cleanup EXIT INT TERM

# Wait for RPC to be ready
echo "Waiting for RPC to be ready..."
for i in {1..30}; do
    if curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null | grep -q result; then
        echo "RPC ready after ${i}s"
        break
    fi
    if ! kill -0 $AUTONITY_PID 2>/dev/null; then
        echo "Error: Autonity process died"
        exit 1
    fi
    sleep 1
done

# Get dev account
DEV_ACCOUNT=$(curl -s -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}' | \
    grep -o '"0x[a-fA-F0-9]\{40\}"' | head -1 | tr -d '"')

if [[ -z "$DEV_ACCOUNT" ]]; then
    echo "Error: Could not get dev account"
    exit 1
fi

echo "Dev account: $DEV_ACCOUNT"

# Fund test account
echo "Funding test account $TEST_ACCOUNT with 10 ETH..."
TX_RESULT=$(curl -s -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$DEV_ACCOUNT\",\"to\":\"$TEST_ACCOUNT\",\"value\":\"$FUND_AMOUNT\"}],\"id\":1}")

TX_HASH=$(echo "$TX_RESULT" | grep -o '"0x[a-fA-F0-9]\{64\}"' | head -1 | tr -d '"')

if [[ -n "$TX_HASH" ]]; then
    echo "Funded! TX: $TX_HASH"

    # Wait for transaction to be mined
    echo "Waiting for transaction to be mined..."
    for i in {1..10}; do
        RECEIPT=$(curl -s -X POST "$RPC_URL" \
            -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$TX_HASH\"],\"id\":1}")
        if echo "$RECEIPT" | grep -q '"blockNumber"'; then
            echo "Transaction mined!"
            break
        fi
        sleep 1
    done
else
    echo "Warning: Funding may have failed: $TX_RESULT"
fi

# Verify balance
TEST_BALANCE=$(curl -s -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$TEST_ACCOUNT\", \"latest\"],\"id\":1}" | \
    grep -o '"0x[a-fA-F0-9]*"' | tail -1 | tr -d '"')

echo "Test account balance: $TEST_BALANCE (expected: $FUND_AMOUNT)"
echo ""
echo "Ready for E2E tests!"
echo "Press Ctrl+C to stop"
echo ""

# Wait for Autonity process
wait $AUTONITY_PID
