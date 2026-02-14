//! Test utilities for E2E tests

use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use std::str::FromStr;

/// Well-known dev account private key (Autonity --dev mode)
/// This is the standard dev account used by most Ethereum dev nodes
pub const DEV_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Create a test wallet from the dev private key
pub fn dev_wallet() -> (PrivateKeySigner, Address) {
    let signer = PrivateKeySigner::from_str(DEV_PRIVATE_KEY).expect("valid private key");
    let address = signer.address();
    (signer, address)
}

/// Deploy the KeyRAAccessControl contract
///
/// Returns the deployed contract address
pub async fn deploy_access_contract(
    rpc_url: &str,
    deployer: PrivateKeySigner,
    initial_admin: Address,
) -> Result<Address, Box<dyn std::error::Error + Send + Sync>> {
    let url: url::Url = rpc_url.parse()?;
    let wallet = EthereumWallet::from(deployer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(url);

    // Contract bytecode from forge build output
    // This is the compiled KeyRAAccessControl contract
    let bytecode = include_str!("../../contracts/out/AccessList.sol/KeyRAAccessControl.json");
    let artifact: serde_json::Value = serde_json::from_str(bytecode)?;
    let bytecode_hex = artifact["bytecode"]["object"]
        .as_str()
        .ok_or("missing bytecode")?;

    // Remove 0x prefix if present
    let bytecode_clean = bytecode_hex.trim_start_matches("0x");

    // Encode constructor argument (address)
    let mut deploy_data = hex::decode(bytecode_clean)?;
    // ABI encode the address (32 bytes, left-padded)
    let mut addr_bytes = [0u8; 32];
    addr_bytes[12..32].copy_from_slice(initial_admin.as_slice());
    deploy_data.extend_from_slice(&addr_bytes);

    // Send deployment transaction
    let tx = alloy::rpc::types::TransactionRequest::default()
        .with_deploy_code(deploy_data);

    let pending = provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;

    receipt
        .contract_address
        .ok_or_else(|| "no contract address in receipt".into())
}

/// Grant access to an address via the contract
pub async fn grant_access(
    rpc_url: &str,
    admin: PrivateKeySigner,
    contract_address: Address,
    account: Address,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface IKeyRAAccessControl {
            function grantAccess(address account) external;
        }
    }

    let url: url::Url = rpc_url.parse()?;
    let wallet = EthereumWallet::from(admin);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(url);

    let contract = IKeyRAAccessControl::new(contract_address, provider);
    let tx = contract.grantAccess(account).send().await?;
    tx.get_receipt().await?;

    Ok(())
}

/// Sign a message using EIP-191 personal_sign format
pub fn sign_message(signer: &PrivateKeySigner, message: &str) -> Vec<u8> {
    // EIP-191 personal message prefix is handled by sign_message
    let sig = signer
        .sign_message_sync(message.as_bytes())
        .expect("signing failed");

    // Return as 65-byte signature (r, s, v)
    // Use as_bytes() to get the full 65-byte representation
    sig.as_bytes().to_vec()
}

/// Check if Autonity node is running
pub async fn is_node_running(rpc_url: &str) -> bool {
    let url: url::Url = match rpc_url.parse() {
        Ok(u) => u,
        Err(_) => return false,
    };
    let provider = ProviderBuilder::new().connect_http(url);

    match provider.get_block_number().await {
        Ok(_) => true,
        Err(_) => false,
    }
}
