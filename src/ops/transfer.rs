use crate::error::AppError;
use crate::types::AssetType;
use crate::key_mgmt::{load_ed25519_keypair_from_file, ss58_address_from_pair};
use crate::resolver::{expand_tilde_to_home, resolve_target_address_interactive};
use crate::config::{self, POLKADOT_SS58_PREFIX};
use crate::chain;
use std::path::PathBuf;
// Required for Subxt transactions
// use subxt::tx::{PairSigner, PolkadotExtrinsicParamsBuilder};
// use subxt:: ออนไลน์ไคลเอนต์;
// use sp_core::crypto::AccountId32;

pub async fn create_and_send_transfer(
    identity_file: &PathBuf,
    raw_amount: f64, // Amount from CLI (e.g., 1.5 DOT)
    target_identifier: &str,
    asset_type: AssetType,
) -> Result<(), AppError> {
    let expanded_id_path = expand_tilde_to_home(identity_file);
    let keypair = load_ed25519_keypair_from_file(&expanded_id_path)?;

    let from_ss58_address = ss58_address_from_pair(&keypair, POLKADOT_SS58_PREFIX); // Adjust prefix if chain-specific
    let to_ss58_address = resolve_target_address_interactive(target_identifier)?;

    // TODO: Convert raw_amount (f64) to on-chain u128 format using asset-specific decimals.
    // This is critical and needs proper handling.
    // let decimals = asset_type.decimals(); // Assuming AssetType has a method for decimals
    // let on_chain_amount = (raw_amount * 10f64.powi(decimals as i32)) as u128;
    let on_chain_amount: u128 = { // Highly simplified placeholder conversion!
        if raw_amount < 0.0 { return Err(AppError::InvalidAmount("Transfer amount cannot be negative.".to_string())); }
        (raw_amount * 1_000_000_000_000.0) as u128 // Example: Assuming 12 decimals if not DOT
    };


    println!(
        "Preparing to send {} {:?} from {} to {} (on-chain amount: {})",
        raw_amount, asset_type, from_ss58_address, to_ss58_address, on_chain_amount
    );

    // TODO: Implement actual transaction signing and submission
    match asset_type {
        AssetType::Dot => {
            eprintln!("Connecting to Polkadot Relay Chain to send DOT...");
            let relay_client_arc = chain::get_shared_relay_light_client(&config::POLKADOT_RELAY_CHAIN).await?;
            let (_light_client_ref, _rpc_ref) = &*relay_client_arc;

            // To sign and submit with subxt-lightclient, you might need to construct the extrinsic manually
            // and use `_rpc_ref.author_submit_extrinsic()`.
            // Or, if you can bridge to a full `OnlineClient` context:
            // let api = OnlineClient::from_rpc_client(_rpc_ref.client().clone()).await?; // Check compatibility
            // let signer = PairSigner::new(keypair);
            // let dest_account_id = AccountId32::from_ss58check(&to_ss58_address)?;
            // let tx_payload = polkadot_runtime::tx().balances().transfer_allow_death(dest_account_id.into(), on_chain_amount);
            // let tx_hash = api.tx().sign_and_submit_then_watch_default(&tx_payload, &signer).await?
            //     .wait_for_finalized_success().await?.extrinsic_hash();
            // println!("DOT transfer successful. Transaction hash: {:?}", tx_hash);
            eprintln!("(Actual DOT transfer submission logic is not yet implemented)");
        }
        asset => { // For other assets, assume Asset Hub Polkadot
            eprintln!("Connecting to Asset Hub Polkadot to send {:?}...", asset);
            let relay_client_arc = chain::get_shared_relay_light_client(&config::POLKADOT_RELAY_CHAIN).await?;
            let _parachain_rpc = chain::get_parachain_light_client_rpc(&relay_client_arc, &config::ASSET_HUB_POLKADOT_CHAIN).await?;
            // let on_chain_asset_id = asset as u32; // Or AssetType::on_chain_id()
            // Similar logic for constructing and submitting an Assets::transfer extrinsic
            eprintln!("(Actual {:?} transfer submission logic is not yet implemented)", asset);
        }
    }
    Ok(())
}
