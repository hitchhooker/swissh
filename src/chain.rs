use crate::error::AppError;
use crate::config::{ChainMetadata, get_chain_specs_cache_dir, get_light_client_db_dir};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::OnceCell;
use subxt_lightclient::{LightClient, ChainConfig, LightClientRpc};

// Type aliases for clarity
pub type SharedRelayLightClient = Arc<(LightClient, LightClientRpc)>;
pub type ParachainLightClientRpc = LightClientRpc;

static POLKADOT_RELAY_CLIENT_INSTANCE: OnceCell<SharedRelayLightClient> = OnceCell::const_new();

/// Ensures a chain specification file is downloaded and returns its local path.
pub async fn ensure_chain_spec_file_cached(chain_meta: &ChainMetadata) -> Result<PathBuf, AppError> {
    let specs_cache_dir = get_chain_specs_cache_dir()?;
    fs::create_dir_all(&specs_cache_dir)
        .map_err(|e| AppError::FileSystem { path: specs_cache_dir.clone(), source: e })?;

    let local_spec_path = specs_cache_dir.join(chain_meta.spec_filename);
    if !local_spec_path.exists() {
        eprintln!("Downloading chain specification for {} to {}...", chain_meta.name, local_spec_path.display());
        let spec_contents = reqwest::get(chain_meta.spec_url).await?.text().await?;
        fs::write(&local_spec_path, spec_contents)
            .map_err(|e| AppError::FileSystem { path: local_spec_path.clone(), source: e })?;
        eprintln!("Successfully downloaded {}.", chain_meta.spec_filename);
    }
    Ok(local_spec_path)
}

/// Initializes and returns a shared, persistent Polkadot relay chain light client.
pub async fn get_shared_relay_light_client(relay_chain_meta: &'static ChainMetadata) -> Result<SharedRelayLightClient, AppError> {
    POLKADOT_RELAY_CLIENT_INSTANCE.get_or_try_init(|| async {
        let local_spec_path = ensure_chain_spec_file_cached(relay_chain_meta).await?;
        
        // Note: client_specific_db_path is prepared here, but not directly used by this version of ChainConfig's API.
        // Smoldot will use an in-memory DB by default as configured by subxt-lightclient.
        let base_db_dir = get_light_client_db_dir()?;
        let client_specific_db_path = relay_chain_meta.light_client_db_path(&base_db_dir);
        if let Some(parent_dir) = client_specific_db_path.parent() { // Still good to ensure app dirs exist
            fs::create_dir_all(parent_dir)
                .map_err(|e| AppError::FileSystem { path: parent_dir.to_path_buf(), source: e })?;
        }

        // Read the spec file content into a string
        let spec_content_string = fs::read_to_string(&local_spec_path)
            .map_err(|e| AppError::FileSystem { path: local_spec_path.clone(), source: e })?;

        eprintln!("Initializing Polkadot relay light client (Name: {})... (using content from spec file)", relay_chain_meta.name);
        // Construct ChainConfig using the spec content directly.
        // The .db() and .name() methods are not available on this version of subxt_lightclient::ChainConfig.
        let chain_config = ChainConfig::chain_spec(spec_content_string);

        LightClient::relay_chain(chain_config)
            .map(Arc::new)
            .map_err(|e| AppError::LightClient(format!("Failed to initialize relay light client for {}: {}", relay_chain_meta.name, e)))
    }).await.cloned()
}

/// Initializes and returns a parachain light client RPC interface.
pub async fn get_parachain_light_client_rpc(
    shared_relay_client: &SharedRelayLightClient,
    parachain_meta: &'static ChainMetadata,
) -> Result<ParachainLightClientRpc, AppError> {
    let (relay_light_client_instance, _relay_rpc) = &**shared_relay_client;

    let local_spec_path = ensure_chain_spec_file_cached(parachain_meta).await?;

    // Similar to relay client, DB path prepared but not used by ChainConfig API.
    let base_db_dir = get_light_client_db_dir()?;
    let client_specific_db_path = parachain_meta.light_client_db_path(&base_db_dir);
    if let Some(parent_dir) = client_specific_db_path.parent() {
        fs::create_dir_all(parent_dir)
            .map_err(|e| AppError::FileSystem { path: parent_dir.to_path_buf(), source: e })?;
    }
    
    let spec_content_string = fs::read_to_string(&local_spec_path)
        .map_err(|e| AppError::FileSystem { path: local_spec_path.clone(), source: e })?;

    eprintln!("Initializing {} parachain light client... (using content from spec file)", parachain_meta.name);
    // Construct ChainConfig using the spec content directly.
    let chain_config = ChainConfig::chain_spec(spec_content_string);

    relay_light_client_instance.parachain(chain_config)
        .map_err(|e| AppError::LightClient(format!("Failed to initialize parachain light client for {}: {}", parachain_meta.name, e)))
}
