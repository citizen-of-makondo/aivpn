mod auth;
mod config;
mod handlers;
mod invite_store;
mod models;
mod rate_limit;
mod state;
mod templates;

use std::path::Path;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use aivpn_common::crypto::KeyPair;
use aivpn_common::network_config::{netmask_to_prefix_len, VpnNetworkConfig};
use aivpn_server::ClientDatabase;

use config::AdminConfig;
use invite_store::InviteStore;
use state::{AppState, AuditLogger};

#[derive(Debug, Clone, Default, Deserialize)]
struct ServerConfigFile {
    network_config: Option<VpnNetworkConfig>,
    tun_addr: Option<std::net::Ipv4Addr>,
    tun_netmask: Option<std::net::Ipv4Addr>,
}

#[tokio::main]
async fn main() {
    init_logging();

    let config = match AdminConfig::from_env() {
        Ok(v) => v,
        Err(e) => {
            error!("failed to load config: {e}");
            std::process::exit(1);
        }
    };

    let network_config = load_network_config_from_server_config(&config.config_dir);

    let client_db = match ClientDatabase::load(&config.clients_db_path(), network_config) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            error!("failed to load clients db: {e}");
            std::process::exit(1);
        }
    };

    let server_public_key_b64 = match load_server_public_key_b64(&config.server_key_path()) {
        Ok(v) => v,
        Err(e) => {
            error!("failed to load server key: {e}");
            std::process::exit(1);
        }
    };

    let invite_store = match InviteStore::new(config.invites_path()) {
        Ok(v) => Arc::new(v),
        Err(e) => {
            error!("failed to initialize invites store: {e}");
            std::process::exit(1);
        }
    };

    let audit = match AuditLogger::new(&config.audit_log_path()) {
        Ok(v) => v,
        Err(e) => {
            error!("failed to initialize audit log: {e}");
            std::process::exit(1);
        }
    };

    let state = Arc::new(AppState::new(
        config.clone(),
        client_db,
        invite_store,
        server_public_key_b64,
        audit,
    ));

    // Keep admin API view in sync with runtime client changes.
    {
        let client_db = state.client_db.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                client_db.reload_if_changed();
            }
        });
    }

    let api_routes = Router::new()
        .route("/login", post(handlers::api_login))
        .route("/logout", post(handlers::api_logout))
        .route("/clients", get(handlers::api_list_clients).post(handlers::api_create_client))
        .route("/clients/bulk", post(handlers::api_bulk_create_clients))
        .route("/clients/:id", get(handlers::api_get_client).delete(handlers::api_delete_client))
        .route("/clients/:id/enable", post(handlers::api_enable_client))
        .route("/clients/:id/disable", post(handlers::api_disable_client))
        .route(
            "/clients/:id/connection-key",
            get(handlers::api_get_connection_key),
        )
        .route("/clients/:id/qr", get(handlers::api_get_connection_qr))
        .route("/invites", get(handlers::api_list_invites).post(handlers::api_create_invite))
        .route("/invites/:id/revoke", post(handlers::api_revoke_invite));

    let app = Router::new()
        .route("/", get(handlers::get_dashboard))
        .route("/login", get(handlers::get_login))
        .route("/healthz", get(handlers::healthz))
        .nest("/api", api_routes)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(config.bind_addr).await {
        Ok(v) => v,
        Err(e) => {
            error!("failed to bind {}: {e}", config.bind_addr);
            std::process::exit(1);
        }
    };

    info!(
        "AIVPN admin started on {} (config dir: {})",
        config.bind_addr,
        config.config_dir.display()
    );

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    {
        error!("server error: {e}");
        std::process::exit(1);
    }
}

fn load_server_public_key_b64(path: &Path) -> Result<String, String> {
    let key_data = std::fs::read(path)
        .map_err(|e| format!("read {} failed: {}", path.display(), e))?;

    if key_data.len() != 32 {
        return Err(format!(
            "expected 32-byte server private key in {}, got {} bytes",
            path.display(),
            key_data.len()
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_data);

    let keypair = KeyPair::from_private_key(key);
    Ok(STANDARD.encode(keypair.public_key_bytes()))
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                EnvFilter::new("aivpn_admin=info,axum=info,tower_http=info")
            }),
        )
        .init();
}

fn load_network_config_from_server_config(config_dir: &Path) -> VpnNetworkConfig {
    let server_json = config_dir.join("server.json");
    let server_example = config_dir.join("server.json.example");
    let path = if server_json.exists() {
        server_json
    } else if server_example.exists() {
        server_example
    } else {
        return VpnNetworkConfig::default();
    };

    let raw = match std::fs::read_to_string(&path) {
        Ok(v) => v,
        Err(_) => return VpnNetworkConfig::default(),
    };

    let parsed: ServerConfigFile = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return VpnNetworkConfig::default(),
    };

    if let Some(cfg) = parsed.network_config {
        return cfg;
    }

    if let (Some(server_vpn_ip), Some(netmask)) = (parsed.tun_addr, parsed.tun_netmask) {
        let prefix_len = match netmask_to_prefix_len(netmask) {
            Ok(v) => v,
            Err(_) => return VpnNetworkConfig::default(),
        };
        return VpnNetworkConfig {
            server_vpn_ip,
            prefix_len,
            mtu: aivpn_common::network_config::DEFAULT_VPN_MTU,
        };
    }

    VpnNetworkConfig::default()
}
