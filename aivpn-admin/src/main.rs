mod auth;
mod config;
mod handlers;
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
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use aivpn_common::crypto::KeyPair;
use aivpn_server::ClientDatabase;

use config::AdminConfig;
use state::{AppState, AuditLogger};

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

    let client_db = match ClientDatabase::load(&config.clients_db_path()) {
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
        server_public_key_b64,
        audit,
    ));

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
        .route("/clients/:id/qr", get(handlers::api_get_connection_qr));

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
