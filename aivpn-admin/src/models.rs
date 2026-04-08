use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use aivpn_server::client_db::ClientConfig;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct BulkCreateRequest {
    pub prefix: String,
    pub count: usize,
    pub start_index: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ClientResponse {
    pub id: String,
    pub name: String,
    pub vpn_ip: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub total_connections: u64,
    pub last_connected: Option<DateTime<Utc>>,
    pub last_handshake: Option<DateTime<Utc>>,
}

impl From<ClientConfig> for ClientResponse {
    fn from(value: ClientConfig) -> Self {
        Self {
            id: value.id,
            name: value.name,
            vpn_ip: value.vpn_ip.to_string(),
            enabled: value.enabled,
            created_at: value.created_at,
            bytes_in: value.stats.bytes_in,
            bytes_out: value.stats.bytes_out,
            total_connections: value.stats.total_connections,
            last_connected: value.stats.last_connected,
            last_handshake: value.stats.last_handshake,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BulkCreateFailure {
    pub name: String,
    pub error: String,
}

#[derive(Debug, Serialize)]
pub struct BulkCreateResponse {
    pub created: Vec<ClientResponse>,
    pub failed: Vec<BulkCreateFailure>,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Serialize)]
pub struct ConnectionKeyResponse {
    pub connection_key: String,
}
