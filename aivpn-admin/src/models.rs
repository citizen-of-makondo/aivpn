use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::invite_store::InviteRecord;
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
    pub online: bool,
    pub last_seen_seconds: Option<i64>,
}

impl ClientResponse {
    pub fn from_client(value: ClientConfig, now: DateTime<Utc>) -> Self {
        let last_connected_age = age_seconds(now, value.stats.last_connected);
        let last_handshake_age = age_seconds(now, value.stats.last_handshake);
        let online = matches!(last_handshake_age, Some(v) if v <= 300)
            || matches!(last_connected_age, Some(v) if v <= 60);
        let last_seen_seconds = match (last_connected_age, last_handshake_age) {
            (Some(a), Some(b)) => Some(std::cmp::min(a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

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
            online,
            last_seen_seconds,
        }
    }
}

fn age_seconds(now: DateTime<Utc>, timestamp: Option<DateTime<Utc>>) -> Option<i64> {
    timestamp.map(|value| {
        let secs = now.signed_duration_since(value).num_seconds();
        std::cmp::max(secs, 0)
    })
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

#[derive(Debug, Serialize)]
pub struct InviteResponse {
    pub id: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub used_by_tg_id: Option<i64>,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<InviteRecord> for InviteResponse {
    fn from(value: InviteRecord) -> Self {
        Self {
            id: value.id,
            status: format!("{:?}", value.status).to_lowercase(),
            created_at: value.created_at,
            used_by_tg_id: value.used_by_tg_id,
            used_at: value.used_at,
            revoked_at: value.revoked_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CreateInviteResponse {
    pub invite: InviteResponse,
    pub code: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn client_with_times(
        last_connected: Option<DateTime<Utc>>,
        last_handshake: Option<DateTime<Utc>>,
    ) -> ClientConfig {
        ClientConfig {
            id: "id1".to_string(),
            name: "client-1".to_string(),
            psk: [1u8; 32],
            vpn_ip: "10.0.0.2".parse().unwrap(),
            enabled: true,
            created_at: Utc::now(),
            stats: aivpn_server::client_db::ClientStats {
                bytes_in: 1,
                bytes_out: 2,
                total_connections: 3,
                last_connected,
                last_handshake,
            },
        }
    }

    #[test]
    fn online_when_recent_handshake() {
        let now = Utc::now();
        let client = client_with_times(None, Some(now - Duration::seconds(12)));
        let out = ClientResponse::from_client(client, now);
        assert!(out.online);
        assert_eq!(out.last_seen_seconds, Some(12));
    }

    #[test]
    fn offline_when_stale_timestamps() {
        let now = Utc::now();
        let client = client_with_times(
            Some(now - Duration::seconds(400)),
            Some(now - Duration::seconds(800)),
        );
        let out = ClientResponse::from_client(client, now);
        assert!(!out.online);
        assert_eq!(out.last_seen_seconds, Some(400));
    }
}
