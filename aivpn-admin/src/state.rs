use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;

use aivpn_server::ClientDatabase;

use crate::config::AdminConfig;
use crate::rate_limit::SlidingWindowRateLimiter;

pub struct AuditLogger {
    file: Mutex<File>,
}

impl AuditLogger {
    pub fn new(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        Ok(Self {
            file: Mutex::new(file),
        })
    }

    pub fn log(
        &self,
        action: &str,
        actor: &str,
        target: Option<&str>,
        ip: IpAddr,
        success: bool,
        details: &str,
    ) {
        let ts = Utc::now().to_rfc3339();
        let target = target.unwrap_or("-");
        let outcome = if success { "ok" } else { "fail" };
        let line = format!(
            "{ts} action={action} actor={actor} target={target} ip={ip} outcome={outcome} details={details}\n"
        );

        if let Ok(mut file) = self.file.lock() {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
    }
}

pub struct AppState {
    pub config: AdminConfig,
    pub client_db: Arc<ClientDatabase>,
    pub server_public_key_b64: String,
    pub login_limiter: SlidingWindowRateLimiter,
    pub mutation_limiter: SlidingWindowRateLimiter,
    pub audit: AuditLogger,
}

impl AppState {
    pub fn new(
        config: AdminConfig,
        client_db: Arc<ClientDatabase>,
        server_public_key_b64: String,
        audit: AuditLogger,
    ) -> Self {
        Self {
            login_limiter: SlidingWindowRateLimiter::new(
                config.login_rate_limit_per_minute,
                Duration::from_secs(60),
            ),
            mutation_limiter: SlidingWindowRateLimiter::new(
                config.mutation_rate_limit_per_minute,
                Duration::from_secs(60),
            ),
            config,
            client_db,
            server_public_key_b64,
            audit,
        }
    }
}
