use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct AdminConfig {
    pub bind_addr: SocketAddr,
    pub config_dir: PathBuf,
    pub server_addr: String,
    pub admin_user: String,
    pub admin_password_hash: String,
    pub session_secret: Vec<u8>,
    pub cookie_secure: bool,
    pub login_rate_limit_per_minute: usize,
    pub mutation_rate_limit_per_minute: usize,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Missing required env var: {0}")]
    MissingEnv(&'static str),
    #[error("Invalid env var {name}: {reason}")]
    InvalidEnv { name: &'static str, reason: String },
}

impl AdminConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = env::var("AIVPN_ADMIN_BIND")
            .unwrap_or_else(|_| "127.0.0.1:8081".to_string())
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::InvalidEnv {
                name: "AIVPN_ADMIN_BIND",
                reason: e.to_string(),
            })?;

        let config_dir = PathBuf::from(
            env::var("AIVPN_CONFIG_DIR").unwrap_or_else(|_| "/etc/aivpn".to_string()),
        );

        let server_addr = env::var("AIVPN_SERVER_ADDR")
            .map_err(|_| ConfigError::MissingEnv("AIVPN_SERVER_ADDR"))?;

        let admin_user = env::var("AIVPN_ADMIN_USER")
            .map_err(|_| ConfigError::MissingEnv("AIVPN_ADMIN_USER"))?;

        let admin_password_hash = env::var("AIVPN_ADMIN_PASSWORD_HASH")
            .map_err(|_| ConfigError::MissingEnv("AIVPN_ADMIN_PASSWORD_HASH"))?;

        let session_secret = env::var("AIVPN_SESSION_SECRET")
            .map_err(|_| ConfigError::MissingEnv("AIVPN_SESSION_SECRET"))?
            .into_bytes();

        if session_secret.len() < 32 {
            return Err(ConfigError::InvalidEnv {
                name: "AIVPN_SESSION_SECRET",
                reason: "must be at least 32 bytes".to_string(),
            });
        }

        let cookie_secure = env::var("AIVPN_COOKIE_SECURE")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(true);

        let login_rate_limit_per_minute = parse_usize_env(
            "AIVPN_LOGIN_RATE_LIMIT_PER_MINUTE",
            20,
        )?;

        let mutation_rate_limit_per_minute = parse_usize_env(
            "AIVPN_MUTATION_RATE_LIMIT_PER_MINUTE",
            120,
        )?;

        Ok(Self {
            bind_addr,
            config_dir,
            server_addr,
            admin_user,
            admin_password_hash,
            session_secret,
            cookie_secure,
            login_rate_limit_per_minute,
            mutation_rate_limit_per_minute,
        })
    }

    pub fn clients_db_path(&self) -> PathBuf {
        self.config_dir.join("clients.json")
    }

    pub fn server_key_path(&self) -> PathBuf {
        self.config_dir.join("server.key")
    }

    pub fn audit_log_path(&self) -> PathBuf {
        self.config_dir.join("admin-audit.log")
    }

    pub fn invites_path(&self) -> PathBuf {
        self.config_dir.join("invites.json")
    }
}

fn parse_usize_env(name: &'static str, default: usize) -> Result<usize, ConfigError> {
    let raw = match env::var(name) {
        Ok(v) => v,
        Err(_) => return Ok(default),
    };

    raw.parse::<usize>().map_err(|e| ConfigError::InvalidEnv {
        name,
        reason: e.to_string(),
    })
}
