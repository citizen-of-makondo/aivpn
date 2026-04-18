use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use fs2::FileExt;
use image::{ImageFormat, Luma};
use qrcode::QrCode;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use teloxide::prelude::*;
use teloxide::types::InputFile;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use aivpn_common::crypto::KeyPair;
use aivpn_common::network_config::{netmask_to_prefix_len, VpnNetworkConfig};
use aivpn_server::client_db::ClientConfig;
use aivpn_server::ClientDatabase;

#[derive(Debug, Clone)]
struct BotConfig {
    tg_bot_token: String,
    config_dir: PathBuf,
    server_addr: String,
    redeem_rate_per_minute: usize,
}

impl BotConfig {
    fn from_env() -> Result<Self, String> {
        let tg_bot_token = std::env::var("AIVPN_TG_BOT_TOKEN")
            .map_err(|_| "Missing AIVPN_TG_BOT_TOKEN".to_string())?;

        let config_dir = PathBuf::from(
            std::env::var("AIVPN_CONFIG_DIR").unwrap_or_else(|_| "/etc/aivpn".to_string()),
        );

        let server_addr = std::env::var("AIVPN_SERVER_ADDR")
            .map_err(|_| "Missing AIVPN_SERVER_ADDR".to_string())?;

        let redeem_rate_per_minute = std::env::var("AIVPN_TG_REDEEM_RATE_PER_MINUTE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(6);

        Ok(Self {
            tg_bot_token,
            config_dir,
            server_addr,
            redeem_rate_per_minute,
        })
    }

    fn clients_db_path(&self) -> PathBuf {
        self.config_dir.join("clients.json")
    }

    fn server_key_path(&self) -> PathBuf {
        self.config_dir.join("server.key")
    }

    fn invites_path(&self) -> PathBuf {
        self.config_dir.join("invites.json")
    }

    fn tg_users_path(&self) -> PathBuf {
        self.config_dir.join("tg_users.json")
    }

    fn audit_log_path(&self) -> PathBuf {
        self.config_dir.join("admin-audit.log")
    }
}

#[derive(Clone)]
struct BotState {
    config: BotConfig,
    client_db: Arc<ClientDatabase>,
    server_public_key_b64: String,
    invite_store: Arc<InviteStore>,
    tg_users: Arc<TgUserStore>,
    limiter: Arc<RedeemRateLimiter>,
    audit: Arc<AuditLogger>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ServerConfigFile {
    network_config: Option<VpnNetworkConfig>,
    tun_addr: Option<Ipv4Addr>,
    tun_netmask: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum InviteStatus {
    Active,
    Used,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InviteRecord {
    id: String,
    code_hash: String,
    status: InviteStatus,
    created_at: DateTime<Utc>,
    used_by_tg_id: Option<i64>,
    used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct InviteFileData {
    invites: Vec<InviteRecord>,
}

#[derive(Debug, Clone)]
struct InviteStore {
    path: PathBuf,
}

impl InviteStore {
    fn new(path: PathBuf) -> std::io::Result<Self> {
        ensure_parent_dir(&path)?;
        if !path.exists() {
            let initial = InviteFileData::default();
            let json = serde_json::to_string_pretty(&initial).map_err(to_io_error)?;
            std::fs::write(&path, json)?;
        }
        Ok(Self { path })
    }

    fn redeem_code(&self, code: &str, tg_user_id: i64) -> Result<InviteRecord, String> {
        let code_hash = hash_code(code.trim());
        self.with_locked_data(true, |data| {
            let now = Utc::now();
            let invite = data
                .invites
                .iter_mut()
                .find(|row| row.code_hash == code_hash)
                .ok_or_else(|| "Invite code is invalid".to_string())?;

            match invite.status {
                InviteStatus::Active => {
                    invite.status = InviteStatus::Used;
                    invite.used_by_tg_id = Some(tg_user_id);
                    invite.used_at = Some(now);
                    Ok(invite.clone())
                }
                InviteStatus::Used => Err("Invite code has already been used".to_string()),
                InviteStatus::Revoked => Err("Invite code has been revoked".to_string()),
            }
        })
    }

    fn with_locked_data<T, F>(&self, write_back: bool, f: F) -> Result<T, String>
    where
        F: FnOnce(&mut InviteFileData) -> Result<T, String>,
    {
        ensure_parent_dir(&self.path).map_err(|e| e.to_string())?;
        let mut file = open_rw_create(&self.path).map_err(|e| e.to_string())?;
        file.lock_exclusive().map_err(|e| e.to_string())?;

        let mut data = read_data::<InviteFileData>(&mut file).map_err(|e| e.to_string())?;
        let result = f(&mut data);

        if write_back && result.is_ok() {
            write_data_atomic(&self.path, &data).map_err(|e| e.to_string())?;
        }

        result
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TgUserBinding {
    tg_user_id: i64,
    tg_username: Option<String>,
    client_id: String,
    invite_id: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TgUsersFileData {
    users: Vec<TgUserBinding>,
}

#[derive(Debug, Clone)]
struct TgUserStore {
    path: PathBuf,
}

impl TgUserStore {
    fn new(path: PathBuf) -> std::io::Result<Self> {
        ensure_parent_dir(&path)?;
        if !path.exists() {
            let initial = TgUsersFileData::default();
            let json = serde_json::to_string_pretty(&initial).map_err(to_io_error)?;
            std::fs::write(&path, json)?;
        }
        Ok(Self { path })
    }

    fn get(&self, tg_user_id: i64) -> Result<Option<TgUserBinding>, String> {
        self.with_locked_data(false, |data| {
            Ok(data
                .users
                .iter()
                .find(|row| row.tg_user_id == tg_user_id)
                .cloned())
        })
    }

    fn upsert(&self, binding: TgUserBinding) -> Result<(), String> {
        self.with_locked_data(true, |data| {
            if let Some(existing) = data.users.iter_mut().find(|row| row.tg_user_id == binding.tg_user_id)
            {
                *existing = binding;
            } else {
                data.users.push(binding);
            }
            Ok(())
        })
    }

    fn with_locked_data<T, F>(&self, write_back: bool, f: F) -> Result<T, String>
    where
        F: FnOnce(&mut TgUsersFileData) -> Result<T, String>,
    {
        ensure_parent_dir(&self.path).map_err(|e| e.to_string())?;
        let mut file = open_rw_create(&self.path).map_err(|e| e.to_string())?;
        file.lock_exclusive().map_err(|e| e.to_string())?;

        let mut data = read_data::<TgUsersFileData>(&mut file).map_err(|e| e.to_string())?;
        let result = f(&mut data);

        if write_back && result.is_ok() {
            write_data_atomic(&self.path, &data).map_err(|e| e.to_string())?;
        }

        result
    }
}

struct AuditLogger {
    file: Mutex<File>,
}

impl AuditLogger {
    fn new(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    fn log(
        &self,
        action: &str,
        actor: &str,
        target: Option<&str>,
        success: bool,
        details: &str,
    ) {
        let ts = Utc::now().to_rfc3339();
        let target = target.unwrap_or("-");
        let outcome = if success { "ok" } else { "fail" };
        let line = format!(
            "{ts} action={action} actor={actor} target={target} ip=- outcome={outcome} details={details}\n"
        );

        if let Ok(mut file) = self.file.lock() {
            let _ = std::io::Write::write_all(&mut *file, line.as_bytes());
            let _ = std::io::Write::flush(&mut *file);
        }
    }
}

struct RedeemRateLimiter {
    limit: usize,
    window: Duration,
    slots: DashMap<i64, Vec<Instant>>,
}

impl RedeemRateLimiter {
    fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            slots: DashMap::new(),
        }
    }

    fn allow(&self, key: i64) -> bool {
        let now = Instant::now();
        let mut entry = self.slots.entry(key).or_default();
        entry.retain(|ts| now.duration_since(*ts) <= self.window);
        if entry.len() >= self.limit {
            return false;
        }
        entry.push(now);
        true
    }
}

#[tokio::main]
async fn main() {
    init_logging();

    let config = match BotConfig::from_env() {
        Ok(v) => v,
        Err(e) => {
            error!("failed to load config: {e}");
            std::process::exit(1);
        }
    };

    let network_config = load_network_config_from_server_config(&config.config_dir);
    let client_db = match ClientDatabase::load(&config.clients_db_path(), network_config) {
        Ok(v) => Arc::new(v),
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

    let tg_users = match TgUserStore::new(config.tg_users_path()) {
        Ok(v) => Arc::new(v),
        Err(e) => {
            error!("failed to initialize tg_users store: {e}");
            std::process::exit(1);
        }
    };

    let audit = match AuditLogger::new(&config.audit_log_path()) {
        Ok(v) => Arc::new(v),
        Err(e) => {
            error!("failed to initialize audit logger: {e}");
            std::process::exit(1);
        }
    };

    let state = Arc::new(BotState {
        config: config.clone(),
        client_db: client_db.clone(),
        server_public_key_b64,
        invite_store,
        tg_users,
        limiter: Arc::new(RedeemRateLimiter::new(
            config.redeem_rate_per_minute,
            Duration::from_secs(60),
        )),
        audit,
    });

    {
        let db = client_db.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                db.reload_if_changed();
            }
        });
    }

    let bot = Bot::new(config.tg_bot_token);

    info!(
        "AIVPN telegram bot started (config dir: {}, server addr: {})",
        config.config_dir.display(),
        config.server_addr
    );

    Dispatcher::builder(bot, Update::filter_message().endpoint(handle_message))
        .dependencies(dptree::deps![state])
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;
}

async fn handle_message(bot: Bot, msg: Message, state: Arc<BotState>) -> ResponseResult<()> {
    let Some(user) = msg.from.as_ref() else {
        return Ok(());
    };

    let tg_user_id = user.id.0 as i64;
    let chat_id = msg.chat.id;

    let existing = state.tg_users.get(tg_user_id).ok().flatten();
    let text = msg.text().unwrap_or("").trim();

    if let Some(binding) = existing {
        if text.starts_with("/start") || text.starts_with("/key") || text.is_empty() {
            match state.client_db.find_by_id(&binding.client_id) {
                Some(client) => {
                    if let Err(e) = send_key_with_qr(&bot, chat_id, &state, &client).await {
                        warn!("failed to send existing key to tg_user_id={}: {}", tg_user_id, e);
                        bot.send_message(chat_id, "Failed to build your key, contact admin.")
                            .await?;
                    }
                    return Ok(());
                }
                None => {
                    let recreate = find_or_create_client_for_user(&state.client_db, tg_user_id);
                    match recreate {
                        Ok(client) => {
                            let _ = state.tg_users.upsert(TgUserBinding {
                                tg_user_id,
                                tg_username: user.username.clone(),
                                client_id: client.id.clone(),
                                invite_id: binding.invite_id.clone(),
                                created_at: binding.created_at,
                            });
                            let _ = send_key_with_qr(&bot, chat_id, &state, &client).await;
                            return Ok(());
                        }
                        Err(e) => {
                            bot.send_message(chat_id, format!("Failed to recreate your access: {e}"))
                                .await?;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    let maybe_code = parse_invite_code(text);
    if maybe_code.is_none() {
        bot.send_message(
            chat_id,
            "Send your invite code to get VPN key. Example: ABCD-EFGH-JKLM-NPQR",
        )
        .await?;
        return Ok(());
    }

    if !state.limiter.allow(tg_user_id) {
        bot.send_message(chat_id, "Too many attempts. Try again in one minute.")
            .await?;
        return Ok(());
    }

    let code = maybe_code.unwrap();
    let redeemed = match state.invite_store.redeem_code(&code, tg_user_id) {
        Ok(v) => v,
        Err(e) => {
            state.audit.log(
                "invite_use",
                &format!("tg:{tg_user_id}"),
                None,
                false,
                &e,
            );
            bot.send_message(chat_id, e).await?;
            return Ok(());
        }
    };

    let client = match find_or_create_client_for_user(&state.client_db, tg_user_id) {
        Ok(v) => v,
        Err(e) => {
            bot.send_message(chat_id, format!("Failed to create VPN profile: {e}"))
                .await?;
            return Ok(());
        }
    };

    let binding = TgUserBinding {
        tg_user_id,
        tg_username: user.username.clone(),
        client_id: client.id.clone(),
        invite_id: Some(redeemed.id.clone()),
        created_at: Utc::now(),
    };

    if let Err(e) = state.tg_users.upsert(binding) {
        bot.send_message(chat_id, format!("Failed to save user binding: {e}"))
            .await?;
        return Ok(());
    }

    state.audit.log(
        "invite_use",
        &format!("tg:{tg_user_id}"),
        Some(&client.id),
        true,
        "ok",
    );

    if let Err(e) = send_key_with_qr(&bot, chat_id, &state, &client).await {
        warn!("failed to send key for tg_user_id={}: {}", tg_user_id, e);
        bot.send_message(chat_id, "Access created, but failed to send QR. Use /key.")
            .await?;
        return Ok(());
    }

    Ok(())
}

fn parse_invite_code(text: &str) -> Option<String> {
    if text.is_empty() {
        return None;
    }

    if let Some(raw) = text.strip_prefix("/start") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    if let Some(raw) = text.strip_prefix("/invite") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    if text.starts_with('/') {
        return None;
    }

    Some(text.to_string())
}

fn find_or_create_client_for_user(db: &ClientDatabase, tg_user_id: i64) -> Result<ClientConfig, String> {
    let name = format!("tg_{tg_user_id}");
    if let Some(existing) = db.list_clients().into_iter().find(|row| row.name == name) {
        return Ok(existing);
    }

    db.add_client(&name).map_err(|e| e.to_string())
}

async fn send_key_with_qr(
    bot: &Bot,
    chat_id: ChatId,
    state: &BotState,
    client: &ClientConfig,
) -> Result<(), String> {
    let key = build_connection_key(&state.config.server_addr, &state.server_public_key_b64, client);
    let text = format!(
        "Your AIVPN key:\n\n{}\n\nImport it into app or scan QR below.",
        key
    );

    bot.send_message(chat_id, text)
        .await
        .map_err(|e| e.to_string())?;

    let png = render_qr_png(&key)?;
    bot.send_photo(chat_id, InputFile::memory(png).file_name("aivpn-key.png"))
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

fn render_qr_png(data: &str) -> Result<Vec<u8>, String> {
    let qr = QrCode::new(data.as_bytes()).map_err(|e| e.to_string())?;
    let image = qr.render::<Luma<u8>>().min_dimensions(320, 320).build();

    let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
    image::DynamicImage::ImageLuma8(image)
        .write_to(&mut cursor, ImageFormat::Png)
        .map_err(|e| e.to_string())?;
    Ok(cursor.into_inner())
}

fn build_connection_key(
    configured_server_addr: &str,
    server_public_key_b64: &str,
    client: &ClientConfig,
) -> String {
    let server_addr = normalize_server_addr(configured_server_addr);
    let psk_b64 = STANDARD.encode(client.psk);

    let payload = serde_json::json!({
        "s": server_addr,
        "k": server_public_key_b64,
        "p": psk_b64,
        "i": client.vpn_ip.to_string(),
    });

    let json = serde_json::to_string(&payload)
        .expect("connection key payload serialization must succeed");
    let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
    format!("aivpn://{encoded}")
}

fn normalize_server_addr(addr: &str) -> String {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return "127.0.0.1:443".to_string();
    }

    let no_scheme = trimmed
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');

    if no_scheme.parse::<std::net::SocketAddr>().is_ok() {
        return no_scheme.to_string();
    }

    if !no_scheme.contains(':') {
        return format!("{no_scheme}:443");
    }

    no_scheme.to_string()
}

fn hash_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hex::encode(hasher.finalize())
}

fn load_server_public_key_b64(path: &Path) -> Result<String, String> {
    let key_data = std::fs::read(path).map_err(|e| format!("read {} failed: {}", path.display(), e))?;

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

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                EnvFilter::new("aivpn_telegram_bot=info,teloxide=info")
            }),
        )
        .init();
}

fn ensure_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn open_rw_create(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
}

fn read_data<T: for<'de> Deserialize<'de>>(file: &mut File) -> std::io::Result<T>
where
    T: Default,
{
    file.seek(SeekFrom::Start(0))?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    if content.trim().is_empty() {
        return Ok(T::default());
    }

    serde_json::from_str::<T>(&content).map_err(to_io_error)
}

fn write_data_atomic<T: Serialize>(path: &Path, data: &T) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "path has no parent"))?;

    let tmp_name = format!(
        ".{}.tmp.{}.{}",
        path.file_name().and_then(|v| v.to_str()).unwrap_or("data"),
        std::process::id(),
        rand::thread_rng().gen_range(10000..99999)
    );
    let tmp_path = parent.join(tmp_name);

    let json = serde_json::to_string_pretty(data).map_err(to_io_error)?;
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn to_io_error<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}
