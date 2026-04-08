use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use askama::Template;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect};
use axum::Json;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use qrcode::render::svg;
use qrcode::QrCode;
use subtle::ConstantTimeEq;
use time::Duration as TimeDuration;

use crate::auth::{
    create_session_token, generate_csrf_token, verify_password_hash, verify_session_token,
    SessionClaims, CSRF_COOKIE, SESSION_COOKIE,
};
use crate::models::{
    BulkCreateFailure, BulkCreateRequest, BulkCreateResponse, ClientResponse,
    ConnectionKeyResponse, CreateClientRequest, ErrorResponse, LoginRequest, MessageResponse,
};
use crate::state::AppState;
use crate::templates::{DashboardTemplate, LoginTemplate};

type ApiError = (StatusCode, Json<ErrorResponse>);

pub async fn healthz() -> &'static str {
    "ok"
}

pub async fn get_login() -> impl IntoResponse {
    let template = LoginTemplate;
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn get_dashboard(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> impl IntoResponse {
    if session_claims_from_jar(&jar, &state).is_none() {
        return Redirect::to("/login").into_response();
    }

    let template = DashboardTemplate {
        admin_user: state.config.admin_user.clone(),
        server_addr: state.config.server_addr.clone(),
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn api_login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<MessageResponse>), ApiError> {
    let ip = addr.ip();

    if !state.login_limiter.allow(ip) {
        state.audit.log(
            "login",
            &req.username,
            None,
            ip,
            false,
            "rate_limit",
        );
        return Err(api_error(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"));
    }

    let valid = req.username == state.config.admin_user
        && verify_password_hash(&req.password, &state.config.admin_password_hash);

    if !valid {
        state.audit.log("login", &req.username, None, ip, false, "invalid_credentials");
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }

    let session_token = create_session_token(&state.config.admin_user, &state.config.session_secret)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let csrf_token = generate_csrf_token();
    let session_cookie = build_session_cookie(session_token, state.config.cookie_secure);
    let csrf_cookie = build_csrf_cookie(csrf_token, state.config.cookie_secure);

    state.audit
        .log("login", &state.config.admin_user, None, ip, true, "ok");

    let jar = jar.add(session_cookie).add(csrf_cookie);
    Ok((
        jar,
        Json(MessageResponse {
            message: "Logged in".to_string(),
        }),
    ))
}

pub async fn api_logout(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<(CookieJar, Json<MessageResponse>), ApiError> {
    let claims = require_api_auth(&state, &jar)?;
    require_csrf(&jar, &headers)?;

    state.audit
        .log("logout", &claims.user, None, addr.ip(), true, "ok");

    let jar = jar
        .remove(clear_cookie(SESSION_COOKIE, state.config.cookie_secure, true))
        .remove(clear_cookie(CSRF_COOKIE, state.config.cookie_secure, false));

    Ok((
        jar,
        Json(MessageResponse {
            message: "Logged out".to_string(),
        }),
    ))
}

pub async fn api_list_clients(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<ClientResponse>>, ApiError> {
    let _claims = require_api_auth(&state, &jar)?;

    let clients = state
        .client_db
        .list_clients()
        .into_iter()
        .map(ClientResponse::from)
        .collect::<Vec<_>>();

    Ok(Json(clients))
}

pub async fn api_create_client(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<CreateClientRequest>,
) -> Result<Json<ClientResponse>, ApiError> {
    let claims = require_api_auth(&state, &jar)?;
    require_mutation_allowed(&state, addr.ip(), &jar, &headers)?;

    let name = req.name.trim();
    if name.is_empty() {
        return Err(api_error(StatusCode::BAD_REQUEST, "Client name is required"));
    }

    match state.client_db.add_client(name) {
        Ok(client) => {
            state
                .audit
                .log("client_create", &claims.user, Some(&client.id), addr.ip(), true, "ok");
            Ok(Json(ClientResponse::from(client)))
        }
        Err(e) => {
            state.audit.log(
                "client_create",
                &claims.user,
                Some(name),
                addr.ip(),
                false,
                &e.to_string(),
            );
            Err(api_error(StatusCode::BAD_REQUEST, &e.to_string()))
        }
    }
}

pub async fn api_bulk_create_clients(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<BulkCreateRequest>,
) -> Result<Json<BulkCreateResponse>, ApiError> {
    let claims = require_api_auth(&state, &jar)?;
    require_mutation_allowed(&state, addr.ip(), &jar, &headers)?;

    let prefix = req.prefix.trim();
    if prefix.is_empty() {
        return Err(api_error(StatusCode::BAD_REQUEST, "Prefix is required"));
    }

    if req.count == 0 || req.count > 500 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "count must be between 1 and 500",
        ));
    }

    let start = req.start_index.unwrap_or(1);

    let mut created = Vec::new();
    let mut failed = Vec::new();

    for offset in 0..req.count {
        let name = format!("{prefix}{}", start + offset);
        match state.client_db.add_client(&name) {
            Ok(client) => created.push(ClientResponse::from(client)),
            Err(e) => failed.push(BulkCreateFailure {
                name,
                error: e.to_string(),
            }),
        }
    }

    state.audit.log(
        "client_bulk_create",
        &claims.user,
        None,
        addr.ip(),
        failed.is_empty(),
        &format!("created={} failed={}", created.len(), failed.len()),
    );

    Ok(Json(BulkCreateResponse { created, failed }))
}

pub async fn api_get_client(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> Result<Json<ClientResponse>, ApiError> {
    let _claims = require_api_auth(&state, &jar)?;

    let client = state
        .client_db
        .find_by_id(&id)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Client not found"))?;

    Ok(Json(ClientResponse::from(client)))
}

pub async fn api_enable_client(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    let claims = require_api_auth(&state, &jar)?;
    require_mutation_allowed(&state, addr.ip(), &jar, &headers)?;

    match state.client_db.set_client_enabled(&id, true) {
        Ok(()) => {
            state
                .audit
                .log("client_enable", &claims.user, Some(&id), addr.ip(), true, "ok");
            Ok(Json(MessageResponse {
                message: "Client enabled".to_string(),
            }))
        }
        Err(e) => {
            state.audit.log(
                "client_enable",
                &claims.user,
                Some(&id),
                addr.ip(),
                false,
                &e.to_string(),
            );
            Err(api_error(StatusCode::BAD_REQUEST, &e.to_string()))
        }
    }
}

pub async fn api_disable_client(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    let claims = require_api_auth(&state, &jar)?;
    require_mutation_allowed(&state, addr.ip(), &jar, &headers)?;

    match state.client_db.set_client_enabled(&id, false) {
        Ok(()) => {
            state.audit.log(
                "client_disable",
                &claims.user,
                Some(&id),
                addr.ip(),
                true,
                "ok",
            );
            Ok(Json(MessageResponse {
                message: "Client disabled".to_string(),
            }))
        }
        Err(e) => {
            state.audit.log(
                "client_disable",
                &claims.user,
                Some(&id),
                addr.ip(),
                false,
                &e.to_string(),
            );
            Err(api_error(StatusCode::BAD_REQUEST, &e.to_string()))
        }
    }
}

pub async fn api_delete_client(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    let claims = require_api_auth(&state, &jar)?;
    require_mutation_allowed(&state, addr.ip(), &jar, &headers)?;

    match state.client_db.remove_client(&id) {
        Ok(()) => {
            state
                .audit
                .log("client_delete", &claims.user, Some(&id), addr.ip(), true, "ok");
            Ok(Json(MessageResponse {
                message: "Client deleted".to_string(),
            }))
        }
        Err(e) => {
            state.audit.log(
                "client_delete",
                &claims.user,
                Some(&id),
                addr.ip(),
                false,
                &e.to_string(),
            );
            Err(api_error(StatusCode::BAD_REQUEST, &e.to_string()))
        }
    }
}

pub async fn api_get_connection_key(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> Result<Json<ConnectionKeyResponse>, ApiError> {
    let claims = require_api_auth(&state, &jar)?;

    let client = state
        .client_db
        .find_by_id(&id)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Client not found"))?;

    let connection_key = build_connection_key(
        &state.config.server_addr,
        &state.server_public_key_b64,
        &client,
    );

    state.audit.log(
        "connection_key_show",
        &claims.user,
        Some(&id),
        addr.ip(),
        true,
        "explicit_view",
    );

    Ok(Json(ConnectionKeyResponse { connection_key }))
}

pub async fn api_get_connection_qr(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let claims = require_api_auth(&state, &jar)?;

    let client = state
        .client_db
        .find_by_id(&id)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Client not found"))?;

    let connection_key = build_connection_key(
        &state.config.server_addr,
        &state.server_public_key_b64,
        &client,
    );

    let qr = QrCode::new(connection_key.as_bytes())
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let svg = qr
        .render::<svg::Color>()
        .min_dimensions(220, 220)
        .dark_color(svg::Color("#0f172a"))
        .light_color(svg::Color("#ffffff"))
        .build();

    state.audit.log(
        "connection_qr_show",
        &claims.user,
        Some(&id),
        addr.ip(),
        true,
        "explicit_view",
    );

    Ok((
        [(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        svg,
    ))
}

fn require_mutation_allowed(
    state: &AppState,
    ip: IpAddr,
    jar: &CookieJar,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    if !state.mutation_limiter.allow(ip) {
        return Err(api_error(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"));
    }
    require_csrf(jar, headers)?;
    Ok(())
}

fn require_api_auth(state: &AppState, jar: &CookieJar) -> Result<SessionClaims, ApiError> {
    session_claims_from_jar(jar, state)
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "Unauthorized"))
}

fn session_claims_from_jar(jar: &CookieJar, state: &AppState) -> Option<SessionClaims> {
    let token = jar.get(SESSION_COOKIE)?.value();
    verify_session_token(token, &state.config.admin_user, &state.config.session_secret)
}

fn require_csrf(jar: &CookieJar, headers: &HeaderMap) -> Result<(), ApiError> {
    let cookie_value = jar
        .get(CSRF_COOKIE)
        .map(|c| c.value().as_bytes().to_vec())
        .ok_or_else(|| api_error(StatusCode::FORBIDDEN, "Missing CSRF cookie"))?;

    let header_value = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.as_bytes().to_vec())
        .ok_or_else(|| api_error(StatusCode::FORBIDDEN, "Missing CSRF header"))?;

    if cookie_value.len() != header_value.len()
        || !bool::from(cookie_value.ct_eq(header_value.as_slice()))
    {
        return Err(api_error(StatusCode::FORBIDDEN, "Invalid CSRF token"));
    }

    Ok(())
}

fn build_session_cookie(token: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE.to_string(), token);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_secure(secure);
    cookie.set_max_age(TimeDuration::hours(12));
    cookie
}

fn build_csrf_cookie(token: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(CSRF_COOKIE.to_string(), token);
    cookie.set_path("/");
    cookie.set_http_only(false);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_secure(secure);
    cookie.set_max_age(TimeDuration::hours(12));
    cookie
}

fn clear_cookie(name: &str, secure: bool, http_only: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(name.to_string(), String::new());
    cookie.set_path("/");
    cookie.set_http_only(http_only);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_secure(secure);
    cookie.set_max_age(TimeDuration::seconds(0));
    cookie
}

fn api_error(status: StatusCode, message: &str) -> ApiError {
    (
        status,
        Json(ErrorResponse {
            error: message.to_string(),
        }),
    )
}

fn build_connection_key(
    configured_server_addr: &str,
    server_public_key_b64: &str,
    client: &aivpn_server::client_db::ClientConfig,
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

    // Bracketed IPv6 [::1]:443 or socket address with explicit port.
    if no_scheme.parse::<SocketAddr>().is_ok() {
        return no_scheme.to_string();
    }

    // Hostname without explicit port.
    if !no_scheme.contains(':') {
        return format!("{no_scheme}:443");
    }

    no_scheme.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_key_contains_expected_fields() {
        let client = aivpn_server::client_db::ClientConfig {
            id: "abc".to_string(),
            name: "test".to_string(),
            psk: [7u8; 32],
            vpn_ip: "10.0.0.2".parse().unwrap(),
            enabled: true,
            created_at: chrono::Utc::now(),
            stats: aivpn_server::client_db::ClientStats::default(),
        };

        let key = build_connection_key("example.com", "server-pub", &client);
        assert!(key.starts_with("aivpn://"));

        let encoded = key.strip_prefix("aivpn://").unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&decoded).unwrap();

        assert_eq!(json["s"], "example.com:443");
        assert_eq!(json["k"], "server-pub");
        assert_eq!(json["i"], "10.0.0.2");
    }
}
