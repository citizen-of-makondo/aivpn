use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::Deserialize;
use std::ffi::{c_char, c_int, CStr, CString};
use std::ptr;

pub const AIVPN_OK: c_int = 0;
pub const AIVPN_ERR_NULL_POINTER: c_int = 1;
pub const AIVPN_ERR_INVALID_FORMAT: c_int = 2;
pub const AIVPN_ERR_NOT_IMPLEMENTED: c_int = 3;
pub const AIVPN_ERR_INTERNAL: c_int = 4;

#[repr(C)]
pub struct AivpnParsedKey {
    pub server: *mut c_char,
    pub server_key_b64: *mut c_char,
    pub psk_b64: *mut c_char,
    pub client_ip: *mut c_char,
}

impl Default for AivpnParsedKey {
    fn default() -> Self {
        Self {
            server: ptr::null_mut(),
            server_key_b64: ptr::null_mut(),
            psk_b64: ptr::null_mut(),
            client_ip: ptr::null_mut(),
        }
    }
}

#[repr(C)]
pub struct AivpnBytes {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl Default for AivpnBytes {
    fn default() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AivpnSession {
    _parsed_key: ParsedKey,
}

#[derive(Debug, Clone, Deserialize)]
struct ParsedKey {
    s: String,
    k: String,
    #[serde(default)]
    p: Option<String>,
    i: String,
}

fn sanitize_for_c(message: &str) -> String {
    message.replace('\0', "\\0")
}

fn clear_error(out_error: *mut *mut c_char) {
    if !out_error.is_null() {
        unsafe {
            *out_error = ptr::null_mut();
        }
    }
}

fn set_error(out_error: *mut *mut c_char, message: &str) {
    if out_error.is_null() {
        return;
    }

    let sanitized = sanitize_for_c(message);
    let c_string = CString::new(sanitized).unwrap_or_else(|_| {
        CString::new("internal error while building error string")
            .expect("constant string must not contain NUL")
    });
    unsafe {
        *out_error = c_string.into_raw();
    }
}

fn free_c_string(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(value));
    }
}

fn clone_c_string(value: &str) -> Result<*mut c_char, c_int> {
    CString::new(value)
        .map(CString::into_raw)
        .map_err(|_| AIVPN_ERR_INVALID_FORMAT)
}

fn parse_c_string(value: *const c_char, field_name: &str) -> Result<String, String> {
    if value.is_null() {
        return Err(format!("{field_name} is null"));
    }

    let raw = unsafe { CStr::from_ptr(value) };
    let text = raw
        .to_str()
        .map_err(|_| format!("{field_name} is not valid UTF-8"))?
        .trim()
        .to_string();
    if text.is_empty() {
        return Err(format!("{field_name} is empty"));
    }
    Ok(text)
}

fn validate_key_material_b64(value: &str, field_name: &str) -> Result<(), String> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| format!("{field_name} is not valid base64"))?;
    if decoded.len() != 32 {
        return Err(format!("{field_name} must decode to 32 bytes"));
    }
    Ok(())
}

fn parse_key_string(raw: &str) -> Result<ParsedKey, String> {
    let normalized = raw.trim();
    if normalized.is_empty() {
        return Err("connection key is empty".to_string());
    }

    let payload = normalized
        .strip_prefix("aivpn://")
        .unwrap_or(normalized)
        .trim();
    if payload.is_empty() {
        return Err("connection key payload is empty".to_string());
    }

    let json_bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| "connection key payload is not valid base64url".to_string())?;

    let parsed: ParsedKey =
        serde_json::from_slice(&json_bytes).map_err(|_| "connection key JSON is invalid".to_string())?;

    if parsed.s.trim().is_empty() {
        return Err("connection key field \"s\" is required".to_string());
    }
    if parsed.i.trim().is_empty() {
        return Err("connection key field \"i\" is required".to_string());
    }
    if parsed.k.trim().is_empty() {
        return Err("connection key field \"k\" is required".to_string());
    }

    validate_key_material_b64(parsed.k.trim(), "\"k\" (server key)")?;
    if let Some(psk) = &parsed.p {
        if !psk.trim().is_empty() {
            validate_key_material_b64(psk.trim(), "\"p\" (preshared key)")?;
        }
    }

    Ok(parsed)
}

fn set_not_implemented(out_error: *mut *mut c_char, function_name: &str) -> c_int {
    set_error(
        out_error,
        &format!("{function_name} is not implemented in phase 3"),
    );
    AIVPN_ERR_NOT_IMPLEMENTED
}

#[no_mangle]
pub extern "C" fn aivpn_error_free(error: *mut c_char) {
    free_c_string(error);
}

#[no_mangle]
pub extern "C" fn aivpn_parsed_key_free(key: *mut AivpnParsedKey) {
    if key.is_null() {
        return;
    }

    unsafe {
        free_c_string((*key).server);
        free_c_string((*key).server_key_b64);
        free_c_string((*key).psk_b64);
        free_c_string((*key).client_ip);
        *key = AivpnParsedKey::default();
    }
}

#[no_mangle]
pub extern "C" fn aivpn_bytes_free(bytes: *mut AivpnBytes) {
    if bytes.is_null() {
        return;
    }

    unsafe {
        let value = &mut *bytes;
        if !value.ptr.is_null() {
            drop(Vec::from_raw_parts(value.ptr, value.len, value.cap));
        }
        *value = AivpnBytes::default();
    }
}

#[no_mangle]
pub extern "C" fn aivpn_parse_key(
    raw_key: *const c_char,
    out_key: *mut AivpnParsedKey,
    out_error: *mut *mut c_char,
) -> c_int {
    clear_error(out_error);

    if raw_key.is_null() || out_key.is_null() {
        set_error(out_error, "raw_key and out_key must be non-null");
        return AIVPN_ERR_NULL_POINTER;
    }

    let raw = match parse_c_string(raw_key, "raw_key") {
        Ok(value) => value,
        Err(error) => {
            set_error(out_error, &error);
            return AIVPN_ERR_INVALID_FORMAT;
        }
    };

    let parsed = match parse_key_string(&raw) {
        Ok(value) => value,
        Err(error) => {
            set_error(out_error, &error);
            return AIVPN_ERR_INVALID_FORMAT;
        }
    };

    let server = match clone_c_string(parsed.s.trim()) {
        Ok(value) => value,
        Err(code) => {
            set_error(out_error, "failed to encode server for C ABI");
            return code;
        }
    };

    let server_key_b64 = match clone_c_string(parsed.k.trim()) {
        Ok(value) => value,
        Err(code) => {
            free_c_string(server);
            set_error(out_error, "failed to encode server key for C ABI");
            return code;
        }
    };

    let psk_b64 = if let Some(psk) = parsed.p.as_ref().map(|v| v.trim()).filter(|v| !v.is_empty()) {
        match clone_c_string(psk) {
            Ok(value) => value,
            Err(code) => {
                free_c_string(server);
                free_c_string(server_key_b64);
                set_error(out_error, "failed to encode preshared key for C ABI");
                return code;
            }
        }
    } else {
        ptr::null_mut()
    };

    let client_ip = match clone_c_string(parsed.i.trim()) {
        Ok(value) => value,
        Err(code) => {
            free_c_string(server);
            free_c_string(server_key_b64);
            free_c_string(psk_b64);
            set_error(out_error, "failed to encode client ip for C ABI");
            return code;
        }
    };

    unsafe {
        *out_key = AivpnParsedKey {
            server,
            server_key_b64,
            psk_b64,
            client_ip,
        };
    }
    AIVPN_OK
}

#[no_mangle]
pub extern "C" fn aivpn_session_create(
    parsed_key: *const AivpnParsedKey,
    out_error: *mut *mut c_char,
) -> *mut AivpnSession {
    clear_error(out_error);

    if parsed_key.is_null() {
        set_error(out_error, "parsed_key must be non-null");
        return ptr::null_mut();
    }

    let parsed_ref = unsafe { &*parsed_key };
    let server = match parse_c_string(parsed_ref.server, "parsed_key.server") {
        Ok(value) => value,
        Err(error) => {
            set_error(out_error, &error);
            return ptr::null_mut();
        }
    };
    let server_key_b64 = match parse_c_string(parsed_ref.server_key_b64, "parsed_key.server_key_b64") {
        Ok(value) => value,
        Err(error) => {
            set_error(out_error, &error);
            return ptr::null_mut();
        }
    };
    let client_ip = match parse_c_string(parsed_ref.client_ip, "parsed_key.client_ip") {
        Ok(value) => value,
        Err(error) => {
            set_error(out_error, &error);
            return ptr::null_mut();
        }
    };

    if let Err(error) = validate_key_material_b64(&server_key_b64, "\"k\" (server key)") {
        set_error(out_error, &error);
        return ptr::null_mut();
    }

    let psk_b64 = if parsed_ref.psk_b64.is_null() {
        None
    } else {
        match parse_c_string(parsed_ref.psk_b64, "parsed_key.psk_b64") {
            Ok(value) => {
                if let Err(error) = validate_key_material_b64(&value, "\"p\" (preshared key)") {
                    set_error(out_error, &error);
                    return ptr::null_mut();
                }
                Some(value)
            }
            Err(error) => {
                set_error(out_error, &error);
                return ptr::null_mut();
            }
        }
    };

    let session = AivpnSession {
        _parsed_key: ParsedKey {
            s: server,
            k: server_key_b64,
            p: psk_b64,
            i: client_ip,
        },
    };
    Box::into_raw(Box::new(session))
}

#[no_mangle]
pub extern "C" fn aivpn_session_free(session: *mut AivpnSession) {
    if session.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(session));
    }
}

#[no_mangle]
pub extern "C" fn aivpn_session_build_init(
    session: *mut AivpnSession,
    out_packet: *mut AivpnBytes,
    out_error: *mut *mut c_char,
) -> c_int {
    clear_error(out_error);
    if session.is_null() || out_packet.is_null() {
        set_error(out_error, "session and out_packet must be non-null");
        return AIVPN_ERR_NULL_POINTER;
    }
    unsafe {
        *out_packet = AivpnBytes::default();
    }
    set_not_implemented(out_error, "aivpn_session_build_init")
}

#[no_mangle]
pub extern "C" fn aivpn_session_encrypt_packet(
    session: *mut AivpnSession,
    packet: *const u8,
    packet_len: usize,
    out_packet: *mut AivpnBytes,
    out_error: *mut *mut c_char,
) -> c_int {
    clear_error(out_error);
    if session.is_null() || out_packet.is_null() {
        set_error(out_error, "session and out_packet must be non-null");
        return AIVPN_ERR_NULL_POINTER;
    }
    if packet.is_null() || packet_len == 0 {
        set_error(out_error, "packet must be non-null and packet_len must be > 0");
        return AIVPN_ERR_INVALID_FORMAT;
    }
    unsafe {
        *out_packet = AivpnBytes::default();
    }
    set_not_implemented(out_error, "aivpn_session_encrypt_packet")
}

#[no_mangle]
pub extern "C" fn aivpn_session_decrypt_packet(
    session: *mut AivpnSession,
    packet: *const u8,
    packet_len: usize,
    out_packet: *mut AivpnBytes,
    out_error: *mut *mut c_char,
) -> c_int {
    clear_error(out_error);
    if session.is_null() || out_packet.is_null() {
        set_error(out_error, "session and out_packet must be non-null");
        return AIVPN_ERR_NULL_POINTER;
    }
    if packet.is_null() || packet_len == 0 {
        set_error(out_error, "packet must be non-null and packet_len must be > 0");
        return AIVPN_ERR_INVALID_FORMAT;
    }
    unsafe {
        *out_packet = AivpnBytes::default();
    }
    set_not_implemented(out_error, "aivpn_session_decrypt_packet")
}

#[no_mangle]
pub extern "C" fn aivpn_session_build_keepalive(
    session: *mut AivpnSession,
    out_packet: *mut AivpnBytes,
    out_error: *mut *mut c_char,
) -> c_int {
    clear_error(out_error);
    if session.is_null() || out_packet.is_null() {
        set_error(out_error, "session and out_packet must be non-null");
        return AIVPN_ERR_NULL_POINTER;
    }
    unsafe {
        *out_packet = AivpnBytes::default();
    }
    set_not_implemented(out_error, "aivpn_session_build_keepalive")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_key() -> String {
        let json = r#"{"s":"194.154.25.21:443","k":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","p":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","i":"10.0.0.2"}"#;
        let payload = URL_SAFE_NO_PAD.encode(json.as_bytes());
        format!("aivpn://{payload}")
    }

    #[test]
    fn parse_valid_key_works() {
        let parsed = parse_key_string(&make_valid_key()).expect("key should parse");
        assert_eq!(parsed.s, "194.154.25.21:443");
        assert_eq!(parsed.i, "10.0.0.2");
    }

    #[test]
    fn parse_invalid_key_fails() {
        let raw = "aivpn://invalid";
        assert!(parse_key_string(raw).is_err());
    }
}
