use aivpn_common::client_wire::{
    build_inner_packet, build_zero_mdh_packet, decode_packet_with_mdh_len,
    obfuscate_client_eph_pub, RecvWindow, DEFAULT_ZERO_MDH,
};
use aivpn_common::crypto::{derive_session_keys, KeyPair, SessionKeys};
use aivpn_common::protocol::{ControlPayload, InnerType};
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

pub struct AivpnSession {
    parsed_key: ParsedKey,
    keypair: KeyPair,
    server_public_key: [u8; 32],
    keys: SessionKeys,
    recv_window: RecvWindow,
    send_counter: u64,
    send_seq: u16,
    mdh_len: usize,
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

fn decode_32_b64(value: &str, field_name: &str) -> Result<[u8; 32], String> {
    validate_key_material_b64(value, field_name)?;
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| format!("{field_name} is not valid base64"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
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

    let parsed: ParsedKey = serde_json::from_slice(&json_bytes)
        .map_err(|_| "connection key JSON is invalid".to_string())?;

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

fn packet_from_raw(packet: *const u8, packet_len: usize) -> Result<Vec<u8>, String> {
    if packet.is_null() || packet_len == 0 {
        return Err("packet must be non-null and packet_len must be > 0".to_string());
    }
    let slice = unsafe { std::slice::from_raw_parts(packet, packet_len) };
    Ok(slice.to_vec())
}

fn set_out_bytes(out_packet: *mut AivpnBytes, data: Vec<u8>) {
    let mut bytes = data;
    let raw = AivpnBytes {
        ptr: bytes.as_mut_ptr(),
        len: bytes.len(),
        cap: bytes.capacity(),
    };
    std::mem::forget(bytes);

    unsafe {
        *out_packet = raw;
    }
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

    let psk_b64 = if let Some(psk) = parsed.p.as_ref().map(|v| v.trim()).filter(|v| !v.is_empty())
    {
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

    let server_public_key = match decode_32_b64(&server_key_b64, "\"k\" (server key)") {
        Ok(v) => v,
        Err(error) => {
            set_error(out_error, &error);
            return ptr::null_mut();
        }
    };

    let psk_bytes = if parsed_ref.psk_b64.is_null() {
        None
    } else {
        match parse_c_string(parsed_ref.psk_b64, "parsed_key.psk_b64") {
            Ok(value) => match decode_32_b64(&value, "\"p\" (preshared key)") {
                Ok(v) => Some(v),
                Err(error) => {
                    set_error(out_error, &error);
                    return ptr::null_mut();
                }
            },
            Err(error) => {
                set_error(out_error, &error);
                return ptr::null_mut();
            }
        }
    };

    let keypair = KeyPair::generate();
    let dh = match keypair.compute_shared(&server_public_key) {
        Ok(v) => v,
        Err(error) => {
            set_error(out_error, &format!("failed to derive shared key: {error}"));
            return ptr::null_mut();
        }
    };

    let keys = derive_session_keys(&dh, psk_bytes.as_ref(), &keypair.public_key_bytes());

    let session = AivpnSession {
        parsed_key: ParsedKey {
            s: server,
            k: server_key_b64,
            p: psk_bytes.as_ref().map(|v| STANDARD.encode(v)),
            i: client_ip,
        },
        keypair,
        server_public_key,
        keys,
        recv_window: RecvWindow::new(),
        send_counter: 0,
        send_seq: 0,
        mdh_len: DEFAULT_ZERO_MDH.len(),
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

    let session_ref = unsafe { &mut *session };

    let keepalive = match ControlPayload::Keepalive.encode() {
        Ok(v) => v,
        Err(e) => {
            set_error(out_error, &format!("failed to encode keepalive: {e}"));
            return AIVPN_ERR_INTERNAL;
        }
    };

    let inner = build_inner_packet(InnerType::Control, session_ref.send_seq, &keepalive);
    let obf_pub = obfuscate_client_eph_pub(&session_ref.keypair, &session_ref.server_public_key);

    let packet = match build_zero_mdh_packet(
        &session_ref.keys,
        &mut session_ref.send_counter,
        &inner,
        Some(&obf_pub),
    ) {
        Ok(v) => v,
        Err(e) => {
            set_error(out_error, &format!("failed to build init packet: {e}"));
            return AIVPN_ERR_INTERNAL;
        }
    };

    session_ref.send_seq = session_ref.send_seq.wrapping_add(1);
    set_out_bytes(out_packet, packet);
    AIVPN_OK
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

    unsafe {
        *out_packet = AivpnBytes::default();
    }

    let payload = match packet_from_raw(packet, packet_len) {
        Ok(v) => v,
        Err(error) => {
            set_error(out_error, &error);
            return AIVPN_ERR_INVALID_FORMAT;
        }
    };

    let session_ref = unsafe { &mut *session };
    let inner = build_inner_packet(InnerType::Data, session_ref.send_seq, &payload);
    let datagram = match build_zero_mdh_packet(
        &session_ref.keys,
        &mut session_ref.send_counter,
        &inner,
        None,
    ) {
        Ok(v) => v,
        Err(e) => {
            set_error(out_error, &format!("failed to encrypt packet: {e}"));
            return AIVPN_ERR_INTERNAL;
        }
    };

    session_ref.send_seq = session_ref.send_seq.wrapping_add(1);
    set_out_bytes(out_packet, datagram);
    AIVPN_OK
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

    unsafe {
        *out_packet = AivpnBytes::default();
    }

    let datagram = match packet_from_raw(packet, packet_len) {
        Ok(v) => v,
        Err(error) => {
            set_error(out_error, &error);
            return AIVPN_ERR_INVALID_FORMAT;
        }
    };

    let session_ref = unsafe { &mut *session };
    let decoded = match decode_packet_with_mdh_len(
        &datagram,
        &session_ref.keys,
        &mut session_ref.recv_window,
        session_ref.mdh_len,
    ) {
        Ok(v) => v,
        Err(e) => {
            set_error(out_error, &format!("failed to decrypt packet: {e}"));
            return AIVPN_ERR_INVALID_FORMAT;
        }
    };

    match decoded.header.inner_type {
        InnerType::Data => {
            set_out_bytes(out_packet, decoded.payload);
            AIVPN_OK
        }
        InnerType::Control => {
            if let Ok(ControlPayload::ServerHello { server_eph_pub, .. }) =
                ControlPayload::decode(&decoded.payload)
            {
                let dh2 = match session_ref.keypair.compute_shared(&server_eph_pub) {
                    Ok(v) => v,
                    Err(e) => {
                        set_error(out_error, &format!("failed to process ServerHello DH: {e}"));
                        return AIVPN_ERR_INTERNAL;
                    }
                };

                let old_session_key = session_ref.keys.session_key;
                session_ref.keys =
                    derive_session_keys(&dh2, Some(&old_session_key), &session_ref.keypair.public_key_bytes());
                session_ref.send_counter = 0;
                session_ref.recv_window.reset();
            }

            set_out_bytes(out_packet, Vec::new());
            AIVPN_OK
        }
        _ => {
            set_out_bytes(out_packet, decoded.payload);
            AIVPN_OK
        }
    }
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

    let session_ref = unsafe { &mut *session };
    let keepalive = match ControlPayload::Keepalive.encode() {
        Ok(v) => v,
        Err(e) => {
            set_error(out_error, &format!("failed to encode keepalive: {e}"));
            return AIVPN_ERR_INTERNAL;
        }
    };

    let inner = build_inner_packet(InnerType::Control, session_ref.send_seq, &keepalive);
    let datagram = match build_zero_mdh_packet(
        &session_ref.keys,
        &mut session_ref.send_counter,
        &inner,
        None,
    ) {
        Ok(v) => v,
        Err(e) => {
            set_error(out_error, &format!("failed to build keepalive packet: {e}"));
            return AIVPN_ERR_INTERNAL;
        }
    };

    session_ref.send_seq = session_ref.send_seq.wrapping_add(1);
    set_out_bytes(out_packet, datagram);
    AIVPN_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_common::client_wire::counter_to_nonce;
    use aivpn_common::crypto::{decrypt_payload, encrypt_payload};

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

    #[test]
    fn nonce_counter_roundtrip() {
        let nonce = counter_to_nonce(42);
        assert_eq!(u64::from_le_bytes(nonce[..8].try_into().unwrap()), 42);
    }

    #[test]
    fn payload_encrypt_decrypt_roundtrip() {
        let key = [7u8; 32];
        let nonce = counter_to_nonce(1);
        let plain = b"hello";
        let enc = encrypt_payload(&key, &nonce, plain).unwrap();
        let dec = decrypt_payload(&key, &nonce, &enc).unwrap();
        assert_eq!(dec, plain);
    }
}
