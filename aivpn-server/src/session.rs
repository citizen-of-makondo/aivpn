//! Session Manager
//! 
//! Manages active VPN sessions with O(1) tag validation

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;
use chacha20poly1305::aead::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use tracing::info;

use aivpn_common::crypto::{
    self, SessionKeys, KeyPair, TAG_SIZE, X25519_PUBLIC_KEY_SIZE, 
    NONCE_SIZE, CHACHA20_KEY_SIZE, DEFAULT_WINDOW_MS,
};
use aivpn_common::protocol::{InnerType, InnerHeader, ControlPayload, ControlSubtype};
use aivpn_common::mask::MaskProfile;
use aivpn_common::error::{Error, Result};

/// Maximum sessions on 1GB VPS
pub const MAX_SESSIONS: usize = 500;

/// Session idle timeout
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Session hard timeout
pub const HARD_TIMEOUT: Duration = Duration::from_secs(24 * 3600);

/// Tag window size (allow out-of-order packets)
pub const TAG_WINDOW_SIZE: usize = 256;

/// Session state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Pending,
    Active,
    Idle,
    Rotating,
    MaskChange,
    Expired,
    Closed,
}

/// Session information
pub struct Session {
    pub session_id: [u8; 16],
    pub client_addr: SocketAddr,
    pub state: SessionState,
    pub keys: SessionKeys,
    pub eph_pub: [u8; X25519_PUBLIC_KEY_SIZE],
    
    /// Packet counter for tag generation
    pub counter: u64,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Created timestamp
    pub created_at: Instant,
    
    /// Current mask profile
    pub mask: Option<MaskProfile>,
    /// Current FSM state
    pub fsm_state: u16,
    /// Packets in current FSM state
    pub fsm_packets: u32,
    /// Duration in current FSM state
    pub fsm_state_start: Instant,
    
    /// Sequence number for outgoing packets
    pub send_seq: u32,
    /// Last received sequence (for ACK)
    pub recv_seq: u32,
    /// Send counter for nonce generation (u64, same space as tags)
    pub send_counter: u64,
    
    /// Expected tags (counter -> tag)
    pub expected_tags: HashMap<u64, [u8; TAG_SIZE]>,
    /// Received tag bitmap (for anti-replay)
    pub received_bitmap: u256,

    // --- PFS Ratchet fields (CRIT-3) ---
    /// Server's ephemeral public key for this session
    pub server_eph_pub: Option<[u8; 32]>,
    /// Ed25519 signature for ServerHello
    pub server_hello_signature: Option<[u8; 64]>,
    /// Ratcheted session keys (PFS)
    pub ratcheted_keys: Option<SessionKeys>,
    /// Ratcheted tags for validation (counter -> tag)
    pub ratcheted_expected_tags: HashMap<u64, [u8; TAG_SIZE]>,
    /// Whether session has completed PFS ratchet
    pub is_ratcheted: bool,
    /// Assigned VPN IP (e.g. 10.0.0.2)
    pub vpn_ip: Option<Ipv4Addr>,
}

/// 256-bit bitmap for tracking received packets
#[derive(Debug, Clone, Copy, Default)]
pub struct u256 {
    lo: u128,
    hi: u128,
}

impl u256 {
    pub fn set_bit(&mut self, bit: usize) {
        if bit < 128 {
            self.lo |= 1u128 << bit;
        } else {
            self.hi |= 1u128 << (bit - 128);
        }
    }
    
    pub fn get_bit(&self, bit: usize) -> bool {
        if bit < 128 {
            (self.lo & (1u128 << bit)) != 0
        } else {
            (self.hi & (1u128 << (bit - 128))) != 0
        }
    }
    
    pub fn clear(&mut self) {
        self.lo = 0;
        self.hi = 0;
    }
}

impl Session {
    pub fn new(
        session_id: [u8; 16],
        client_addr: SocketAddr,
        keys: SessionKeys,
        eph_pub: [u8; X25519_PUBLIC_KEY_SIZE],
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            client_addr,
            state: SessionState::Pending,
            keys,
            eph_pub,
            counter: 0,
            last_seen: now,
            created_at: now,
            mask: None,
            fsm_state: 0,
            fsm_packets: 0,
            fsm_state_start: now,
            send_seq: 0,
            recv_seq: 0,
            send_counter: 0,
            expected_tags: HashMap::with_capacity(TAG_WINDOW_SIZE),
            received_bitmap: u256::default(),
            server_eph_pub: None,
            server_hello_signature: None,
            ratcheted_keys: None,
            ratcheted_expected_tags: HashMap::new(),
            is_ratcheted: false,
            vpn_ip: None,
        }
    }
    
    /// Compute next nonce for encryption from send_counter (u64)
    /// Uses the same counter space as tag generation for consistency
    pub fn next_send_nonce(&mut self) -> ([u8; NONCE_SIZE], u64) {
        let counter = self.send_counter;
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&counter.to_le_bytes());
        self.send_counter += 1;
        (nonce, counter)
    }
    
    /// Update expected tags for validation window
    pub fn update_tag_window(&mut self) {
        let time_window = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            DEFAULT_WINDOW_MS,
        );
        
        // Pre-compute tags for next TAG_WINDOW_SIZE packets
        self.expected_tags.clear();
        for i in 0..TAG_WINDOW_SIZE {
            let tag = crypto::generate_resonance_tag(
                &self.keys.tag_secret,
                self.counter + i as u64,
                time_window,
            );
            self.expected_tags.insert(self.counter + i as u64, tag);
        }
    }
    
    /// Validate received tag (constant-time)
    /// Returns (counter, is_ratcheted_tag) if valid
    pub fn validate_tag(&self, tag: &[u8; TAG_SIZE]) -> Option<(u64, bool)> {
        // Check initial keys first
        for (counter, expected) in &self.expected_tags {
            if bool::from(expected.ct_eq(tag)) {
                // Check anti-replay
                let bit_index = counter - self.counter;
                if bit_index < 256 && self.received_bitmap.get_bit(bit_index as usize) {
                    return None; // Already received
                }
                return Some((*counter, false));
            }
        }
        // Check ratcheted keys (only during transition, before ratchet is complete)
        if !self.is_ratcheted {
            for (counter, expected) in &self.ratcheted_expected_tags {
                if bool::from(expected.ct_eq(tag)) {
                    return Some((*counter, true));
                }
            }
        }
        None
    }
    
    /// Mark tag as received
    pub fn mark_tag_received(&mut self, counter: u64) {
        let bit_index = counter - self.counter;
        if bit_index < 256 {
            self.received_bitmap.set_bit(bit_index as usize);
        }
    }
    
    /// Get next sequence number for inner header
    pub fn next_seq(&mut self) -> u32 {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        seq
    }
    
    /// Update FSM state
    pub fn update_fsm(&mut self) {
        if let Some(mask) = &self.mask {
            let duration_ms = self.fsm_state_start.elapsed().as_millis() as u64;
            let (new_state, size_override, iat_override, padding_override) = 
                mask.process_transition(self.fsm_state, self.fsm_packets, duration_ms);
            
            if new_state != self.fsm_state {
                self.fsm_state = new_state;
                self.fsm_packets = 0;
                self.fsm_state_start = Instant::now();
            }
        }
        self.fsm_packets += 1;
    }
    
    /// Check if session is idle
    pub fn is_idle(&self) -> bool {
        self.last_seen.elapsed() > IDLE_TIMEOUT
    }
    
    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > HARD_TIMEOUT
    }

    /// Pre-compute tags for ratcheted keys
    pub fn update_ratcheted_tag_window(&mut self) {
        if let Some(ratcheted_keys) = &self.ratcheted_keys {
            let time_window = crypto::compute_time_window(
                crypto::current_timestamp_ms(),
                DEFAULT_WINDOW_MS,
            );
            self.ratcheted_expected_tags.clear();
            // Ratcheted counter starts at 0
            for i in 0..TAG_WINDOW_SIZE {
                let tag = crypto::generate_resonance_tag(
                    &ratcheted_keys.tag_secret,
                    i as u64,
                    time_window,
                );
                self.ratcheted_expected_tags.insert(i as u64, tag);
            }
        }
    }

    /// Complete PFS ratchet: switch to ratcheted keys, zeroize old ones
    pub fn complete_ratchet(&mut self) {
        if let Some(ratcheted_keys) = self.ratcheted_keys.take() {
            self.keys = ratcheted_keys;
            self.counter = 0;
            self.send_counter = 0;
            self.expected_tags = std::mem::take(&mut self.ratcheted_expected_tags);
            self.received_bitmap.clear();
            self.is_ratcheted = true;
            self.server_eph_pub = None;
            self.server_hello_signature = None;
        }
    }
}

/// Session Manager with O(1) tag lookup
pub struct SessionManager {
    /// Sessions by ID
    sessions: DashMap<[u8; 16], Arc<Mutex<Session>>>,
    /// Tag -> Session ID mapping for O(1) lookup
    tag_map: DashMap<[u8; TAG_SIZE], [u8; 16]>,
    /// VPN IP -> Session ID mapping for TUN return routing
    vpn_ip_map: DashMap<Ipv4Addr, [u8; 16]>,
    /// Next VPN IP to assign (last octet)
    next_ip_octet: AtomicU32,
    /// Server's long-term keypair
    server_keys: KeyPair,
    /// Server's signing key (Ed25519)
    signing_key: ed25519_dalek::SigningKey,
    /// Default mask profile
    default_mask: MaskProfile,
}

impl SessionManager {
    pub fn new(
        server_keys: KeyPair,
        signing_key: ed25519_dalek::SigningKey,
        default_mask: MaskProfile,
    ) -> Self {
        Self {
            sessions: DashMap::new(),
            tag_map: DashMap::new(),
            vpn_ip_map: DashMap::new(),
            next_ip_octet: AtomicU32::new(2),
            server_keys,
            signing_key,
            default_mask,
        }
    }
    
    /// Create new session from initial packet
    pub fn create_session(
        &self,
        client_addr: SocketAddr,
        eph_pub: [u8; X25519_PUBLIC_KEY_SIZE],
        preshared_key: Option<[u8; 32]>,
    ) -> Result<Arc<Mutex<Session>>> {
        // The current Android client configures a stable tunnel IP locally.
        // When the same public client IP reconnects, reuse its prior VPN IP.
        let same_ip_sessions: Vec<([u8; 16], Option<Ipv4Addr>)> = self.sessions.iter()
            .filter_map(|entry| {
                let session = entry.value().lock();
                if session.client_addr.ip() == client_addr.ip() {
                    Some((*entry.key(), session.vpn_ip))
                } else {
                    None
                }
            })
            .collect();

        let reused_vpn_ip = if same_ip_sessions.len() == 1 {
            let (old_session_id, vpn_ip) = same_ip_sessions[0];
            self.remove_session(&old_session_id);
            vpn_ip
        } else {
            None
        };

        if self.sessions.len() >= MAX_SESSIONS {
            return Err(Error::Session("Max sessions reached".into()));
        }
        
        // MED-6: Per-IP session limit (max 5 sessions per IP)
        let ip_count = self.sessions.iter()
            .filter(|e| e.value().lock().client_addr.ip() == client_addr.ip())
            .count();
        if ip_count >= 5 {
            return Err(Error::Session("Per-IP session limit reached".into()));
        }
        
        // DH1: server_static * client_eph → initial keys (0-RTT)
        let dh1 = self.server_keys.compute_shared(&eph_pub)?;
        let initial_keys = crypto::derive_session_keys(
            &dh1,
            preshared_key.as_ref(),
            &eph_pub,
        );
        
        // --- CRIT-3 + HIGH-6: PFS ratchet preparation ---
        // Generate server ephemeral keypair
        let server_eph_kp = crypto::KeyPair::generate();
        let server_eph_pub = server_eph_kp.public_key_bytes();
        
        // DH2: server_eph * client_eph → PFS keys
        let dh2 = server_eph_kp.compute_shared(&eph_pub)?;
        // Use initial session_key as PSK for domain separation
        let ratcheted_keys = crypto::derive_session_keys(
            &dh2,
            Some(&initial_keys.session_key),
            &eph_pub,
        );
        
        // Sign (server_eph_pub || client_eph_pub) for server authentication (HIGH-6)
        use ed25519_dalek::Signer;
        let mut sign_message = Vec::with_capacity(64);
        sign_message.extend_from_slice(&server_eph_pub);
        sign_message.extend_from_slice(&eph_pub);
        let signature = self.signing_key.sign(&sign_message).to_bytes();
        
        // Generate session ID
        let mut session_id = [0u8; 16];
        OsRng.fill_bytes(&mut session_id);
        
        // Create session with initial (DH1) keys
        let session = Arc::new(Mutex::new(Session::new(
            session_id,
            client_addr,
            initial_keys,
            eph_pub,
        )));
        
        // Setup ratchet state + populate tag maps
        {
            let mut sess = session.lock();
            sess.state = SessionState::Active;
            
            // Store ratchet data
            sess.server_eph_pub = Some(server_eph_pub);
            sess.server_hello_signature = Some(signature);
            sess.ratcheted_keys = Some(ratcheted_keys);
            
            // Compute initial tags
            sess.update_tag_window();
            for tag in sess.expected_tags.values() {
                self.tag_map.insert(*tag, session_id);
            }
            
            // Pre-compute ratcheted tags (for when client switches to PFS keys)
            sess.update_ratcheted_tag_window();
            for tag in sess.ratcheted_expected_tags.values() {
                self.tag_map.insert(*tag, session_id);
            }
        }
        
        // Insert into session map
        self.sessions.insert(session_id, session.clone());
        
        // Assign VPN IP and register mapping
        let vpn_ip = reused_vpn_ip.or_else(|| {
            let octet = self.next_ip_octet.fetch_add(1, Ordering::Relaxed);
            if octet <= 254 {
                Some(Ipv4Addr::new(10, 0, 0, octet as u8))
            } else {
                None
            }
        });

        if let Some(vpn_ip) = vpn_ip {
            session.lock().vpn_ip = Some(vpn_ip);
            self.vpn_ip_map.insert(vpn_ip, session_id);
            info!("Assigned VPN IP {} to session", vpn_ip);
        }
        
        Ok(session)
    }
    
    /// Get session by tag (O(1) lookup)
    pub fn get_session_by_tag(&self, tag: &[u8; TAG_SIZE]) -> Option<Arc<Mutex<Session>>> {
        if let Some(entry) = self.tag_map.get(tag) {
            let session_id = *entry;
            drop(entry);
            self.sessions.get(&session_id).map(|e| e.clone())
        } else {
            None
        }
    }

    /// Refresh tag windows for all sessions (time window may have advanced)
    /// and try to find a session matching the given tag.
    pub fn refresh_and_find_by_tag(&self, tag: &[u8; TAG_SIZE]) -> Option<(Arc<Mutex<Session>>, u64, bool)> {
        for entry in self.sessions.iter() {
            let session = entry.value().clone();
            let session_id = *entry.key();
            let mut sess = session.lock();

            // Refresh initial key tags
            let old_tags: Vec<[u8; TAG_SIZE]> = sess.expected_tags.values().cloned().collect();
            for old_tag in &old_tags {
                self.tag_map.remove(old_tag);
            }
            sess.update_tag_window();
            for t in sess.expected_tags.values() {
                self.tag_map.insert(*t, session_id);
            }

            // Refresh ratcheted key tags
            let old_ratcheted: Vec<[u8; TAG_SIZE]> = sess.ratcheted_expected_tags.values().cloned().collect();
            for old_tag in &old_ratcheted {
                self.tag_map.remove(old_tag);
            }
            sess.update_ratcheted_tag_window();
            for t in sess.ratcheted_expected_tags.values() {
                self.tag_map.insert(*t, session_id);
            }

            // Try to validate the tag now
            if let Some((counter, is_ratcheted)) = sess.validate_tag(tag) {
                drop(sess);
                return Some((session, counter, is_ratcheted));
            }
        }
        None
    }
    
    /// Get session by ID
    pub fn get_session(&self, session_id: &[u8; 16]) -> Option<Arc<Mutex<Session>>> {
        self.sessions.get(session_id).map(|e| e.clone())
    }
    
    /// Get session by VPN IP (for routing TUN responses back to clients)
    pub fn get_session_by_vpn_ip(&self, vpn_ip: &Ipv4Addr) -> Option<Arc<Mutex<Session>>> {
        if let Some(entry) = self.vpn_ip_map.get(vpn_ip) {
            let session_id = *entry;
            drop(entry);
            self.sessions.get(&session_id).map(|e| e.clone())
        } else {
            None
        }
    }
    
    /// Remove session
    pub fn remove_session(&self, session_id: &[u8; 16]) {
        if let Some((_, session)) = self.sessions.remove(session_id) {
            let sess = session.lock();
            // Remove all tags from tag map (initial + ratcheted)
            for tag in sess.expected_tags.values() {
                self.tag_map.remove(tag);
            }
            for tag in sess.ratcheted_expected_tags.values() {
                self.tag_map.remove(tag);
            }
            // Remove VPN IP mapping
            if let Some(vpn_ip) = sess.vpn_ip {
                self.vpn_ip_map.remove(&vpn_ip);
            }
        }
    }
    
    /// Refresh tag_map after session's tag window has been updated
    pub fn refresh_session_tags(&self, session_id: &[u8; 16]) {
        if let Some(session) = self.sessions.get(session_id) {
            let sess = session.lock();
            // Remove stale tags for this session
            self.tag_map.retain(|_, id| id != session_id);
            // Re-add current tags
            for tag in sess.expected_tags.values() {
                self.tag_map.insert(*tag, *session_id);
            }
            for tag in sess.ratcheted_expected_tags.values() {
                self.tag_map.insert(*tag, *session_id);
            }
        }
    }
    
    /// Complete PFS ratchet for a session: switch to ratcheted keys, remove old tags
    pub fn complete_session_ratchet(&self, session_id: &[u8; 16]) {
        if let Some(session) = self.sessions.get(session_id) {
            let mut sess = session.lock();
            // Remove old initial key tags from tag_map
            for tag in sess.expected_tags.values() {
                self.tag_map.remove(tag);
            }
            // Complete the ratchet (swaps keys, moves ratcheted_expected_tags → expected_tags)
            sess.complete_ratchet();
            // Re-add the now-active tags (which were the ratcheted tags)
            for tag in sess.expected_tags.values() {
                self.tag_map.insert(*tag, *session_id);
            }
        }
    }
    
    /// Cleanup expired sessions
    pub fn cleanup_expired(&self) {
        let expired: Vec<[u8; 16]> = self.sessions
            .iter()
            .filter(|e| e.value().lock().is_expired() || e.value().lock().is_idle())
            .map(|e| *e.key())
            .collect();
        
        for session_id in expired {
            self.remove_session(&session_id);
        }
    }
    
    /// Get active session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
    
    /// Get server public key
    pub fn server_public_key(&self) -> [u8; X25519_PUBLIC_KEY_SIZE] {
        self.server_keys.public_key_bytes()
    }
    
    /// Sign mask data
    pub fn sign_mask(&self, mask_data: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(mask_data);
        signature.to_bytes()
    }
    
    /// Iterate over all sessions (for neural resonance checks)
    pub fn iter_sessions(&self) -> dashmap::iter::Iter<'_, [u8; 16], Arc<Mutex<Session>>> {
        self.sessions.iter()
    }
    
    /// Update mask for a session (triggered by neural resonance compromise detection)
    pub fn update_session_mask(&self, session_id: &[u8; 16], new_mask: MaskProfile) {
        if let Some(session) = self.sessions.get(session_id) {
            let mut sess = session.lock();
            info!("Session mask rotated: {} → {}", 
                sess.mask.as_ref().map(|m| m.mask_id.as_str()).unwrap_or("default"),
                new_mask.mask_id
            );
            sess.mask = Some(new_mask);
            sess.state = SessionState::MaskChange;
            // Reset FSM state for the new mask
            sess.fsm_state = 0;
            sess.fsm_packets = 0;
            sess.fsm_state_start = Instant::now();
        }
    }
}
