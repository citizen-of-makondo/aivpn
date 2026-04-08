#ifndef AIVPN_IOS_CORE_H
#define AIVPN_IOS_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AivpnSession AivpnSession;

typedef struct AivpnParsedKey {
    char* server;
    char* server_key_b64;
    char* psk_b64;
    char* client_ip;
} AivpnParsedKey;

typedef struct AivpnBytes {
    uint8_t* ptr;
    size_t len;
    size_t cap;
} AivpnBytes;

enum {
    AIVPN_OK = 0,
    AIVPN_ERR_NULL_POINTER = 1,
    AIVPN_ERR_INVALID_FORMAT = 2,
    AIVPN_ERR_NOT_IMPLEMENTED = 3,
    AIVPN_ERR_INTERNAL = 4
};

int32_t aivpn_parse_key(const char* raw_key, AivpnParsedKey* out_key, char** out_error);
void aivpn_parsed_key_free(AivpnParsedKey* key);

AivpnSession* aivpn_session_create(const AivpnParsedKey* parsed_key, char** out_error);
void aivpn_session_free(AivpnSession* session);

int32_t aivpn_session_build_init(AivpnSession* session, AivpnBytes* out_packet, char** out_error);
int32_t aivpn_session_encrypt_packet(
    AivpnSession* session,
    const uint8_t* packet,
    size_t packet_len,
    AivpnBytes* out_packet,
    char** out_error
);
int32_t aivpn_session_decrypt_packet(
    AivpnSession* session,
    const uint8_t* packet,
    size_t packet_len,
    AivpnBytes* out_packet,
    char** out_error
);
int32_t aivpn_session_build_keepalive(AivpnSession* session, AivpnBytes* out_packet, char** out_error);

void aivpn_bytes_free(AivpnBytes* bytes);
void aivpn_error_free(char* error);

#ifdef __cplusplus
}
#endif

#endif
