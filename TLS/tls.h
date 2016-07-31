#ifndef TLS_H
#define TLS_H

#include <stdint.h>

enum TLS_content_types {
	HANDSHAKE = 0x16,

};

enum TLS_cipher_suite {
	ECDHA_DSA_AES_128_GCM_SHA256 = 0xc02b,
	ECDHA_RSA_AES_128_GCM_SHA256 = 0xc02f,
	ECDHA_DSA_AES_256_CBC_SHA = 0xC00A,


};

enum TLS_handshake_types {
	CLIENT_HELLO = 1,
	NEW_SESSION_TICKET = 4,
	CLIENT_KEY_EXCHANGE = 0x10,
	SERVER_KEY_EXCHANGE = 0xC,
	SERVER_HELLO_DONE = 0xE,
	FINISHED = 0x14,
};

struct TLS_record_protocol {
	uint8_t type;
	uint16_t version;
	uint16_t length;
} __attribute__((packed));

struct TLS_handshake_protocol {
	uint8_t handshake_type;
	uint8_t length[3];
} __attribute__((packed));

struct TLS_Client_Hello {
	struct TLS_record_protocol record_protocol;
	struct TLS_handshake_protocol handshake;
	uint16_t version;
	struct {
		uint32_t time;
		uint8_t rand[28];
	} random;
	uint8_t session_ID_len;
/*	uint16_t cipher_suites_length;
	uint8_t *cipher_suites;
	uint16_t compr_method_len;
	uint8_t *compr_suites;
	uint16_t extenstions_length; */
	uint8_t flexible_data[];

} __attribute__((packed));

struct TLS_Server_Hello {
	struct TLS_record_protocol record_protocol;
	struct TLS_handshake_protocol handshake;
	uint16_t version;
	struct {
		uint32_t time;
		uint32_t rand[28];
	} random;
	uint8_t session_ID_len;
	uint16_t cipher_suite;
	uint8_t compr_method;
	uint16_t extenstions_length;
	uint8_t flexible_data[];

} __attribute__((packed));

struct TLS_Client_Key_Exchange {
	struct TLS_record_protocol record_protocol;
	struct TLS_handshake_protocol handshake;
	uint8_t EC_len;
	uint8_t pubkey[];
};

struct TLS_Server_Key_Exchange {
	struct TLS_record_protocol record_protocol;
	struct TLS_handshake_protocol handshake;
	uint8_t EC_len;
	uint8_t pubkey[];
} __attribute__((packed));

struct TLS_Certificate {
	struct TLS_record_protocol record_protocol;
	struct TLS_handshake_protocol handshake;
	uint8_t length[3];
	uint8_t certificate[];

} __attribute__((packed));

struct TLS_Server_Hello_Done {
	struct TLS_record_protocol record_protocol;
	struct TLS_handshake_protocol handshake;
} __attribute__((packed));

#endif
