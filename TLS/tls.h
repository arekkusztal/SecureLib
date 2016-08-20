/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Arek Kusztal. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in
 *	   the documentation and/or other materials provided with the
 *	   distribution.
 *	 * Neither the name of SecureLib Project nor the names of its
 *	   contributors may be used to endorse or promote products derived
 *	   from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef TLS_H
#define TLS_H

#include <stdint.h>

enum TLS_content_types {
	CHANGECIPHERSPEC = 0x14,
	ALERT = 0x15,
	HANDSHAKE = 0x16,
	APPLICATIONDATA = 0x17
};

enum TLS_ext_srv_name_type {
	HOST_NAME	= 0,
};


enum TLS_extenstions {
	TLS_EXT_SRV_NAME = 0,
	TLS_EXT_RENEGOTIATION_INFO = 0xFF01,
	TLS_EXT_ELLIPTIC_CURVES = 0x000A,

};
/* According RFC 4492
 *
 *Elliptic Curve Cryptography (ECC)
 *Elliptic Cipher Suites for
 *Elliptic Transport Layer Security (TLS) */

enum TLS_elliptic_curve {
	TLS_EC_SECP256R1 = 0x17,
	TLS_EC_SECP384R1 = 0x18,
	TLS_EC_SECP521R1 = 0x19,

};

struct EC_sextuple {
	/* p - point on the curve */
	/* a */
	/* b */
	/* G - generator over Fn */
};

/* Move to tls_init */
uint16_t TLS_elliptic_curves[] = {
		TLS_EC_SECP256R1,
		TLS_EC_SECP384R1,
		TLS_EC_SECP521R1,
};

enum TLS_version {
	SSLv3 = 0x300,
	TLSv1_0 = 0x301,
	TLSv1_1 = 0x302,
	TLSv1_2 = 0x303,
};

#define CIPHER_SUITES_NUM	22

enum TLS_cipher_suite {
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = (0xc02b),
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = (0xc02f),
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = (0xc00a),
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = (0xc013),
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = (0xc014),
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA = (0x0033),
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA = (0x0039),
	TLS_RSA_WITH_AES_128_CBC_SHA = (0x002f),
	TLS_RSA_WITH_AES_256_CBC_SHA = (0x0035),
	TLS_RSA_WITH_3DES_EDE_CBC_SHA = (0x000a)
};

enum TLS_compr_suite {
	TLS_COMPR_NULL = 0,
};

uint8_t TLS_compr_suites[] = {
		TLS_COMPR_NULL,
};

uint16_t TLS_cipher_suites[] = {
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_3DES_EDE_CBC_SHA
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
