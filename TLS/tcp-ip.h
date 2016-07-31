#ifndef TCP_IP_H
#define TCP_IP_H

#include <stdint.h>

struct IP_hdr {
	uint8_t v:4;
	uint8_t hl:4;
	uint8_t tos;
	uint16_t len;
	uint16_t ident;
	uint16_t flags:3;
	uint16_t fragment:13;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t source;
	uint32_t destination;
};

struct TCP_hdr {
	uint16_t s_port;
	uint16_t d_port;
	uint32_t seq_number;
	uint32_t ack_number;
#ifdef TCP_OPT_ONE
	uint32_t rsvd:7;
	uint32_t nonce:1;
	uint32_t cwr:1;
	uint32_t ecn_echo:1;
	uint32_t urgent:1;
	uint32_t ack:1;
	uint32_t push:1;
	uint32_t reset:1;
	uint32_t syn:1;
	uint32_t fin:1;
#endif
	uint16_t flags;
	uint32_t window;
	uint32_t checksum;
	uint32_t urgent_pointer;
	uint8_t opt[];
};

struct TCP {
	struct TCP_hdr TCP_hdr;
	uint8_t TCP_payload[];
};

#endif
