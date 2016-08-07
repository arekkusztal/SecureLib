#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <tls.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define PORTNO 443
uint8_t buffer[4096];
uint8_t *message = "The message";
const char *IP = "209.85.202.94";//"192.168.192.47"; //"127.0.0.1";
//const char *IP = "192.168.192.19"; //"127.0.0.1";
#define LEN 	187

/* SPDY :/ */
uint8_t spdy[] = { 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33, 0x2e, 0x31
};
/* http 1.1 */

uint8_t http[] = {
		0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31
};


uint8_t name[] = {
		0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x6C
};

void hex_dump(const char *def, uint8_t *data, uint16_t len,
		uint16_t br)
{
	uint16_t i;

	printf("\n%s:\n", def);
	for (i = 0; i < len; ++i) {
		if (i && ( i % br ==0 ))
			printf("\n");
		printf("0x%02X ",data[i]);
	}
	printf("\n");
}

uint8_t rands[28];


int TLS_Client_Hello_Set(struct TLS_Client_Hello *client_hello)
{
	int i;
	uint16_t ciphers_size = sizeof(TLS_cipher_suites);
	uint8_t *client_hello_array = calloc(LEN, 1);

	client_hello->record_protocol.type = HANDSHAKE;
	client_hello->record_protocol.version = htons(0x301);
	client_hello->record_protocol.length = htons(LEN - 5);

	client_hello->handshake.handshake_type = CLIENT_HELLO;
	client_hello->handshake.length[2] = 156 + ciphers_size;

	client_hello->version = htons(0x303);

	/* 2012... */
	client_hello->random.time = htonl(time(NULL));
	/* Need to add some PRNG */
	for (i=0;i<7;i++)
		*(int *)&client_hello->random.rand[i*4] = rand();

	client_hello->session_ID_len = 0;
	/* Cipher suites no */
	*(uint16_t *)&client_hello->flexible_data[0] = htons(ciphers_size);
	for (i = 2; i < sizeof(TLS_cipher_suites); i+=2) {
		*(uint16_t *)&client_hello->flexible_data[i] = htons(TLS_cipher_suites[i/2-1]);
	}

	*(uint8_t *)&client_hello->flexible_data[24] = 1;
	*(uint8_t *)&client_hello->flexible_data[25] = 0;

	/* Put some real/random data into the extensions */
	*(uint16_t *)&client_hello->flexible_data[26] = htons(115);
	*(uint16_t *)&client_hello->flexible_data[30] = htons(18);
	*(uint16_t *)&client_hello->flexible_data[32] = htons(16);
	*(uint16_t *)&client_hello->flexible_data[35] = htons(13);
	memcpy((uint8_t *)&client_hello->flexible_data[37], name, 13);

	/* Renegotitation info */

	*(uint16_t *)&client_hello->flexible_data[50] = htons(0xff01);
	*(uint16_t *)&client_hello->flexible_data[52] = htons(1);

	/* Elliptic curves */

	*(uint16_t *)&client_hello->flexible_data[55] = htons(0x000a);
	*(uint16_t *)&client_hello->flexible_data[57] = htons(8);
	*(uint16_t *)&client_hello->flexible_data[59] = htons(6);
	*(uint16_t *)&client_hello->flexible_data[61] = htons(0x17);
	*(uint16_t *)&client_hello->flexible_data[63] = htons(0x18);
	*(uint16_t *)&client_hello->flexible_data[65] = htons(0x19);

	/* EC point format */
	*(uint16_t *)&client_hello->flexible_data[67] = htons(0xb);
	*(uint16_t *)&client_hello->flexible_data[69] = htons(2);
	*(uint8_t *)&client_hello->flexible_data[71] = 1;

	/* Session ticket TLS */
	*(uint16_t *)&client_hello->flexible_data[73] = htons(0x23);

	/* Protocol negotiation */
	*(uint16_t *)&client_hello->flexible_data[77] = htons(0x3374);

	/* Application Layer Protocol Negotiation */
	*(uint16_t *)&client_hello->flexible_data[81] = 0x1000;
	*(uint16_t *)&client_hello->flexible_data[83] = htons(0x17);
	*(uint16_t *)&client_hello->flexible_data[85] = htons(0x15);
	*(uint16_t *)&client_hello->flexible_data[87] = 2;
	*(uint16_t *)&client_hello->flexible_data[88] = htons(0x6832);
	*(uint8_t *)&client_hello->flexible_data[90] = 8;
	memcpy((uint8_t *)&client_hello->flexible_data[91], spdy, 8);
	*(uint8_t *)&client_hello->flexible_data[99] = 8;
	memcpy((uint8_t *)&client_hello->flexible_data[100], http, 8);

	*(uint16_t *)&client_hello->flexible_data[108] = htons(0x5);
	*(uint16_t *)&client_hello->flexible_data[110] = htons(0x5);
	*(uint8_t *)&client_hello->flexible_data[112] = 1;
	*(uint16_t *)&client_hello->flexible_data[117] = htons(0xd);
	*(uint16_t *)&client_hello->flexible_data[119] = htons(0x16);
	*(uint16_t *)&client_hello->flexible_data[121] = htons(0x14);


	*(uint16_t *)&client_hello->flexible_data[123] = htons(0x401);
	*(uint16_t *)&client_hello->flexible_data[125] = htons(0x501);
	*(uint16_t *)&client_hello->flexible_data[127] = htons(0x601);
	*(uint16_t *)&client_hello->flexible_data[129] = htons(0x201);
	*(uint16_t *)&client_hello->flexible_data[131] = htons(0x403);
	*(uint16_t *)&client_hello->flexible_data[133] = htons(0x503);
	*(uint16_t *)&client_hello->flexible_data[135] = htons(0x603);
	*(uint16_t *)&client_hello->flexible_data[137] = htons(0x203);
	*(uint16_t *)&client_hello->flexible_data[139] = htons(0x402);
	*(uint16_t *)&client_hello->flexible_data[141] = htons(0x202);
	return 0;
}



uint8_t *randp = "abcdabcdabcdabcdabcdabcdabcdabcd";
int main(int argc, char *argv[])
{
	int i;
	int ret;
	int msock;
	struct sockaddr_in addr_server;
	struct TLS_Client_Hello *client_hello = calloc(LEN, 1);

	TLS_Client_Hello_Set(client_hello);

    inet_pton(AF_INET, IP , &addr_server.sin_addr);
	addr_server.sin_family = AF_INET;
	addr_server.sin_port = htons(PORTNO);

	msock = socket(AF_INET, SOCK_STREAM, 0);
	if (msock < 0) {
		printf("\nError on creatin socket");
		return -1;
	}

	ret = connect(msock, (struct sockaddr *)&addr_server, sizeof(struct sockaddr) );
	if (ret < 0) {
		printf("\nError on connect");
		close(msock);
		return -2;
	}

	getc(stdin);

	memcpy(buffer, (uint8_t *)client_hello, LEN);
	ret = write(msock, (uint8_t *)client_hello, LEN);
	if (ret < 0) {
		printf("\nError writing to socket");
		close(msock);
		return -3;
	}

	ret = read(msock, buffer, 4096);

	printf("\nRead %d bytes", ret);

	hex_dump("Server Hello", buffer, 4096, 32);
	printf("\n%s", buffer);
	getc(stdin);
	close(msock);
	return 0;
}


/*
16030100b6010000b20303d6e9e7feb6c03cbe984cfcf560238d0a5dd28f252adc10457fd8f929a62d23ee 000016c02bc02fc00ac009c013c01400330039002f0035000a0100007300000012001000000d7777772e676f6f676c652e706cff01000100000a0008000600 1700180019 000b00020100002300003374000000100017001502 6832 08737064792f332e3108687474702f312e31000500050100000000000d001600 140401050106010201040305030603020304020202
16030100b6010000b2030357a73a8d67458b6bc6237b3269983c647348336651dcb074ff5c49194a94e82a 000016c02bc02fc00ac009c013c01400330039002f0035000a0100007300000012001000000d7777772e676f6f676c652e706cff01000100000a0008000600 1100120013 000b00020100002300003374000000100017001502 3268 08737064792f332e3108687474702f312e31000500050100000000000d001600 040105010601020104030503060302030402020200
*/
