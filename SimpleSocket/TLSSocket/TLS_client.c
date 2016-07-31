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

#define PORTNO 6500
uint8_t buffer[256];
uint8_t *message = "The message";
const char *IP = "127.0.0.1";
#define LEN 	187
int main(int argc, char *argv[])
{
	int ret;
	int msock;
	struct sockaddr_in addr_server;
	struct TLS_Client_Hello *client_hello = calloc(LEN, 1);
	uint8_t *client_hello_array = calloc(LEN, 1);

	client_hello->record_protocol.type = HANDSHAKE;
	client_hello->record_protocol.version = htons(0x301);
	client_hello->record_protocol.length = htons(LEN - 5);

	client_hello->handshake.handshake_type = CLIENT_HELLO;
	client_hello->handshake.length[2] = 178;

	client_hello->version = htons(0x303);

	/* 2012... */
	client_hello->random.time = htonl(0x50aa6120);
	/* Need to add some PRNG */
	client_hello->random.rand[0] = 0x9a;

	client_hello->session_ID_len = 0;
	*(uint16_t *)&client_hello->flexible_data[0] = htons(22);
	*(uint16_t *)&client_hello->flexible_data[2] = htons(0xc02b);
	*(uint8_t *)&client_hello->flexible_data[24] = 1;
	*(uint8_t *)&client_hello->flexible_data[25] = 0;

	/* Put some real/random data into the extensions */
	*(uint16_t *)&client_hello->flexible_data[26] = htons(115);
	*(uint16_t *)&client_hello->flexible_data[30] = htons(18);
	*(uint16_t *)&client_hello->flexible_data[32] = htons(16);
	*(uint16_t *)&client_hello->flexible_data[35] = htons(13);






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

	close(msock);
	return 0;
}
