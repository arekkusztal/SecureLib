#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#define PORTNO	6500
uint8_t buffer[255];

int main(int argc, char *argv[])
{
	int ret = 0;
	int msock, srv_sock;
	socklen_t addr_len = sizeof(struct sockaddr_in);
	struct sockaddr_in addr_server, addr_client;

	msock = socket(AF_INET, SOCK_STREAM, 0);
	if (msock < 0) {
		printf("\nError on creatin socket");
		return -1;
	}

	addr_server.sin_family = AF_INET;
	addr_server.sin_addr.s_addr = INADDR_ANY;
	addr_server.sin_port = htons(PORTNO);

	ret = bind(msock, (struct sockaddr *)&addr_server,
			sizeof(struct sockaddr_in));

	if (ret) {
		printf("\nError on binding");
		return -2;
	}

	listen(msock, 5);

	srv_sock = accept(msock, (struct sockaddr *)&addr_client,
				&addr_len);

	if (srv_sock < 0) {
		printf("\nError on accept");
		close(msock);
		return -3;
	}

	ret = read(srv_sock, buffer, 255);
	if (ret < 0) {
		printf("\nError on reading");
		close(srv_sock);
		close(msock);
		return -4;
	}


	printf("\nReceived message = %s", buffer);




	close(srv_sock);
	close(msock);

	return 0;
}
