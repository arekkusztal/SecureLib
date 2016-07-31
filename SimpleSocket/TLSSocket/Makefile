all:
	gcc -o srv TLS_server.c $(CFLAGS)
	gcc -o cli TLS_client.c $(CFLAGS)
.PHONY:
clean:
	rm -f srv
	rm -f cli
