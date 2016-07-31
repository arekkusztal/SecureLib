CFLAGS=-I$(PWD)/TLS
export CFLAGS

all:
	$(MAKE) -C SimpleSocket/Socket
	$(MAKE) -C SimpleSocket/TLSSocket
.PHONY:
clean:
	$(MAKE) -C SimpleSocket/Socket clean
	$(MAKE) -C SimpleSocket/TLSSocket clean
