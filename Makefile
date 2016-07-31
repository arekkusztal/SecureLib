CFLAGS=-I$(PWD)/TLS
export CFLAGS

all:
	$(MAKE) -C SimpleSocket
.PHONY:
clean:
	$(MAKE) -C SimpleSocket clean