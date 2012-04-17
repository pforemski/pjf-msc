CFLAGS = -I./libsvm-3.1/
LDFLAGS = -lpjf -levent -lpcap -lm -lpcre -lsvm -lstdc++

ME=libspi
C_OBJECTS=spi.o source.o ep.o flow.o kissp.o verdict.o
TARGETS=libspi.so

include rules.mk

libspi.so: $(C_OBJECTS)
	$(CC) $(C_OBJECTS) $(LDFLAGS) -shared -o libspi.so

install: install-std
