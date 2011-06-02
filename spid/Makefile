CFLAGS = -I/usr/include/libsvm-2.0
LDFLAGS = -lpjf -lpcre -levent -lpcap -lm -llinear

ME=spid
C_OBJECTS=spi.o source.o ep.o flow.o kissp.o verdict.o
TARGETS=spid libspi.so

include rules.mk

spid: main.o $(C_OBJECTS)
	$(CC) main.o $(C_OBJECTS) $(LDFLAGS) -o spid

libspi.so: $(C_OBJECTS)
	$(CC) $(C_OBJECTS) $(LDFLAGS) -shared -o libspi.so

install: install-std
