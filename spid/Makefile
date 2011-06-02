CFLAGS = -I/usr/include/libsvm-2.0
LDFLAGS = -lpjf -lpcre -levent -lpcap -lm -llinear

ME=spid
C_OBJECTS=main.o spid.o source.o ep.o flow.o kissp.o verdict.o
TARGETS=spid

include rules.mk

spid: $(C_OBJECTS)
	$(CC) $(C_OBJECTS) $(LDFLAGS) -o spid

install: install-std
