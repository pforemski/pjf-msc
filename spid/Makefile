CFLAGS =
LDFLAGS = -lpjf -lpcre -levent -lpcap

ME=spid
C_OBJECTS=main.o spid.o source.o ep.o flow.o kissp.o
TARGETS=spid

include rules.mk

spid: $(C_OBJECTS)
	$(CC) $(C_OBJECTS) $(LDFLAGS) -o spid

install: install-std
