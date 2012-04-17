CFLAGS =
LDFLAGS = -lspi -lpjf

ME=spid
C_OBJECTS=spid.o samplefile.o
TARGETS=spid

include rules.mk

spid: $(C_OBJECTS)
	$(CC) $(C_OBJECTS) $(LDFLAGS) -o spid

install: install-std
