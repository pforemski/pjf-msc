CFLAGS = -I./libsvm-3.1/
LDFLAGS = -lpjf -levent -lpcap -lm -llinear -lpcre

ME=libspi
C_OBJECTS=spi.o source.o ep.o flow.o kissp.o verdict.o libsvm-3.1/svm.o
TARGETS=libspi.so

include rules.mk

libsvm-3.1/svm.o:
	$(MAKE) -C libsvm-3.1/

libspi.so: $(C_OBJECTS)
	$(CC) $(C_OBJECTS) $(LDFLAGS) -shared -o libspi.so

install: install-std
