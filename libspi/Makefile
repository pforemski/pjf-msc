CFLAGS = -I./libsvm-3.1/ -I./liblinear-1.8/
LDFLAGS = -lpjf -levent -lpcap -lm -lpcre -lstdc++

ME=libspi
C_OBJECTS=spi.o source.o ep.o flow.o kissp.o verdict.o libsvm-3.1/svm.o liblinear-1.8/linear.a
TARGETS=libspi.so

include rules.mk

libsvm-3.1/svm.o:
	$(MAKE) -C libsvm-3.1/ svm.o

liblinear-1.8/linear.a:
	$(MAKE) -C liblinear-1.8/ lib
	sh -c "cd liblinear-1.8; ar rcv linear.a tron.o linear.o blas/*.o; ranlib linear.a"

libspi.so: $(C_OBJECTS)
	$(CC) $(C_OBJECTS) $(LDFLAGS) -shared -o libspi.so

install: install-std
