CC=gcc

OPENSSL_DIR=../openssl-1.1.1h/.openssl
CFLAGS += -I$(OPENSSL_DIR)/include
LDFLAGS+= -L$(OPENSSL_DIR)/lib -lcrypto

CURL_DIR=../curl-7.77.0/.curl
CFLAGS += -I$(CURL_DIR)/include
LDFLAGS+= -L$(CURL_DIR)/lib -lcurl

ODIR=obj

build: obj/main 

_OBJ = iap.o main.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

obj/main.o: main.c
	$(CC) -c -o $@ $< $(CFLAGS)

obj/iap.o: iap.c iap.h
	$(CC) -c -o $@ $< $(CFLAGS)

obj/main: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core
