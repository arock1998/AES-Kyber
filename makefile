CC=/usr/bin/gcc
CFLAGS += -O3 -fomit-frame-pointer
LDFLAGS=-lcrypto

AES_DIR= ./aes128
AES_SOURCES= $(AES_DIR)/aes.c
AES_HEADERS= $(AES_DIR)/sbox.h $(AES_DIR)/aes.h 

KYBER_DIR= ./kyber512
KYBER_SOURCES= $(KYBER_DIR)/cbd.c $(KYBER_DIR)/fips202.c $(KYBER_DIR)/indcpa.c $(KYBER_DIR)/kem.c $(KYBER_DIR)/ntt.c $(KYBER_DIR)/poly.c $(KYBER_DIR)/polyvec.c $(KYBER_DIR)/reduce.c $(KYBER_DIR)/rng.c $(KYBER_DIR)/verify.c $(KYBER_DIR)/symmetric-shake.c #$(KYBER_DIR)/PQCgenKAT_kem.c
KYBER_HEADERS= $(KYBER_DIR)/api.h $(KYBER_DIR)/cbd.h $(KYBER_DIR)/fips202.h $(KYBER_DIR)/indcpa.h $(KYBER_DIR)/ntt.h $(KYBER_DIR)/params.h $(KYBER_DIR)/poly.h $(KYBER_DIR)/polyvec.h $(KYBER_DIR)/reduce.h $(KYBER_DIR)/rng.h $(KYBER_DIR)/verify.h $(KYBER_DIR)/symmetric.h

all : make build

make : main.c $(AES_SOURCES) $(AES_HEADERS) $(KYBER_SOURCES) $(KYBER_HEADERS)
	$(CC) $(CFLAGS) main.c $(KYBER_SOURCES) $(AES_SOURCES) -o main $(LDFLAGS)

build : ./main

clean : rm -f main
