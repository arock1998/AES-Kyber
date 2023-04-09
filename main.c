#include <stdio.h>
#include <string.h>
#include "./aes128/aes.h"
#include "./kyber512/rng.h"
#include "./kyber512/api.h"

void AES_TEST();
void KYBER_TEST();

int main() {
    AES_TEST();
    KYBER_TEST();
}


void AES_TEST() {
    byte key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    byte plain[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    byte right_enc[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    byte output[16] = {0,};
    byte w[(10+1)*4*4] = {0,};
    // 키 스케줄링
    KeyExpansion(key, w);

    PrintArray("plain text  ", plain);
    PrintArray("key         ", key);
    // 암호화
    Cipher(plain, output, w);
    if ( memcmp(output, right_enc, 16) ) {
        printf("## Error : AES 암호화 동작 오류");
        return;
    }

    printf("## Success : AES 암호화 정상 동작\n");
    // 복호화
    InvCipher(right_enc, output, w);
    if ( memcmp(output, plain, 16) ) {
        printf("## Error : AES 암호화 동작 오류");
        return;
    }
    
    printf("## Success : AES 복호화 정상 동작\n");
}


void KYBER_TEST() {

    byte pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    byte ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES];
    byte seed[48] = {0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A, 0x25, 
            0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC, 0xFD, 0xE7, 
            0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2, 0xE1, 0xFF, 0xA1};

    printf("\nseed = ");
    randombytes_init(seed, NULL, 256);
    for(int i = 0; i < 48; i++) {
        printf("%02x", seed[i]);
    }

    // 공개키, 개인키 생성
    crypto_kem_keypair(pk, sk);
    printf("\npk = ");
    for (int i=0; i<CRYPTO_PUBLICKEYBYTES; i++){
        printf("%02X", pk[i]);
    }
    printf("\nsk = ");
    for (int i=0; i<CRYPTO_SECRETKEYBYTES; i++){
		printf("%02X", sk[i]);
    }

    // 공개키로 암호화 진행
    crypto_kem_enc(ct, ss, pk);
    printf("\nct = ");
    for (int i=0; i<CRYPTO_CIPHERTEXTBYTES; i++){
		printf("%02X", ct[i]);
    }
    
    // 개인키로 복호화 진행
    crypto_kem_dec(ss1, ct, sk);
    printf("\nss1 = ");
    for (int i=0; i<CRYPTO_BYTES; i++){
		printf("%02X", ss1[i]);
    }
    printf("\n");
    
    if ( memcmp(ss, ss1, CRYPTO_BYTES) ) {
        printf("## Error : kyber 동작 오류");
    } else {
        printf("## Success : kyber 정상 동작\n");
    }
}