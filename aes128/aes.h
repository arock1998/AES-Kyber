#include <stdio.h>
#include "sbox.h"

typedef unsigned char byte;

//          128     192     256            
#define Nk  4   //  6       8
#define Nb  4   //  4       4 
#define Nr  10  //  12      14

void AESTest();

void Cipher(byte* in, byte* out, byte* w);

void InvCipher(byte* in, byte* out, byte* w);

void KeyExpansion(byte* key, byte* word);

void SubBytes(byte* state);

void InvSubBytes(byte* state);

void ShiftRows(byte* state);

void InvShiftRows(byte* state);

void MixColumns(byte* state);

void InvMixColumns(byte* state);

void AddRoundKey(byte* state, int round, byte* w);

byte xtime(byte byte1);

byte mul(byte x, byte y);

void PrintArray(char* str, byte* state);

void PrintW();