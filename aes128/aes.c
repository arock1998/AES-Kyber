#include "aes.h"

/**
 * 암호화 동작 함수
 * w[] => contains the key schedule
*/
void Cipher(byte* in, byte* out, byte* word) {
    byte state[4*Nb] = {0, };
    for(int i = 0; i < 4*Nb; i++) { 
        state[i] = in[i];
    }
    AddRoundKey(state, 0, word);
    for(int i = 1; i < Nr; i ++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, i, word);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, Nr, word);
    for(int i = 0; i < 4*Nb; i++) {
        out[i] = state[i];
    }
    PrintArray("encrypt text", out);
}


/**
 * 복호화 동작 함수
*/
void InvCipher(byte* in, byte* out, byte* word) {
    byte state[4*Nb] = {0, };
    for(int i = 0; i < 4*Nb; i++) { 
        state[i] = in[i];
    }
    AddRoundKey(state, Nr, word);
    for(int i = Nr-1; i > 0; i--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, i, word);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, 0, word);
    for(int i = 0; i < 4*Nb; i++) {
        out[i] = state[i];
    }
    PrintArray("decrypt text", out);
}


/**
 * key expansion 
*/
void KeyExpansion(byte* key, byte* word) {
    byte Rcon_Nr10[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    for(int i = 0; i < Nk * 4; i++) {
        word[i] = key[i];
    } 
	for (int i = Nk*4; i < (Nr+1)*Nk*4; i++) {
		if (i % 16 == 0)
			word[i] = s_box[word[i-3]] ^ Rcon_Nr10[(i-16)/16] ^ word[i-16];
		if ((i%16) == 1 || (i%16) == 2)
			word[i] = s_box[word[i-3]] ^ word[i-16];
		if (i % 16 == 3)
			word[i] = s_box[word[i-7]] ^ word[i-16];
		if ((i % 16) > 3)
			word[i] = word[i-4] ^ word[i-16];
	}
}


/**
 * sub bytes
*/
void SubBytes(byte* state) {
    for(int i = 0; i < 4*Nb; i++) {
        state[i] = s_box[state[i]];
    }
}


/**
 * inverse sub bytes
*/
void InvSubBytes(byte* state) {
    for(int i = 0; i < 4*Nb; i++) {
        state[i] = inv_s_box[state[i]];
    }
}


/**
 * shift rows
*/
void ShiftRows(byte* state) {
    byte temp[Nb];
    byte t0;
    
    for(int i = 1; i < 4; i++) {
        for(int j = 0; j < Nb; j++) { 
            temp[j] = state[j*Nb+i];
        }
        // i번 만큼 왼쪽으로 이동
        // TODO : 더 좋은 방법이 있지 않을까?
        for(int k = i; k > 0; k--) {
            t0 = (byte)temp[0];
            for(int l = 0; l < 3; l++) {
                temp[l] = temp[l+1];
            }
            temp[3] = t0;
        }
        for(int j = 0; j < Nb; j++) { 
            state[j*Nb+i] = temp[j];
        }
    }
}


/**
 * inverse shift rows
*/
void InvShiftRows(byte* state) {
    byte temp[Nb];
    byte t3;

    for(int i = 1; i < 4; i++) {
        for(int j = 0; j < Nb; j++) {
            temp[j] = state[j*Nb+i];
        }
        // 오른쪽으로 한칸 씩 이동
        for(int k = i; k > 0; k--) {
            t3 = (byte)temp[3];
            for(int l = 3; l > 0; l--) {
                temp[l] = temp[l-1];
            }
            temp[0] = t3;
        }
        for(int j = 0; j < Nb; j++) {
            state[j*Nb+i] = temp[j];
        }
    }
}


/**
 * mix columns
*/
void MixColumns(byte* state) {
    byte temp[4*Nb];
    for(int i = 0; i < 4*Nb; i++) {
        temp[i] = state[i];
    }
    for(int i = 0; i < Nb; i++) {
        state[4*i+0] = mul(temp[4*i+0], 2) ^ mul(temp[4*i+1], 3) ^ temp[4*i+2] ^ temp[4*i+3];
        state[4*i+1] = mul(temp[4*i+1], 2) ^ mul(temp[4*i+2], 3) ^ temp[4*i+3] ^ temp[4*i+0];
        state[4*i+2] = mul(temp[4*i+2], 2) ^ mul(temp[4*i+3], 3) ^ temp[4*i+0] ^ temp[4*i+1];
        state[4*i+3] = mul(temp[4*i+3], 2) ^ mul(temp[4*i+0], 3) ^ temp[4*i+1] ^ temp[4*i+2];
    }
}


/**
 * inverse mix columns
*/
void InvMixColumns(byte* state) {
    byte temp[4*Nb];
    for(int i = 0; i < 4*Nb; i++) {
        temp[i] = state[i];
    }
    for(int i = 0; i < Nb; i++) {
        state[4*i+0] = mul(temp[4*i+0], 14) ^ mul(temp[4*i+1], 11) ^ mul(temp[4*i+2], 13) ^ mul(temp[4*i+3], 9);
        state[4*i+1] = mul(temp[4*i+1], 14) ^ mul(temp[4*i+2], 11) ^ mul(temp[4*i+3], 13) ^ mul(temp[4*i+0], 9);
        state[4*i+2] = mul(temp[4*i+2], 14) ^ mul(temp[4*i+3], 11) ^ mul(temp[4*i+0], 13) ^ mul(temp[4*i+1], 9);
        state[4*i+3] = mul(temp[4*i+3], 14) ^ mul(temp[4*i+0], 11) ^ mul(temp[4*i+1], 13) ^ mul(temp[4*i+2], 9);
    }
}


/**
 * add round key
*/
void AddRoundKey(byte* state, int round, byte* word) {
    for(int i = 0; i < Nb; i++) {
        state[4*i+0] = state[4*i+0] ^ word[4*(round*Nb+i)+0];
        state[4*i+1] = state[4*i+1] ^ word[4*(round*Nb+i)+1];
        state[4*i+2] = state[4*i+2] ^ word[4*(round*Nb+i)+2];
        state[4*i+3] = state[4*i+3] ^ word[4*(round*Nb+i)+3];
    }
}


/**
 * xtime 
*/
byte xtime(byte byte1) {
    int b7 = byte1 >> 7 & 0x01;
    byte1 = byte1 << 1;
    if(b7 == 1) {
        byte1 ^= 0x1b;
    }
    return byte1;
}


/**
 * multiply x and y
*/
byte mul(byte x, byte y) {
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
}


/**
 * 배열 출력 함수
*/
void PrintArray(char* str, byte* state) {
    printf("## %s : ", str);
    for(int i = 0; i < 4*Nb; i++) {
        printf("%02x, ", state[i]);
    }
    printf("\n");
}


/**
 * w 출력 함수
*/
void PrintW(byte* w) {
    for(int i = 0; i <176; i++) {
        printf("w[%d] : %x \n", i, w[i]);
        if(i % 16 == 0 ) {
            printf("\n");
        }
    } 
}