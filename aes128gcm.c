#include <string.h> /* memset */
#include <stdint.h>
#include <stdio.h>

#include "aes128gcm.h"
#include "aes128e.h"

#define AES_SIZE 16

void xor_block(unsigned char dst[16], const unsigned char src[16]);
//void printbits_64(uint64_t number);
//void printbits(uint32_t number);
//void printbits_8(uint8_t number);
void inc32(unsigned char x[16]);
void g_ctrk(unsigned char *ICB, const unsigned char *X, int len_p, const unsigned char *K, unsigned char *C);
void g_mult(const unsigned char x[16], const unsigned char H[16], unsigned char z[16]);
//void g_hash(unsigned char H[16], unsigned char s_block[16*7], int len_s_block, unsigned char y_output[16]);
void g_hash(unsigned char H[16], unsigned char *s_block, int len_s_block, unsigned char *y_output);

/* Under the 16-byte (128-bit) key "k",
 and the 12-byte (96-bit) initial value "IV",
 encrypt the plaintext "plaintext" and store it at "ciphertext".
 The length of the plaintext is a multiple of 16-byte (128-bit) given by len_p (e.g., len_p = 2 for a 32-byte plaintext).
 The length of the ciphertext "ciphertext" is len_p*16 bytes.
 The authentication tag is obtained by the 16-byte tag "tag".
 For the authentication an additional data "add_data" can be added.
 The number of blocks for this additional data is "len_ad" (e.g., len_ad = 1 for a 16-byte additional data).
 */

/* Multiplication in GF(2^128) */

void right_shift(unsigned char v[16]);

/*void printbits(uint32_t number) {
	int i;
	for (i = 31; i >= 0  ; i--){
		printf("%d", number >> i &1);
		//number >>= 1;
		}
	printf("\n");
}

void printbits_64(uint64_t number) {
	int i;
	for (i = 63; i >= 0  ; i--){
		printf("%d", number >> i &1);
		//number >>= 1;
		}
	printf("\n");
}

void printbits_8(uint8_t number) {
	int i;
	for (i = 7; i >= 0  ; i--){
		printf("%d", number >> i &1);
		//number >>= 1;
		}
	printf("\n");
}*/

void inc32(unsigned char x[16]){
	uint32_t lsb = 0;
	//printbits(lsb);
	lsb |= x[12] << 24;
	lsb |= x[13] << 16;
	lsb |= x[14] << 8;
	lsb |= x[15];

	/*printf("number is bit string of before one\n");
	printbits(lsb);*/

	lsb = lsb+1;

	/*printf("number is bit string of after one\n");
	printbits(lsb);*/

	uint32_t twoP32 = 4294967;

	/*printf("number is bit string of twoP32s\n");
	printbits(4294967);*/

	uint32_t after_mod = lsb % twoP32;

	/*printf("number is bit string of after_mod %u\n", after_mod);
	printbits(after_mod);*/

	x[15] = after_mod;

	after_mod >>= 8;
	x[14] = after_mod;

	after_mod >>= 8;
	x[13] = after_mod;

	after_mod >>= 8;
	x[12] = after_mod;

	/*printbits_8(x[12]);
	printbits_8(x[13]);
	printbits_8(x[14]);
	printbits_8(x[15]);*/
}

void right_shift(unsigned char v[16]){
	int i;
	int lowestBit, highestBit;
	for (i = 0; i< 16; i++){
		lowestBit = v[i] & 0x01;
		v[i] >>= 1;
		if(i != 0){
			v[i] |= (highestBit==0)?(0):(0x80);
		}
		highestBit = lowestBit;
	}
}


void xor_block(unsigned char dst[16], const unsigned char src[16]){
	int i;
	for (i = 0; i< 16; i++){
		dst[i] ^= src[i];
	}
}


void g_mult(const unsigned char x[16], const unsigned char H[16], unsigned char z[16]) {

	unsigned char v[AES_SIZE];

	int i, j;

	memset(z, 0, AES_SIZE);
	memcpy(v, H, AES_SIZE);



	for (i = 0; i < 16; i++) {

		for (j = 0; j < 8; j++) {
			int x_bit = x[i] >> (7-j) &1;

			if (x_bit & 0x01){
				xor_block(z, v);
			}

			if (v[15] & 0x01) {
				right_shift(v);
				v[0] ^= 0xe1;
			}else{
				right_shift(v);
			}


		}
	}

}

/*void g_hash(unsigned char H[16], unsigned char s_block[16*7], int len_s_block, unsigned char y_output[16]){

	memset(y_output, 0, AES_SIZE);

	unsigned char out_s_block[AES_SIZE*7],tmp_s[AES_SIZE], tmp_out_block[AES_SIZE];
	memset(out_s_block, 0, AES_SIZE*7);
	memset(tmp_s, 0, AES_SIZE);
	memset(tmp_out_block, 0, AES_SIZE);

	int i;

	for (i = 1; i<=len_s_block; i++){

		memcpy(tmp_s, s_block + AES_SIZE*(i-1), AES_SIZE);
		if (i == 1){
			g_mult(tmp_s, H, y_output);
		}else{
			memcpy(tmp_out_block, out_s_block + AES_SIZE*(i-2), AES_SIZE);
			xor_block(tmp_out_block, tmp_s);
			g_mult(tmp_out_block, H, y_output);
		}

		memcpy(out_s_block+AES_SIZE*(i-1), y_output, AES_SIZE);
		memset(tmp_s, 0, AES_SIZE);
		memset(tmp_out_block, 0, AES_SIZE);
		memset(y_output, 0, AES_SIZE);
	}

	memcpy(y_output, out_s_block+AES_SIZE*6, AES_SIZE);

}*/

void g_hash(unsigned char H[16], unsigned char *s_block, int len_s_block, unsigned char *y_output){

	memset(y_output, 0, AES_SIZE);

	unsigned char out_s_block[AES_SIZE*len_s_block],tmp_s[AES_SIZE], tmp_out_block[AES_SIZE];
	memset(out_s_block, 0, AES_SIZE*len_s_block);
	memset(tmp_s, 0, AES_SIZE);
	memset(tmp_out_block, 0, AES_SIZE);

	int i;

	for (i = 1; i<=len_s_block; i++){

		memcpy(tmp_s, s_block + AES_SIZE*(i-1), AES_SIZE);
		if (i == 1){
			g_mult(tmp_s, H, y_output);
		}else{
			memcpy(tmp_out_block, out_s_block + AES_SIZE*(i-2), AES_SIZE);
			xor_block(tmp_out_block, tmp_s);
			g_mult(tmp_out_block, H, y_output);
		}

		memcpy(out_s_block+AES_SIZE*(i-1), y_output, AES_SIZE);
		memset(tmp_s, 0, AES_SIZE);
		memset(tmp_out_block, 0, AES_SIZE);
		if (i != len_s_block){
			memset(y_output, 0, AES_SIZE);
		}
	}

}

void g_ctrk(unsigned char *ICB, const unsigned char *X, int len_p, const unsigned char *K, unsigned char *Cipher){
	if (len_p == 0){
		return;
	}
	size_t i;
	unsigned char cb[AES_SIZE*len_p], tmp[AES_SIZE], cipher[AES_SIZE];
	memset(Cipher, 0, AES_SIZE*len_p);
	memset(cb, 0, AES_SIZE*len_p);
	memset(tmp, 0, 16);
	memset(cipher, 0, 16);

	memcpy(cb, ICB, 16);
	memcpy(tmp, ICB, 16);

	for (i = 2; i <= len_p; i++){
		inc32(tmp);
		memcpy(cb+(16*(i-1)), tmp, 16);
	}
	memset(tmp, 0, 16);

	for (i = 1; i<=len_p; i++){

		memset(tmp, 0, 16);
		memcpy(tmp, cb + (16*(i-1)), 16);

		aes128e(cipher, tmp, K);

		memset(tmp, 0, 16);
		memcpy(tmp, X + (16*(i-1)), 16);

		xor_block(tmp, cipher);
		memcpy(Cipher+(16*(i-1)), tmp, 16);

		memset(tmp, 0, 16);
		memset(cipher, 0, 16);
	}
	// LAST BLOCK

	/*memcpy(tmp, cb + 32, 16);
	aes128e(cipher, tmp, K);
	memset(tmp, 0, 16);
	memcpy(tmp, X + 32, 16);
	xor_block(tmp, cipher);
	memcpy(Cipher+32, tmp, 16);*/
}






void aes128gcm(unsigned char *ciphertext, unsigned char *tag,
		const unsigned char *k, const unsigned char *IV,
		const unsigned char *plaintext, const unsigned long len_p,
		const unsigned char* add_data, const unsigned long len_ad) {

	unsigned char H[AES_SIZE], J0[AES_SIZE];

	//Let H = CIPHK(0128).
	memset(H, 0, AES_SIZE);
	aes128e(H, H ,k);

	memset(J0, 0, AES_SIZE);

	int i;

	//Define a block, J0, as follows:
	int lenIV = sizeof(IV)*12;
	// NOt checked for not equal to 96 as we know it is 96
	if (lenIV == 96){
		//printf("\nLENGTH OF IV %d\n", lenIV);
		//printf("\nPrinting IV Bits %d\n", lenIV);
		//for (i = 0; i < 12; i++){
			//printbits_8(IV[i]);
		//}

		// copy IV to MSB of J0
		//printf("\nPrinting J0 Bits %d\n", lenIV);
		//J0 = IV || 031 ||1.
		memcpy(J0, IV, 12);
		J0[AES_SIZE-1] = 0x01;

		//for (i = 0; i < 16; i++){
			//printbits_8(J0[i]);
		//}

		// Let C=GCTRK(inc32(J0), P).
		inc32(J0);
		//printf("\nPrinting J0 Bits after 32 bit increment \n");
		//for (i = 0; i < 16; i++){
			//printbits_8(J0[i]);
		//}

		//Let C=GCTRK(inc32(J0), P).
		g_ctrk(J0, plaintext, len_p, k, ciphertext);

		//Let u = ⋅⎡ ⎤ ( ) C − len128len128 (C) and let v = ⋅⎡ (A) ⎤ − len128len128 ( ) A .
		//int u = 0; 	int v = 0;


		//Define a block, S, as follows:
		//S = GHASH-h-(A || 0v || C || 0u || [len(A)]64 || [len(C)]64)
		int s_size = len_ad+len_p+1;
		unsigned char S_Block[AES_SIZE*s_size];
		memset(S_Block, 0, AES_SIZE*s_size);

		memcpy(S_Block, add_data, AES_SIZE*len_ad);
		memcpy(S_Block+AES_SIZE*len_ad, ciphertext, AES_SIZE*len_p);

		int rem_size = (s_size -1)*AES_SIZE;

		//uint64_t inBits_1 = 384;
		uint64_t inBits_1 = (uint64_t)128*len_ad;

		for (i = rem_size+7; i>=rem_size; i--){
			S_Block[i] |= inBits_1;
			inBits_1 >>= 8;
		}

		//uint64_t inBits_2 = 384;
		uint64_t inBits_2 = (uint64_t)128*len_p;
		for (i = rem_size+15; i>=rem_size+8; i--){
			S_Block[i] |= inBits_2;
			inBits_2 >>= 8;
		}
		puts("\n");

		// Hashing the SBLOCK

		unsigned char s_hashed[AES_SIZE];
		g_hash(H, S_Block, len_ad+len_p+1, s_hashed);
		// S_BLOCK GENERATION COMPLETE......


		memset(J0, 0, AES_SIZE);
		memcpy(J0, IV, 12);
		J0[AES_SIZE-1] = 0x01;
		g_ctrk(J0, s_hashed, 1, k, tag);

	}



}

























