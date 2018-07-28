/*
* Copyright (c) 2009 Colin Percival, 2011 ArtForz
* Copyright (c) 2012 Andrew Moon (floodyberry)
* Copyright (c) 2012 Samuel Neves <sneves@dei.uc.pt>
* Copyright (c) 2014 John Doering <ghostlander@phoenixcoin.org>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "miner.h"

#if (WINDOWS)
/* sizeof(unsigned long) = 4 for MinGW64 */
typedef unsigned long long ulong;
#else
typedef unsigned long ulong;
#endif
typedef unsigned int  uint;

#ifndef SSE

/* NeoScrypt */
static void neoscrypt_salsa_tangle(uint *X)
{
	register __m256i ymm0, ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7;
	for (int i = 0; i < 16; i += 4)
	{
		ymm0 = _mm256_load_si256((__m256i*)X + i + 0);				// 0 1 2 3    0 5 A F
		ymm1 = _mm256_load_si256((__m256i*)X + i + 1);				// 4 5 6 7    C 1 6 B
		ymm2 = _mm256_load_si256((__m256i*)X + i + 2);				// 8 9 A B    8 D 2 7
		ymm3 = _mm256_load_si256((__m256i*)X + i + 3);				// C D E F    4 9 E 3

																	// 0 1 2 3    0 5 A F
		ymm1 = _mm256_shuffle_epi32(ymm1, _MM_SHUFFLE(0, 3, 2, 1));	// 5 6 7 4    1 6 B C
		ymm2 = _mm256_shuffle_epi32(ymm2, _MM_SHUFFLE(1, 0, 3, 2));	// A B 8 9    2 7 8 D
		ymm3 = _mm256_shuffle_epi32(ymm3, _MM_SHUFFLE(2, 1, 0, 3));	// F C D E    3 4 9 E

		ymm4 = _mm256_unpacklo_epi32(ymm0, ymm1);					// 0 5 1 6    0 1 5 6
		ymm5 = _mm256_unpackhi_epi32(ymm0, ymm1);					// 2 7 3 4    A B F C
		ymm6 = _mm256_unpacklo_epi32(ymm2, ymm3);					// A F B C    2 3 7 4
		ymm7 = _mm256_unpackhi_epi32(ymm2, ymm3);					// 8 D 9 E    8 9 D E

		ymm0 = _mm256_unpacklo_epi64(ymm4, ymm6);					// 0 5 A F    0 1 2 3
		ymm1 = _mm256_unpackhi_epi64(ymm4, ymm6);					// 1 6 B C    5 6 7 4
		ymm2 = _mm256_unpacklo_epi64(ymm5, ymm7);					// 2 7 8 D    A B 8 9
		ymm3 = _mm256_unpackhi_epi64(ymm5, ymm7);					// 3 4 9 E    F C D E

																	// 0 5 A F    0 1 2 3
		ymm1 = _mm256_shuffle_epi32(ymm1, _MM_SHUFFLE(2, 1, 0, 3));	// C 1 6 B    4 5 6 7
		ymm2 = _mm256_shuffle_epi32(ymm2, _MM_SHUFFLE(1, 0, 3, 2));	// 8 D 2 7    8 9 A B
		ymm3 = _mm256_shuffle_epi32(ymm3, _MM_SHUFFLE(0, 3, 2, 1));	// 4 9 E 3    C D E F

		_mm256_store_si256((__m256i*)X + i + 0, ymm0);
		_mm256_store_si256((__m256i*)X + i + 1, ymm1);
		_mm256_store_si256((__m256i*)X + i + 2, ymm2);
		_mm256_store_si256((__m256i*)X + i + 3, ymm3);
	}
}

/* Salsa20, rounds must be a multiple of 2 */
static void neoscrypt_salsa(__m256i *X, uint rounds) {
	register __m256i ymm0, ymm1, ymm2, ymm3, ymm12, ymm13, ymm14, ymm15;
	register __m256i ymm4;

	ymm0 = _mm256_load_si256(X + 0);						// 0 5 A F
	ymm1 = _mm256_load_si256(X + 1);						// C 1 6 B
	ymm2 = _mm256_load_si256(X + 2);						// 8 D 2 7
	ymm3 = _mm256_load_si256(X + 3);						// 4 9 E 3
	ymm12 = ymm0;
	ymm13 = ymm1;
	ymm14 = ymm2;
	ymm15 = ymm3;

#define quarter(a, b, c, d, tmp) \
    tmp = _mm256_add_epi32(a, d); b = _mm256_xor_si256(b, _mm256_slli_epi32(tmp, 7)); b = _mm256_xor_si256(b, _mm256_srli_epi32(tmp, 32 - 7)); \
    tmp = _mm256_add_epi32(b, a); c = _mm256_xor_si256(c, _mm256_slli_epi32(tmp, 9)); c = _mm256_xor_si256(c, _mm256_srli_epi32(tmp, 32 - 9)); \
    tmp = _mm256_add_epi32(c, b); d = _mm256_xor_si256(d, _mm256_slli_epi32(tmp, 13)); d = _mm256_xor_si256(d, _mm256_srli_epi32(tmp, 32 - 13)); \
    tmp = _mm256_add_epi32(d, c); a = _mm256_xor_si256(a, _mm256_slli_epi32(tmp, 18)); a = _mm256_xor_si256(a, _mm256_srli_epi32(tmp, 32 - 18))

	for (; rounds; rounds -= 2) {
		quarter(ymm0, ymm3, ymm2, ymm1, ymm4);
		// 0 5 A F
		ymm1 = _mm256_shuffle_epi32(ymm1, _MM_SHUFFLE(0, 3, 2, 1));	// 1 6 B C
		ymm2 = _mm256_shuffle_epi32(ymm2, _MM_SHUFFLE(1, 0, 3, 2));	// 2 7 8 D
		ymm3 = _mm256_shuffle_epi32(ymm3, _MM_SHUFFLE(2, 1, 0, 3));	// 3 4 9 E
		quarter(ymm0, ymm1, ymm2, ymm3, ymm4);
		// 0 5 A F
		ymm1 = _mm256_shuffle_epi32(ymm1, _MM_SHUFFLE(2, 1, 0, 3));	// C 1 6 B
		ymm2 = _mm256_shuffle_epi32(ymm2, _MM_SHUFFLE(1, 0, 3, 2));	// 8 D 2 7
		ymm3 = _mm256_shuffle_epi32(ymm3, _MM_SHUFFLE(0, 3, 2, 1));	// 4 9 E 3
	}

	ymm0 = _mm256_add_epi32(ymm0, ymm12);
	ymm1 = _mm256_add_epi32(ymm1, ymm13);
	ymm2 = _mm256_add_epi32(ymm2, ymm14);
	ymm3 = _mm256_add_epi32(ymm3, ymm15);

	_mm256_store_si256(X + 0, ymm0);
	_mm256_store_si256(X + 1, ymm1);
	_mm256_store_si256(X + 2, ymm2);
	_mm256_store_si256(X + 3, ymm3);

#undef quarter
}

/* ChaCha20, rounds must be a multiple of 2 */
static void neoscrypt_chacha(__m256i *X, uint rounds) {
	register __m256i ymm0, ymm1, ymm2, ymm3, ymm12, ymm13, ymm14, ymm15;

	ymm0 = _mm256_load_si256(X + 0);							// 0 1 2 3
	ymm1 = _mm256_load_si256(X + 1);							// 4 5 6 7
	ymm2 = _mm256_load_si256(X + 2);							// 8 9 A B
	ymm3 = _mm256_load_si256(X + 3);							// C D E F
	ymm12 = ymm0;
	ymm13 = ymm1;
	ymm14 = ymm2;
	ymm15 = ymm3;

#define quarter(a,b,c,d) \
    a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); d = _mm256_shufflehi_epi16(_mm256_shufflelo_epi16(d, 0xB1), 0xB1); \
    c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); b = _mm256_xor_si256(_mm256_slli_epi32(b, 12), _mm256_srli_epi32(b, 32 - 12)); \
    a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); d = _mm256_xor_si256(_mm256_slli_epi32(d, 8), _mm256_srli_epi32(d, 32 - 8)); \
    c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); b = _mm256_xor_si256(_mm256_slli_epi32(b, 7), _mm256_srli_epi32(b, 32 - 7)); \

	for (; rounds; rounds -= 2) {
		quarter(ymm0, ymm1, ymm2, ymm3);
		// 0 1 2 3
		ymm1 = _mm256_shuffle_epi32(ymm1, _MM_SHUFFLE(0, 3, 2, 1));	// 5 6 7 4
		ymm2 = _mm256_shuffle_epi32(ymm2, _MM_SHUFFLE(1, 0, 3, 2));	// A B 8 9
		ymm3 = _mm256_shuffle_epi32(ymm3, _MM_SHUFFLE(2, 1, 0, 3));	// F C D E

		quarter(ymm0, ymm1, ymm2, ymm3);
		// 0 1 2 3
		ymm1 = _mm256_shuffle_epi32(ymm1, _MM_SHUFFLE(2, 1, 0, 3));	// 4 5 6 7
		ymm2 = _mm256_shuffle_epi32(ymm2, _MM_SHUFFLE(1, 0, 3, 2));	// 8 9 A B
		ymm3 = _mm256_shuffle_epi32(ymm3, _MM_SHUFFLE(0, 3, 2, 1));	// C D E F
	}

	ymm0 = _mm256_add_epi32(ymm0, ymm12);
	ymm1 = _mm256_add_epi32(ymm1, ymm13);
	ymm2 = _mm256_add_epi32(ymm2, ymm14);
	ymm3 = _mm256_add_epi32(ymm3, ymm15);

	_mm256_store_si256(X + 0, ymm0);
	_mm256_store_si256(X + 1, ymm1);
	_mm256_store_si256(X + 2, ymm2);
	_mm256_store_si256(X + 3, ymm3);

#undef quarter
}

/* Fast 32-bit / 64-bit memcpy();
* len must be a multiple of 32 bytes */
static void neoscrypt_blkcpy(__m256i *dst, const __m256i *src) {
	_mm256_store_si256(dst + 0, _mm256_load_si256(src + 0));
	_mm256_store_si256(dst + 1, _mm256_load_si256(src + 1));
	_mm256_store_si256(dst + 2, _mm256_load_si256(src + 2));
	_mm256_store_si256(dst + 3, _mm256_load_si256(src + 3));
	_mm256_store_si256(dst + 4, _mm256_load_si256(src + 4));
	_mm256_store_si256(dst + 5, _mm256_load_si256(src + 5));
	_mm256_store_si256(dst + 6, _mm256_load_si256(src + 6));
	_mm256_store_si256(dst + 7, _mm256_load_si256(src + 7));
	_mm256_store_si256(dst + 8, _mm256_load_si256(src + 8));
	_mm256_store_si256(dst + 9, _mm256_load_si256(src + 9));
	_mm256_store_si256(dst + 10, _mm256_load_si256(src + 10));
	_mm256_store_si256(dst + 11, _mm256_load_si256(src + 11));
	_mm256_store_si256(dst + 12, _mm256_load_si256(src + 12));
	_mm256_store_si256(dst + 13, _mm256_load_si256(src + 13));
	_mm256_store_si256(dst + 14, _mm256_load_si256(src + 14));
	_mm256_store_si256(dst + 15, _mm256_load_si256(src + 15));
}

/* Fast 32-bit / 64-bit block XOR engine;
* len must be a multiple of 32 bytes */
static void neoscrypt_blkxor(__m256i *dst, const __m256i *src) {
	_mm256_store_si256(dst + 0, _mm256_xor_si256(_mm256_load_si256(dst + 0), _mm256_load_si256(src + 0)));
	_mm256_store_si256(dst + 1, _mm256_xor_si256(_mm256_load_si256(dst + 1), _mm256_load_si256(src + 1)));
	_mm256_store_si256(dst + 2, _mm256_xor_si256(_mm256_load_si256(dst + 2), _mm256_load_si256(src + 2)));
	_mm256_store_si256(dst + 3, _mm256_xor_si256(_mm256_load_si256(dst + 3), _mm256_load_si256(src + 3)));
	_mm256_store_si256(dst + 4, _mm256_xor_si256(_mm256_load_si256(dst + 4), _mm256_load_si256(src + 4)));
	_mm256_store_si256(dst + 5, _mm256_xor_si256(_mm256_load_si256(dst + 5), _mm256_load_si256(src + 5)));
	_mm256_store_si256(dst + 6, _mm256_xor_si256(_mm256_load_si256(dst + 6), _mm256_load_si256(src + 6)));
	_mm256_store_si256(dst + 7, _mm256_xor_si256(_mm256_load_si256(dst + 7), _mm256_load_si256(src + 7)));
	_mm256_store_si256(dst + 8, _mm256_xor_si256(_mm256_load_si256(dst + 8), _mm256_load_si256(src + 8)));
	_mm256_store_si256(dst + 9, _mm256_xor_si256(_mm256_load_si256(dst + 9), _mm256_load_si256(src + 9)));
	_mm256_store_si256(dst + 10, _mm256_xor_si256(_mm256_load_si256(dst + 10), _mm256_load_si256(src + 10)));
	_mm256_store_si256(dst + 11, _mm256_xor_si256(_mm256_load_si256(dst + 11), _mm256_load_si256(src + 11)));
	_mm256_store_si256(dst + 12, _mm256_xor_si256(_mm256_load_si256(dst + 12), _mm256_load_si256(src + 12)));
	_mm256_store_si256(dst + 13, _mm256_xor_si256(_mm256_load_si256(dst + 13), _mm256_load_si256(src + 13)));
	_mm256_store_si256(dst + 14, _mm256_xor_si256(_mm256_load_si256(dst + 14), _mm256_load_si256(src + 14)));
	_mm256_store_si256(dst + 15, _mm256_xor_si256(_mm256_load_si256(dst + 15), _mm256_load_si256(src + 15)));
}

static void neoscrypt_blkxor_select(__m256i *dst, const __m256i *src, uint i, uint j) {
	_mm256_store_si256(dst + 0, _mm256_xor_si256(_mm256_load_si256(dst + 0), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 0) + 1, (__m128i*)(src + 16 * i + 0) + 0)));
	_mm256_store_si256(dst + 1, _mm256_xor_si256(_mm256_load_si256(dst + 1), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 1) + 1, (__m128i*)(src + 16 * i + 1) + 0)));
	_mm256_store_si256(dst + 2, _mm256_xor_si256(_mm256_load_si256(dst + 2), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 2) + 1, (__m128i*)(src + 16 * i + 2) + 0)));
	_mm256_store_si256(dst + 3, _mm256_xor_si256(_mm256_load_si256(dst + 3), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 3) + 1, (__m128i*)(src + 16 * i + 3) + 0)));
	_mm256_store_si256(dst + 4, _mm256_xor_si256(_mm256_load_si256(dst + 4), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 4) + 1, (__m128i*)(src + 16 * i + 4) + 0)));
	_mm256_store_si256(dst + 5, _mm256_xor_si256(_mm256_load_si256(dst + 5), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 5) + 1, (__m128i*)(src + 16 * i + 5) + 0)));
	_mm256_store_si256(dst + 6, _mm256_xor_si256(_mm256_load_si256(dst + 6), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 6) + 1, (__m128i*)(src + 16 * i + 6) + 0)));
	_mm256_store_si256(dst + 7, _mm256_xor_si256(_mm256_load_si256(dst + 7), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 7) + 1, (__m128i*)(src + 16 * i + 7) + 0)));
	_mm256_store_si256(dst + 8, _mm256_xor_si256(_mm256_load_si256(dst + 8), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 8) + 1, (__m128i*)(src + 16 * i + 8) + 0)));
	_mm256_store_si256(dst + 9, _mm256_xor_si256(_mm256_load_si256(dst + 9), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 9) + 1, (__m128i*)(src + 16 * i + 9) + 0)));
	_mm256_store_si256(dst + 10, _mm256_xor_si256(_mm256_load_si256(dst + 10), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 10) + 1, (__m128i*)(src + 16 * i + 10) + 0)));
	_mm256_store_si256(dst + 11, _mm256_xor_si256(_mm256_load_si256(dst + 11), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 11) + 1, (__m128i*)(src + 16 * i + 11) + 0)));
	_mm256_store_si256(dst + 12, _mm256_xor_si256(_mm256_load_si256(dst + 12), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 12) + 1, (__m128i*)(src + 16 * i + 12) + 0)));
	_mm256_store_si256(dst + 13, _mm256_xor_si256(_mm256_load_si256(dst + 13), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 13) + 1, (__m128i*)(src + 16 * i + 13) + 0)));
	_mm256_store_si256(dst + 14, _mm256_xor_si256(_mm256_load_si256(dst + 14), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 14) + 1, (__m128i*)(src + 16 * i + 14) + 0)));
	_mm256_store_si256(dst + 15, _mm256_xor_si256(_mm256_load_si256(dst + 15), _mm256_loadu2_m128i((__m128i*)(src + 16 * j + 15) + 1, (__m128i*)(src + 16 * i + 15) + 0)));
}

/* BLAKE2s */

#define G(a,b,c,d,m,r0,r1,r2,r3,r4,r5,r6,r7) \
  do { \
    a = _mm256_add_epi32(a, b); \
	a = _mm256_add_epi32(a, _mm256_setr_epi32((m)[r0],(m)[r2],(m)[r4],(m)[r6],(m)[r0+16],(m)[r2+16],(m)[r4+16],(m)[r6+16])); \
	d = _mm256_xor_si256(d, a); \
	d = _mm256_xor_si256(_mm256_srli_epi32(d, 16), _mm256_slli_epi32(d, 32 - 16)); \
    c = _mm256_add_epi32(c, d); \
	b = _mm256_xor_si256(b, c); \
	b = _mm256_xor_si256(_mm256_srli_epi32(b, 12), _mm256_slli_epi32(b, 32 - 12)); \
    a = _mm256_add_epi32(a, b); \
	a = _mm256_add_epi32(a, _mm256_setr_epi32((m)[r1],(m)[r3],(m)[r5],(m)[r7],(m)[r1+16],(m)[r3+16],(m)[r5+16],(m)[r7+16])); \
	d = _mm256_xor_si256(d, a); \
	d = _mm256_xor_si256(_mm256_srli_epi32(d, 8), _mm256_slli_epi32(d, 32 - 8)); \
    c = _mm256_add_epi32(c, d); \
	b = _mm256_xor_si256(b, c); \
	b = _mm256_xor_si256(_mm256_srli_epi32(b, 7), _mm256_slli_epi32(b, 32 - 7)); \
  } while(0)
#define ROUND(m,r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15) \
  do { \
    G(ymm0, ymm1, ymm2, ymm3,m,  r0,r1,r2,r3,r4,r5,r6,r7); \
    ymm1 = _mm256_shuffle_epi32(ymm1, _MM_SHUFFLE(0,3,2,1)); \
	ymm2 = _mm256_shuffle_epi32(ymm2, _MM_SHUFFLE(1,0,3,2)); \
	ymm3 = _mm256_shuffle_epi32(ymm3, _MM_SHUFFLE(2,1,0,3)); \
    G(ymm0, ymm1, ymm2, ymm3,m,r8,r9,r10,r11,r12,r13,r14,r15); \
	ymm1 = _mm256_shuffle_epi32(ymm1, _MM_SHUFFLE(2,1,0,3)); \
	ymm2 = _mm256_shuffle_epi32(ymm2, _MM_SHUFFLE(1,0,3,2)); \
	ymm3 = _mm256_shuffle_epi32(ymm3, _MM_SHUFFLE(0,3,2,1)); \
  } while(0)


/* FastKDF, a fast buffered key derivation function:
* FASTKDF_BUFFER_SIZE must be a power of 2;
* password_len, salt_len and output_len should not exceed FASTKDF_BUFFER_SIZE;
* prf_output_size must be <= prf_key_size; */
static void neoscrypt_fastkdf_1(const uchar *password, uint password_len, const uchar *salt, uint salt_len,
	uint N, uchar *output, uint output_len) {

	uint bufptr1 = 0, bufptr2 = 0, i, j;
	__m256i *prf_input1, *prf_input2, *prf_key1, *prf_key2;
	__m256i A[20], B[18], m[4];
	register __m256i ymm0, ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7;

	/* Initialise the password buffer */
	/* Initialise the salt buffer */
	ymm0 = _mm256_loadu_si256((__m256i*)password + 0);
	ymm1 = _mm256_loadu_si256((__m256i*)password + 1);
	ymm2 = _mm256_castsi128_si256(_mm_loadu_si128((__m128i*)password + 4));
	ymm2 = _mm256_permute2x128_si256(ymm2, ymm0, 0x20);
	ymm3 = _mm256_permute2x128_si256(ymm0, ymm1, 0x21);
	ymm4 = _mm256_permute2x128_si256(ymm1, ymm2, 0x21);
	_mm256_store_si256(A + 0, ymm0); _mm256_store_si256(B + 0, ymm0);
	_mm256_store_si256(A + 1, ymm1); _mm256_store_si256(B + 1, ymm1);
	_mm256_store_si256(A + 2, ymm2); _mm256_store_si256(B + 2, ymm2);
	_mm256_store_si256(A + 3, ymm3); _mm256_store_si256(B + 3, ymm3);
	_mm256_store_si256(A + 4, ymm4); _mm256_store_si256(B + 4, ymm4);
	_mm256_store_si256(A + 5, ymm0); _mm256_store_si256(B + 5, ymm0);
	_mm256_store_si256(A + 6, ymm1); _mm256_store_si256(B + 6, ymm1);
	_mm256_store_si256(A + 7, ymm2); _mm256_store_si256(B + 7, ymm2);
	_mm256_store_si256(A + 8, ymm0); _mm256_store_si256(B + 8, ymm0);
	_mm256_store_si256(A + 9, ymm1);
	_mm256_store_si256(A + 10, ymm0); _mm256_store_si256(B + 9, ymm0);
	_mm256_store_si256(A + 11, ymm1); _mm256_store_si256(B + 10, ymm1);
	_mm256_store_si256(A + 12, ymm2); _mm256_store_si256(B + 11, ymm2);
	_mm256_store_si256(A + 13, ymm3); _mm256_store_si256(B + 12, ymm3);
	_mm256_store_si256(A + 14, ymm4); _mm256_store_si256(B + 13, ymm4);
	_mm256_store_si256(A + 15, ymm0); _mm256_store_si256(B + 14, ymm0);
	_mm256_store_si256(A + 16, ymm1); _mm256_store_si256(B + 15, ymm1);
	_mm256_store_si256(A + 17, ymm2); _mm256_store_si256(B + 16, ymm2);
	_mm256_store_si256(A + 18, ymm0); _mm256_store_si256(B + 17, ymm0);
	_mm256_store_si256(A + 19, ymm1);

	/* The primary iteration */
	for (i = 0; i < N; i++) {

		/* Map the PRF input buffer */
		prf_input1 = (__m256i*)((uchar*)(A + 0) + bufptr1);
		prf_input2 = (__m256i*)((uchar*)(A + 10) + bufptr2);

		/* Map the PRF key buffer */
		prf_key1 = (__m256i*)((uchar*)(B + 0) + bufptr1);
		prf_key2 = (__m256i*)((uchar*)(B + 9) + bufptr2);

		/* PRF */
		ymm0 = ymm4 = _mm256_setr_epi32(0x6A09E667 ^ 0x01012020, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x6A09E667 ^ 0x01012020, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A);
		ymm1 = ymm5 = _mm256_setr_epi32(0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
		ymm2 = _mm256_setr_epi32(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A);
		ymm3 = _mm256_setr_epi32(0x510E527F ^ 64, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 0x510E527F ^ 64, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
		_mm256_store_si256(m + 0, _mm256_loadu_si256(prf_key1 + 0));
		_mm256_store_si256(m + 1, _mm256_setzero_si256());
		_mm256_store_si256(m + 2, _mm256_loadu_si256(prf_key2 + 0));
		_mm256_store_si256(m + 3, _mm256_setzero_si256());
		ROUND((uint*)m, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
		ROUND((uint*)m, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
		ROUND((uint*)m, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
		ROUND((uint*)m, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
		ROUND((uint*)m, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
		ROUND((uint*)m, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
		ROUND((uint*)m, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
		ROUND((uint*)m, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
		ROUND((uint*)m, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
		ROUND((uint*)m, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);

		ymm0 = ymm4 = _mm256_xor_si256(_mm256_xor_si256(ymm0, ymm2), ymm4);
		ymm1 = ymm5 = _mm256_xor_si256(_mm256_xor_si256(ymm1, ymm3), ymm5);
		ymm2 = _mm256_setr_epi32(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A);
		ymm3 = _mm256_setr_epi32(0x510E527F ^ 128, 0x9B05688C, 0x1F83D9AB ^ 0xFFFFFFFF, 0x5BE0CD19, 0x510E527F ^ 128, 0x9B05688C, 0x1F83D9AB ^ 0xFFFFFFFF, 0x5BE0CD19);
		_mm256_store_si256(m + 0, _mm256_loadu_si256(prf_input1 + 0));
		_mm256_store_si256(m + 1, _mm256_loadu_si256(prf_input1 + 1));
		_mm256_store_si256(m + 2, _mm256_loadu_si256(prf_input2 + 0));
		_mm256_store_si256(m + 3, _mm256_loadu_si256(prf_input2 + 1));
		ROUND((uint*)m, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
		ROUND((uint*)m, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
		ROUND((uint*)m, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
		ROUND((uint*)m, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
		ROUND((uint*)m, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
		ROUND((uint*)m, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
		ROUND((uint*)m, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
		ROUND((uint*)m, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
		ROUND((uint*)m, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
		ROUND((uint*)m, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);

		ymm0 = _mm256_xor_si256(_mm256_xor_si256(ymm0, ymm2), ymm4);
		ymm1 = _mm256_xor_si256(_mm256_xor_si256(ymm1, ymm3), ymm5);
		ymm2 = _mm256_permute2x128_si256(ymm0, ymm1, 0x31);
		ymm3 = _mm256_permute2x128_si256(ymm0, ymm1, 0x20);

		/* Calculate the next buffer pointer */
		ymm0 = _mm256_add_epi8(ymm0, ymm1);
		ymm0 = _mm256_add_epi8(_mm256_shuffle_epi32(ymm0, _MM_SHUFFLE(2, 3, 0, 1)), ymm0);
		ymm0 = _mm256_add_epi8(_mm256_shuffle_epi32(ymm0, _MM_SHUFFLE(1, 0, 3, 2)), ymm0);
		uint tmp1 = (uint)_mm256_extract_epi32(ymm0, 0);
		uint tmp2 = (uint)_mm256_extract_epi32(ymm0, 4);
		tmp1 = ((tmp1 >> 8) & 0x00FF00FF) + (tmp1 & 0x00FF00FF);
		tmp2 = ((tmp2 >> 8) & 0x00FF00FF) + (tmp2 & 0x00FF00FF);
		tmp1 = ((tmp1 >> 16) & 0x0000FFFF) + (tmp1 & 0x0000FFFF);
		tmp2 = ((tmp2 >> 16) & 0x0000FFFF) + (tmp2 & 0x0000FFFF);
		bufptr1 = tmp1 & 0xFF;
		bufptr2 = tmp2 & 0xFF;

		/* Map the PRF key buffer */
		prf_key1 = (__m256i*)((uchar*)(B + 0) + bufptr1);
		prf_key2 = (__m256i*)((uchar*)(B + 9) + bufptr2);

		/* Modify the salt buffer */
		_mm256_storeu_si256(prf_key1, _mm256_xor_si256(_mm256_loadu_si256(prf_key1), ymm2));
		_mm256_storeu_si256(prf_key2, _mm256_xor_si256(_mm256_loadu_si256(prf_key2), ymm3));

		/* Head modified, tail updated */
		if (bufptr1 < 32)
			_mm256_store_si256(B + 8, _mm256_load_si256(B + 0));
		if (bufptr2 < 32)
			_mm256_store_si256(B + 17, _mm256_load_si256(B + 9));

		/* Tail modified, head updated */
		if ((256 - bufptr1) < 32)
			_mm256_store_si256(B + 0, _mm256_load_si256(B + 8));
		if ((256 - bufptr2) < 32)
			_mm256_store_si256(B + 9, _mm256_load_si256(B + 17));
	}

	/* Modify and copy into the output buffer */
	for (i = 0; i < (output_len >> 5); i++)
	{
		ymm0 = _mm256_xor_si256(_mm256_load_si256(A + i + 0), _mm256_loadu_si256(prf_key1));
		ymm1 = _mm256_xor_si256(_mm256_load_si256(A + i + 10), _mm256_loadu_si256(prf_key2));
		_mm256_store_si256((__m256i*)output + i * 2 + 0, _mm256_permute2x128_si256(ymm0, ymm1, 0x20));
		_mm256_store_si256((__m256i*)output + i * 2 + 1, _mm256_permute2x128_si256(ymm0, ymm1, 0x31));
		bufptr1 = (bufptr1 + 32) & 255;
		bufptr2 = (bufptr2 + 32) & 255;
		prf_key1 = (__m256i*)((uchar*)(B + 0) + bufptr1);
		prf_key2 = (__m256i*)((uchar*)(B + 9) + bufptr2);
	}
}

/* FastKDF, a fast buffered key derivation function:
* FASTKDF_BUFFER_SIZE must be a power of 2;
* password_len, salt_len and output_len should not exceed FASTKDF_BUFFER_SIZE;
* prf_output_size must be <= prf_key_size; */
static void neoscrypt_fastkdf_2(const uchar *password, uint password_len, const uchar *salt, uint salt_len,
	uint N, uchar *output, uint output_len) {

	uint bufptr1 = 0, bufptr2 = 0, i, j;
	__m256i *prf_input1, *prf_input2, *prf_key1, *prf_key2;
	__m256i A[20], B[18], m[4];
	register __m256i ymm0, ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7;

	/* Initialise the password buffer */
	ymm0 = _mm256_loadu_si256((__m256i*)password + 0);
	ymm1 = _mm256_loadu_si256((__m256i*)password + 1);
	ymm2 = _mm256_castsi128_si256(_mm_loadu_si128((__m128i*)password + 4));
	ymm2 = _mm256_permute2x128_si256(ymm2, ymm0, 0x20);
	ymm3 = _mm256_permute2x128_si256(ymm0, ymm1, 0x21);
	ymm4 = _mm256_permute2x128_si256(ymm1, ymm2, 0x21);
	_mm256_store_si256(A + 0, ymm0);
	_mm256_store_si256(A + 1, ymm1);
	_mm256_store_si256(A + 2, ymm2);
	_mm256_store_si256(A + 3, ymm3);
	_mm256_store_si256(A + 4, ymm4);
	_mm256_store_si256(A + 5, ymm0);
	_mm256_store_si256(A + 6, ymm1);
	_mm256_store_si256(A + 7, ymm2);
	_mm256_store_si256(A + 8, ymm0);
	_mm256_store_si256(A + 9, ymm1);
	_mm256_store_si256(A + 10, ymm0);
	_mm256_store_si256(A + 11, ymm1);
	_mm256_store_si256(A + 12, ymm2);
	_mm256_store_si256(A + 13, ymm3);
	_mm256_store_si256(A + 14, ymm4);
	_mm256_store_si256(A + 15, ymm0);
	_mm256_store_si256(A + 16, ymm1);
	_mm256_store_si256(A + 17, ymm2);
	_mm256_store_si256(A + 18, ymm0);
	_mm256_store_si256(A + 19, ymm1);

	/* Initialise the salt buffer */
	ymm0 = _mm256_load_si256((__m256i*)salt + 0);
	ymm4 = _mm256_load_si256((__m256i*)salt + 1);
	ymm1 = _mm256_load_si256((__m256i*)salt + 2);
	ymm5 = _mm256_load_si256((__m256i*)salt + 3);
	ymm2 = _mm256_permute2x128_si256(ymm0, ymm4, 0x31);
	ymm0 = _mm256_permute2x128_si256(ymm0, ymm4, 0x20);
	ymm3 = _mm256_permute2x128_si256(ymm1, ymm5, 0x31);
	ymm1 = _mm256_permute2x128_si256(ymm1, ymm5, 0x20);
	_mm256_store_si256(B + 0, ymm0); _mm256_store_si256(B + 8, ymm0);
	_mm256_store_si256(B + 1, ymm1);
	_mm256_store_si256(B + 9, ymm2); _mm256_store_si256(B + 17, ymm2);
	_mm256_store_si256(B + 10, ymm3);
	ymm0 = _mm256_load_si256((__m256i*)salt + 4);
	ymm4 = _mm256_load_si256((__m256i*)salt + 5);
	ymm1 = _mm256_load_si256((__m256i*)salt + 6);
	ymm5 = _mm256_load_si256((__m256i*)salt + 7);
	ymm2 = _mm256_permute2x128_si256(ymm0, ymm4, 0x31);
	ymm0 = _mm256_permute2x128_si256(ymm0, ymm4, 0x20);
	ymm3 = _mm256_permute2x128_si256(ymm1, ymm5, 0x31);
	ymm1 = _mm256_permute2x128_si256(ymm1, ymm5, 0x20);
	_mm256_store_si256(B + 2, ymm0);
	_mm256_store_si256(B + 3, ymm1);
	_mm256_store_si256(B + 11, ymm2);
	_mm256_store_si256(B + 12, ymm3);
	ymm0 = _mm256_load_si256((__m256i*)salt + 8);
	ymm4 = _mm256_load_si256((__m256i*)salt + 9);
	ymm1 = _mm256_load_si256((__m256i*)salt + 10);
	ymm5 = _mm256_load_si256((__m256i*)salt + 11);
	ymm2 = _mm256_permute2x128_si256(ymm0, ymm4, 0x31);
	ymm0 = _mm256_permute2x128_si256(ymm0, ymm4, 0x20);
	ymm3 = _mm256_permute2x128_si256(ymm1, ymm5, 0x31);
	ymm1 = _mm256_permute2x128_si256(ymm1, ymm5, 0x20);
	_mm256_store_si256(B + 4, ymm0);
	_mm256_store_si256(B + 5, ymm1);
	_mm256_store_si256(B + 13, ymm2);
	_mm256_store_si256(B + 14, ymm3);
	ymm0 = _mm256_load_si256((__m256i*)salt + 12);
	ymm4 = _mm256_load_si256((__m256i*)salt + 13);
	ymm1 = _mm256_load_si256((__m256i*)salt + 14);
	ymm5 = _mm256_load_si256((__m256i*)salt + 15);
	ymm2 = _mm256_permute2x128_si256(ymm0, ymm4, 0x31);
	ymm0 = _mm256_permute2x128_si256(ymm0, ymm4, 0x20);
	ymm3 = _mm256_permute2x128_si256(ymm1, ymm5, 0x31);
	ymm1 = _mm256_permute2x128_si256(ymm1, ymm5, 0x20);
	_mm256_store_si256(B + 6, ymm0);
	_mm256_store_si256(B + 7, ymm1);
	_mm256_store_si256(B + 15, ymm2);
	_mm256_store_si256(B + 16, ymm3);

	/* The primary iteration */
	for (i = 0; i < N; i++) {

		/* Map the PRF input buffer */
		prf_input1 = (__m256i*)((uchar*)(A + 0) + bufptr1);
		prf_input2 = (__m256i*)((uchar*)(A + 10) + bufptr2);

		/* Map the PRF key buffer */
		prf_key1 = (__m256i*)((uchar*)(B + 0) + bufptr1);
		prf_key2 = (__m256i*)((uchar*)(B + 9) + bufptr2);

		/* PRF */
		ymm0 = ymm4 = _mm256_setr_epi32(0x6A09E667 ^ 0x01012020, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x6A09E667 ^ 0x01012020, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A);
		ymm1 = ymm5 = _mm256_setr_epi32(0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
		ymm2 = _mm256_setr_epi32(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A);
		ymm3 = _mm256_setr_epi32(0x510E527F ^ 64, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 0x510E527F ^ 64, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
		_mm256_store_si256(m + 0, _mm256_loadu_si256(prf_key1 + 0));
		_mm256_store_si256(m + 1, _mm256_setzero_si256());
		_mm256_store_si256(m + 2, _mm256_loadu_si256(prf_key2 + 0));
		_mm256_store_si256(m + 3, _mm256_setzero_si256());
		ROUND((uint*)m, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
		ROUND((uint*)m, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
		ROUND((uint*)m, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
		ROUND((uint*)m, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
		ROUND((uint*)m, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
		ROUND((uint*)m, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
		ROUND((uint*)m, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
		ROUND((uint*)m, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
		ROUND((uint*)m, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
		ROUND((uint*)m, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);

		ymm0 = ymm4 = _mm256_xor_si256(_mm256_xor_si256(ymm0, ymm2), ymm4);
		ymm1 = ymm5 = _mm256_xor_si256(_mm256_xor_si256(ymm1, ymm3), ymm5);
		ymm2 = _mm256_setr_epi32(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A);
		ymm3 = _mm256_setr_epi32(0x510E527F ^ 128, 0x9B05688C, 0x1F83D9AB ^ 0xFFFFFFFF, 0x5BE0CD19, 0x510E527F ^ 128, 0x9B05688C, 0x1F83D9AB ^ 0xFFFFFFFF, 0x5BE0CD19);
		_mm256_store_si256(m + 0, _mm256_loadu_si256(prf_input1 + 0));
		_mm256_store_si256(m + 1, _mm256_loadu_si256(prf_input1 + 1));
		_mm256_store_si256(m + 2, _mm256_loadu_si256(prf_input2 + 0));
		_mm256_store_si256(m + 3, _mm256_loadu_si256(prf_input2 + 1));
		ROUND((uint*)m, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
		ROUND((uint*)m, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
		ROUND((uint*)m, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
		ROUND((uint*)m, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
		ROUND((uint*)m, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
		ROUND((uint*)m, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
		ROUND((uint*)m, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
		ROUND((uint*)m, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
		ROUND((uint*)m, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
		ROUND((uint*)m, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);

		ymm0 = _mm256_xor_si256(_mm256_xor_si256(ymm0, ymm2), ymm4);
		ymm1 = _mm256_xor_si256(_mm256_xor_si256(ymm1, ymm3), ymm5);
		ymm2 = _mm256_permute2x128_si256(ymm0, ymm1, 0x31);
		ymm3 = _mm256_permute2x128_si256(ymm0, ymm1, 0x20);

		/* Calculate the next buffer pointer */
		ymm0 = _mm256_add_epi8(ymm0, ymm1);
		ymm0 = _mm256_add_epi8(_mm256_shuffle_epi32(ymm0, _MM_SHUFFLE(2, 3, 0, 1)), ymm0);
		ymm0 = _mm256_add_epi8(_mm256_shuffle_epi32(ymm0, _MM_SHUFFLE(1, 0, 3, 2)), ymm0);
		uint tmp1 = (uint)_mm256_extract_epi32(ymm0, 0);
		uint tmp2 = (uint)_mm256_extract_epi32(ymm0, 4);
		tmp1 = ((tmp1 >> 8) & 0x00FF00FF) + (tmp1 & 0x00FF00FF);
		tmp2 = ((tmp2 >> 8) & 0x00FF00FF) + (tmp2 & 0x00FF00FF);
		tmp1 = ((tmp1 >> 16) & 0x0000FFFF) + (tmp1 & 0x0000FFFF);
		tmp2 = ((tmp2 >> 16) & 0x0000FFFF) + (tmp2 & 0x0000FFFF);
		bufptr1 = tmp1 & 0xFF;
		bufptr2 = tmp2 & 0xFF;

		/* Map the PRF key buffer */
		prf_key1 = (__m256i*)((uchar*)(B + 0) + bufptr1);
		prf_key2 = (__m256i*)((uchar*)(B + 9) + bufptr2);

		/* Modify the salt buffer */
		_mm256_storeu_si256(prf_key1, _mm256_xor_si256(_mm256_loadu_si256(prf_key1), ymm2));
		_mm256_storeu_si256(prf_key2, _mm256_xor_si256(_mm256_loadu_si256(prf_key2), ymm3));

		/* Head modified, tail updated */
		if (bufptr1 < 32)
			_mm256_store_si256(B + 8, _mm256_load_si256(B + 0));
		if (bufptr2 < 32)
			_mm256_store_si256(B + 17, _mm256_load_si256(B + 9));

		/* Tail modified, head updated */
		if ((256 - bufptr1) < 32)
			_mm256_store_si256(B + 0, _mm256_load_si256(B + 8));
		if ((256 - bufptr2) < 32)
			_mm256_store_si256(B + 9, _mm256_load_si256(B + 17));
	}

	/* Modify and copy into the output buffer */
	for (i = 0; i < (output_len >> 5); i++)
	{
		ymm0 = _mm256_xor_si256(_mm256_load_si256(A + i + 0), _mm256_loadu_si256(prf_key1));
		ymm1 = _mm256_xor_si256(_mm256_load_si256(A + i + 10), _mm256_loadu_si256(prf_key2));
		_mm256_store_si256((__m256i*)output + (output_len >> 5) * 0 + i, ymm0);
		_mm256_store_si256((__m256i*)output + (output_len >> 5) * 1 + i, ymm1);
		bufptr1 = (bufptr1 + 32) & 255;
		bufptr2 = (bufptr2 + 32) & 255;
		prf_key1 = (__m256i*)((uchar*)(B + 0) + bufptr1);
		prf_key2 = (__m256i*)((uchar*)(B + 9) + bufptr2);
	}
}
#undef G
#undef ROUND

/* Configurable optimised block mixer */
static void neoscrypt_blkmix_chacha(__m256i *X) {
	/* NeoScrypt flow:                   Scrypt flow:
	Xa ^= Xd;  M(Xa'); Ya = Xa";      Xa ^= Xb;  M(Xa'); Ya = Xa";
	Xb ^= Xa"; M(Xb'); Yb = Xb";      Xb ^= Xa"; M(Xb'); Yb = Xb";
	Xc ^= Xb"; M(Xc'); Yc = Xc";      Xa" = Ya;
	Xd ^= Xc"; M(Xd'); Yd = Xd";      Xb" = Yb;
	Xa" = Ya; Xb" = Yc;
	Xc" = Yb; Xd" = Yd; */

	__m256i temp[4];
	_mm256_store_si256(X + 0, _mm256_xor_si256(_mm256_load_si256(X + 0), _mm256_load_si256(X + 12)));
	_mm256_store_si256(X + 1, _mm256_xor_si256(_mm256_load_si256(X + 1), _mm256_load_si256(X + 13)));
	_mm256_store_si256(X + 2, _mm256_xor_si256(_mm256_load_si256(X + 2), _mm256_load_si256(X + 14)));
	_mm256_store_si256(X + 3, _mm256_xor_si256(_mm256_load_si256(X + 3), _mm256_load_si256(X + 15)));
	neoscrypt_chacha(&X[0], 20);
	_mm256_store_si256(temp + 0, _mm256_xor_si256(_mm256_load_si256(X + 4), _mm256_load_si256(X + 0)));
	_mm256_store_si256(temp + 1, _mm256_xor_si256(_mm256_load_si256(X + 5), _mm256_load_si256(X + 1)));
	_mm256_store_si256(temp + 2, _mm256_xor_si256(_mm256_load_si256(X + 6), _mm256_load_si256(X + 2)));
	_mm256_store_si256(temp + 3, _mm256_xor_si256(_mm256_load_si256(X + 7), _mm256_load_si256(X + 3)));
	neoscrypt_chacha(temp, 20);
	_mm256_store_si256(X + 4, _mm256_xor_si256(_mm256_load_si256(X + 8), _mm256_load_si256(temp + 0)));
	_mm256_store_si256(X + 5, _mm256_xor_si256(_mm256_load_si256(X + 9), _mm256_load_si256(temp + 1)));
	_mm256_store_si256(X + 6, _mm256_xor_si256(_mm256_load_si256(X + 10), _mm256_load_si256(temp + 2)));
	_mm256_store_si256(X + 7, _mm256_xor_si256(_mm256_load_si256(X + 11), _mm256_load_si256(temp + 3)));
	neoscrypt_chacha(&X[4], 20);
	_mm256_store_si256(X + 12, _mm256_xor_si256(_mm256_load_si256(X + 12), _mm256_load_si256(X + 4)));
	_mm256_store_si256(X + 13, _mm256_xor_si256(_mm256_load_si256(X + 13), _mm256_load_si256(X + 5)));
	_mm256_store_si256(X + 14, _mm256_xor_si256(_mm256_load_si256(X + 14), _mm256_load_si256(X + 6)));
	_mm256_store_si256(X + 15, _mm256_xor_si256(_mm256_load_si256(X + 15), _mm256_load_si256(X + 7)));
	neoscrypt_chacha(&X[12], 20);
	_mm256_store_si256(X + 8, _mm256_load_si256(temp + 0));
	_mm256_store_si256(X + 9, _mm256_load_si256(temp + 1));
	_mm256_store_si256(X + 10, _mm256_load_si256(temp + 2));
	_mm256_store_si256(X + 11, _mm256_load_si256(temp + 3));
}

/* Configurable optimised block mixer */
static void neoscrypt_blkmix_salsa(__m256i *X) {
	/* NeoScrypt flow:                   Scrypt flow:
	Xa ^= Xd;  M(Xa'); Ya = Xa";      Xa ^= Xb;  M(Xa'); Ya = Xa";
	Xb ^= Xa"; M(Xb'); Yb = Xb";      Xb ^= Xa"; M(Xb'); Yb = Xb";
	Xc ^= Xb"; M(Xc'); Yc = Xc";      Xa" = Ya;
	Xd ^= Xc"; M(Xd'); Yd = Xd";      Xb" = Yb;
	Xa" = Ya; Xb" = Yc;
	Xc" = Yb; Xd" = Yd; */

	__m256i temp[4];
	_mm256_store_si256(X + 0, _mm256_xor_si256(_mm256_load_si256(X + 0), _mm256_load_si256(X + 12)));
	_mm256_store_si256(X + 1, _mm256_xor_si256(_mm256_load_si256(X + 1), _mm256_load_si256(X + 13)));
	_mm256_store_si256(X + 2, _mm256_xor_si256(_mm256_load_si256(X + 2), _mm256_load_si256(X + 14)));
	_mm256_store_si256(X + 3, _mm256_xor_si256(_mm256_load_si256(X + 3), _mm256_load_si256(X + 15)));
	neoscrypt_salsa(&X[0], 20);
	_mm256_store_si256(temp + 0, _mm256_xor_si256(_mm256_load_si256(X + 4), _mm256_load_si256(X + 0)));
	_mm256_store_si256(temp + 1, _mm256_xor_si256(_mm256_load_si256(X + 5), _mm256_load_si256(X + 1)));
	_mm256_store_si256(temp + 2, _mm256_xor_si256(_mm256_load_si256(X + 6), _mm256_load_si256(X + 2)));
	_mm256_store_si256(temp + 3, _mm256_xor_si256(_mm256_load_si256(X + 7), _mm256_load_si256(X + 3)));
	neoscrypt_salsa(temp, 20);
	_mm256_store_si256(X + 4, _mm256_xor_si256(_mm256_load_si256(X + 8), _mm256_load_si256(temp + 0)));
	_mm256_store_si256(X + 5, _mm256_xor_si256(_mm256_load_si256(X + 9), _mm256_load_si256(temp + 1)));
	_mm256_store_si256(X + 6, _mm256_xor_si256(_mm256_load_si256(X + 10), _mm256_load_si256(temp + 2)));
	_mm256_store_si256(X + 7, _mm256_xor_si256(_mm256_load_si256(X + 11), _mm256_load_si256(temp + 3)));
	neoscrypt_salsa(&X[4], 20);
	_mm256_store_si256(X + 12, _mm256_xor_si256(_mm256_load_si256(X + 12), _mm256_load_si256(X + 4)));
	_mm256_store_si256(X + 13, _mm256_xor_si256(_mm256_load_si256(X + 13), _mm256_load_si256(X + 5)));
	_mm256_store_si256(X + 14, _mm256_xor_si256(_mm256_load_si256(X + 14), _mm256_load_si256(X + 6)));
	_mm256_store_si256(X + 15, _mm256_xor_si256(_mm256_load_si256(X + 15), _mm256_load_si256(X + 7)));
	neoscrypt_salsa(&X[12], 20);
	_mm256_store_si256(X + 8, _mm256_load_si256(temp + 0));
	_mm256_store_si256(X + 9, _mm256_load_si256(temp + 1));
	_mm256_store_si256(X + 10, _mm256_load_si256(temp + 2));
	_mm256_store_si256(X + 11, _mm256_load_si256(temp + 3));
}

/* NeoScrypt core engine:
* p = 1, salt = password;
* Basic customisation (required):
*   profile bit 0:
*     0 = NeoScrypt(128, 2, 1) with Salsa20/20 and ChaCha20/20;
*     1 = Scrypt(1024, 1, 1) with Salsa20/8;
*   profile bits 4 to 1:
*     0000 = FastKDF-BLAKE2s;
*     0001 = PBKDF2-HMAC-SHA256;
* Extended customisation (optional):
*   profile bit 31:
*     0 = extended customisation absent;
*     1 = extended customisation present;
*   profile bits 7 to 5 (rfactor):
*     000 = r of 1;
*     001 = r of 2;
*     010 = r of 4;
*     ...
*     111 = r of 128;
*   profile bits 12 to 8 (Nfactor):
*     00000 = N of 2;
*     00001 = N of 4;
*     00010 = N of 8;
*     .....
*     00110 = N of 128;
*     .....
*     01001 = N of 1024;
*     .....
*     11110 = N of 2147483648;
*   profile bits 30 to 13 are reserved */
void neoscrypt(uchar *output, const uchar *password, uint32_t profile)
{
	uint i, j, k;
	__m256i X[16];
	__m256i Z[16];
	__m256i V[128 * 16];

	neoscrypt_fastkdf_1(password, 80, password, 80, 32, (uchar *)X, 256);

	/* Process ChaCha 1st, Salsa 2nd and XOR them into FastKDF; otherwise Salsa only */
	/* blkcpy(Z, X) */
	neoscrypt_blkcpy(Z, X);

	/* Z = SMix(Z) */
	for (i = 0; i < 128; i++) {
		/* blkcpy(V, Z) */
		neoscrypt_blkcpy(V + i * 16, Z);
		/* blkmix(Z, Y) */
		neoscrypt_blkmix_chacha(Z);
	}
	for (i = 0; i < 128; i++) {
		/* integerify(Z) mod N */
		j = Z[12].m256i_u32[0] & 127;
		k = Z[12].m256i_u32[4] & 127;
		/* blkxor(Z, V) */
		neoscrypt_blkxor_select(Z, V, j, k);
		/* blkmix(Z, Y) */
		neoscrypt_blkmix_chacha(Z);
	}

	/* Must be called before and after SSE2 Salsa */
	neoscrypt_salsa_tangle(X);

	/* X = SMix(X) */
	for (i = 0; i < 128; i++) {
		/* blkcpy(V, X) */
		neoscrypt_blkcpy(V + i * 16, X);
		/* blkmix(X, Y) */
		neoscrypt_blkmix_salsa(X);
	}
	for (i = 0; i < 128; i++) {
		/* integerify(X) mod N */
		j = X[12].m256i_u32[0] & 127;
		k = X[12].m256i_u32[4] & 127;
		/* blkxor(X, V) */
		neoscrypt_blkxor_select(X, V, j, k);
		/* blkmix(X, Y) */
		neoscrypt_blkmix_salsa(X);
	}

	neoscrypt_salsa_tangle(X);

	/* blkxor(X, Z) */
	neoscrypt_blkxor(X, Z);

	/* output = KDF(password, X) */
	neoscrypt_fastkdf_2(password, 80, (uchar *)X, 256, 32, output, 32);

}

#else

/* NeoScrypt */
static void neoscrypt_salsa_tangle(uint *X)
{
	register __m128i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
	for (int i = 0; i < 16; i += 4)
	{
		xmm0 = _mm_load_si128((__m128i*)X + i + 0);					// 0 1 2 3    0 5 A F
		xmm1 = _mm_load_si128((__m128i*)X + i + 1);					// 4 5 6 7    C 1 6 B
		xmm2 = _mm_load_si128((__m128i*)X + i + 2);					// 8 9 A B    8 D 2 7
		xmm3 = _mm_load_si128((__m128i*)X + i + 3);					// C D E F    4 9 E 3

																	// 0 1 2 3    0 5 A F
		xmm1 = _mm_shuffle_epi32(xmm1, _MM_SHUFFLE(0, 3, 2, 1));	// 5 6 7 4    1 6 B C
		xmm2 = _mm_shuffle_epi32(xmm2, _MM_SHUFFLE(1, 0, 3, 2));	// A B 8 9    2 7 8 D
		xmm3 = _mm_shuffle_epi32(xmm3, _MM_SHUFFLE(2, 1, 0, 3));	// F C D E    3 4 9 E

		xmm4 = _mm_unpacklo_epi32(xmm0, xmm1);						// 0 5 1 6    0 1 5 6
		xmm5 = _mm_unpackhi_epi32(xmm0, xmm1);						// 2 7 3 4    A B F C
		xmm6 = _mm_unpacklo_epi32(xmm2, xmm3);						// A F B C    2 3 7 4
		xmm7 = _mm_unpackhi_epi32(xmm2, xmm3);						// 8 D 9 E    8 9 D E

		xmm0 = _mm_unpacklo_epi64(xmm4, xmm6);						// 0 5 A F    0 1 2 3
		xmm1 = _mm_unpackhi_epi64(xmm4, xmm6);						// 1 6 B C    5 6 7 4
		xmm2 = _mm_unpacklo_epi64(xmm5, xmm7);						// 2 7 8 D    A B 8 9
		xmm3 = _mm_unpackhi_epi64(xmm5, xmm7);						// 3 4 9 E    F C D E

																	// 0 5 A F    0 1 2 3
		xmm1 = _mm_shuffle_epi32(xmm1, _MM_SHUFFLE(2, 1, 0, 3));	// C 1 6 B    4 5 6 7
		xmm2 = _mm_shuffle_epi32(xmm2, _MM_SHUFFLE(1, 0, 3, 2));	// 8 D 2 7    8 9 A B
		xmm3 = _mm_shuffle_epi32(xmm3, _MM_SHUFFLE(0, 3, 2, 1));	// 4 9 E 3    C D E F

		_mm_store_si128((__m128i*)X + i + 0, xmm0);
		_mm_store_si128((__m128i*)X + i + 1, xmm1);
		_mm_store_si128((__m128i*)X + i + 2, xmm2);
		_mm_store_si128((__m128i*)X + i + 3, xmm3);
	}
}

/* Salsa20, rounds must be a multiple of 2 */
static void neoscrypt_salsa(uint *X, uint rounds) {
	register __m128i xmm0, xmm1, xmm2, xmm3, xmm12, xmm13, xmm14, xmm15;
	register __m128i xmm4;

	xmm0 = _mm_load_si128((__m128i*)X + 0);							// 0 5 A F
	xmm1 = _mm_load_si128((__m128i*)X + 1);							// C 1 6 B
	xmm2 = _mm_load_si128((__m128i*)X + 2);							// 8 D 2 7
	xmm3 = _mm_load_si128((__m128i*)X + 3);							// 4 9 E 3
	xmm12 = xmm0;
	xmm13 = xmm1;
	xmm14 = xmm2;
	xmm15 = xmm3;

#define quarter(a, b, c, d, tmp) \
    tmp = _mm_add_epi32(a, d); b = _mm_xor_si128(b, _mm_slli_epi32(tmp, 7)); b = _mm_xor_si128(b, _mm_srli_epi32(tmp, 32 - 7)); \
    tmp = _mm_add_epi32(b, a); c = _mm_xor_si128(c, _mm_slli_epi32(tmp, 9)); c = _mm_xor_si128(c, _mm_srli_epi32(tmp, 32 - 9)); \
    tmp = _mm_add_epi32(c, b); d = _mm_xor_si128(d, _mm_slli_epi32(tmp, 13)); d = _mm_xor_si128(d, _mm_srli_epi32(tmp, 32 - 13)); \
    tmp = _mm_add_epi32(d, c); a = _mm_xor_si128(a, _mm_slli_epi32(tmp, 18)); a = _mm_xor_si128(a, _mm_srli_epi32(tmp, 32 - 18))

	for (; rounds; rounds -= 2) {
		quarter(xmm0, xmm3, xmm2, xmm1, xmm4);
		// 0 5 A F
		xmm1 = _mm_shuffle_epi32(xmm1, _MM_SHUFFLE(0, 3, 2, 1));	// 1 6 B C
		xmm2 = _mm_shuffle_epi32(xmm2, _MM_SHUFFLE(1, 0, 3, 2));	// 2 7 8 D
		xmm3 = _mm_shuffle_epi32(xmm3, _MM_SHUFFLE(2, 1, 0, 3));	// 3 4 9 E
		quarter(xmm0, xmm1, xmm2, xmm3, xmm4);
		// 0 5 A F
		xmm1 = _mm_shuffle_epi32(xmm1, _MM_SHUFFLE(2, 1, 0, 3));	// C 1 6 B
		xmm2 = _mm_shuffle_epi32(xmm2, _MM_SHUFFLE(1, 0, 3, 2));	// 8 D 2 7
		xmm3 = _mm_shuffle_epi32(xmm3, _MM_SHUFFLE(0, 3, 2, 1));	// 4 9 E 3
	}

	xmm0 = _mm_add_epi32(xmm0, xmm12);
	xmm1 = _mm_add_epi32(xmm1, xmm13);
	xmm2 = _mm_add_epi32(xmm2, xmm14);
	xmm3 = _mm_add_epi32(xmm3, xmm15);

	_mm_store_si128((__m128i*)X + 0, xmm0);
	_mm_store_si128((__m128i*)X + 1, xmm1);
	_mm_store_si128((__m128i*)X + 2, xmm2);
	_mm_store_si128((__m128i*)X + 3, xmm3);

#undef quarter
}

/* ChaCha20, rounds must be a multiple of 2 */
static void neoscrypt_chacha(uint *X, uint rounds) {
	register __m128i xmm0, xmm1, xmm2, xmm3, xmm12, xmm13, xmm14, xmm15;

	xmm0 = _mm_load_si128((__m128i*)X + 0);							// 0 1 2 3
	xmm1 = _mm_load_si128((__m128i*)X + 1);							// 4 5 6 7
	xmm2 = _mm_load_si128((__m128i*)X + 2);							// 8 9 A B
	xmm3 = _mm_load_si128((__m128i*)X + 3);							// C D E F
	xmm12 = xmm0;
	xmm13 = xmm1;
	xmm14 = xmm2;
	xmm15 = xmm3;

#define quarter(a,b,c,d) \
    a = _mm_add_epi32(a, b); d = _mm_xor_si128(d, a); d = _mm_shufflehi_epi16(_mm_shufflelo_epi16(d, 0xB1), 0xB1); \
    c = _mm_add_epi32(c, d); b = _mm_xor_si128(b, c); b = _mm_xor_si128(_mm_slli_epi32(b, 12), _mm_srli_epi32(b, 32 - 12)); \
    a = _mm_add_epi32(a, b); d = _mm_xor_si128(d, a); d = _mm_xor_si128(_mm_slli_epi32(d, 8), _mm_srli_epi32(d, 32 - 8)); \
    c = _mm_add_epi32(c, d); b = _mm_xor_si128(b, c); b = _mm_xor_si128(_mm_slli_epi32(b, 7), _mm_srli_epi32(b, 32 - 7)); \

	for (; rounds; rounds -= 2) {
		quarter(xmm0, xmm1, xmm2, xmm3);
		// 0 1 2 3
		xmm1 = _mm_shuffle_epi32(xmm1, _MM_SHUFFLE(0, 3, 2, 1));	// 5 6 7 4
		xmm2 = _mm_shuffle_epi32(xmm2, _MM_SHUFFLE(1, 0, 3, 2));	// A B 8 9
		xmm3 = _mm_shuffle_epi32(xmm3, _MM_SHUFFLE(2, 1, 0, 3));	// F C D E

		quarter(xmm0, xmm1, xmm2, xmm3);
		// 0 1 2 3
		xmm1 = _mm_shuffle_epi32(xmm1, _MM_SHUFFLE(2, 1, 0, 3));	// 4 5 6 7
		xmm2 = _mm_shuffle_epi32(xmm2, _MM_SHUFFLE(1, 0, 3, 2));	// 8 9 A B
		xmm3 = _mm_shuffle_epi32(xmm3, _MM_SHUFFLE(0, 3, 2, 1));	// C D E F
	}

	xmm0 = _mm_add_epi32(xmm0, xmm12);
	xmm1 = _mm_add_epi32(xmm1, xmm13);
	xmm2 = _mm_add_epi32(xmm2, xmm14);
	xmm3 = _mm_add_epi32(xmm3, xmm15);

	_mm_store_si128((__m128i*)X + 0, xmm0);
	_mm_store_si128((__m128i*)X + 1, xmm1);
	_mm_store_si128((__m128i*)X + 2, xmm2);
	_mm_store_si128((__m128i*)X + 3, xmm3);

#undef quarter
}

/* Fast 32-bit / 64-bit memcpy();
* len must be a multiple of 32 bytes */
static void neoscrypt_blkcpy(__m128i *dst, const __m128i *src) {
	_mm_store_si128(dst + 0, _mm_load_si128(src + 0));
	_mm_store_si128(dst + 1, _mm_load_si128(src + 1));
	_mm_store_si128(dst + 2, _mm_load_si128(src + 2));
	_mm_store_si128(dst + 3, _mm_load_si128(src + 3));
	_mm_store_si128(dst + 4, _mm_load_si128(src + 4));
	_mm_store_si128(dst + 5, _mm_load_si128(src + 5));
	_mm_store_si128(dst + 6, _mm_load_si128(src + 6));
	_mm_store_si128(dst + 7, _mm_load_si128(src + 7));
	_mm_store_si128(dst + 8, _mm_load_si128(src + 8));
	_mm_store_si128(dst + 9, _mm_load_si128(src + 9));
	_mm_store_si128(dst + 10, _mm_load_si128(src + 10));
	_mm_store_si128(dst + 11, _mm_load_si128(src + 11));
	_mm_store_si128(dst + 12, _mm_load_si128(src + 12));
	_mm_store_si128(dst + 13, _mm_load_si128(src + 13));
	_mm_store_si128(dst + 14, _mm_load_si128(src + 14));
	_mm_store_si128(dst + 15, _mm_load_si128(src + 15));
}

/* Fast 32-bit / 64-bit block XOR engine;
* len must be a multiple of 32 bytes */
static void neoscrypt_blkxor(__m128i *dst, const __m128i *src) {
	_mm_store_si128(dst + 0, _mm_xor_si128(_mm_load_si128(dst + 0), _mm_load_si128(src + 0)));
	_mm_store_si128(dst + 1, _mm_xor_si128(_mm_load_si128(dst + 1), _mm_load_si128(src + 1)));
	_mm_store_si128(dst + 2, _mm_xor_si128(_mm_load_si128(dst + 2), _mm_load_si128(src + 2)));
	_mm_store_si128(dst + 3, _mm_xor_si128(_mm_load_si128(dst + 3), _mm_load_si128(src + 3)));
	_mm_store_si128(dst + 4, _mm_xor_si128(_mm_load_si128(dst + 4), _mm_load_si128(src + 4)));
	_mm_store_si128(dst + 5, _mm_xor_si128(_mm_load_si128(dst + 5), _mm_load_si128(src + 5)));
	_mm_store_si128(dst + 6, _mm_xor_si128(_mm_load_si128(dst + 6), _mm_load_si128(src + 6)));
	_mm_store_si128(dst + 7, _mm_xor_si128(_mm_load_si128(dst + 7), _mm_load_si128(src + 7)));
	_mm_store_si128(dst + 8, _mm_xor_si128(_mm_load_si128(dst + 8), _mm_load_si128(src + 8)));
	_mm_store_si128(dst + 9, _mm_xor_si128(_mm_load_si128(dst + 9), _mm_load_si128(src + 9)));
	_mm_store_si128(dst + 10, _mm_xor_si128(_mm_load_si128(dst + 10), _mm_load_si128(src + 10)));
	_mm_store_si128(dst + 11, _mm_xor_si128(_mm_load_si128(dst + 11), _mm_load_si128(src + 11)));
	_mm_store_si128(dst + 12, _mm_xor_si128(_mm_load_si128(dst + 12), _mm_load_si128(src + 12)));
	_mm_store_si128(dst + 13, _mm_xor_si128(_mm_load_si128(dst + 13), _mm_load_si128(src + 13)));
	_mm_store_si128(dst + 14, _mm_xor_si128(_mm_load_si128(dst + 14), _mm_load_si128(src + 14)));
	_mm_store_si128(dst + 15, _mm_xor_si128(_mm_load_si128(dst + 15), _mm_load_si128(src + 15)));
}

/* BLAKE2s */

#define G(a,b,c,d,m,r0,r1,r2,r3,r4,r5,r6,r7) \
  do { \
    a = _mm_add_epi32(a, b); \
	a = _mm_add_epi32(a, _mm_setr_epi32((m)[r0],(m)[r2],(m)[r4],(m)[r6])); \
	d = _mm_xor_si128(d, a); \
	d = _mm_xor_si128(_mm_srli_epi32(d, 16), _mm_slli_epi32(d, 32 - 16)); \
    c = _mm_add_epi32(c, d); \
	b = _mm_xor_si128(b, c); \
	b = _mm_xor_si128(_mm_srli_epi32(b, 12), _mm_slli_epi32(b, 32 - 12)); \
    a = _mm_add_epi32(a, b); \
	a = _mm_add_epi32(a, _mm_setr_epi32((m)[r1],(m)[r3],(m)[r5],(m)[r7])); \
	d = _mm_xor_si128(d, a); \
	d = _mm_xor_si128(_mm_srli_epi32(d, 8), _mm_slli_epi32(d, 32 - 8)); \
    c = _mm_add_epi32(c, d); \
	b = _mm_xor_si128(b, c); \
	b = _mm_xor_si128(_mm_srli_epi32(b, 7), _mm_slli_epi32(b, 32 - 7)); \
  } while(0)
#define ROUND(m,r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15) \
  do { \
    G(xmm0, xmm1, xmm2, xmm3,m,  r0,r1,r2,r3,r4,r5,r6,r7); \
    xmm1 = _mm_shuffle_epi32(xmm1, _MM_SHUFFLE(0,3,2,1)); \
	xmm2 = _mm_shuffle_epi32(xmm2, _MM_SHUFFLE(1,0,3,2)); \
	xmm3 = _mm_shuffle_epi32(xmm3, _MM_SHUFFLE(2,1,0,3)); \
    G(xmm0, xmm1, xmm2, xmm3,m,r8,r9,r10,r11,r12,r13,r14,r15); \
	xmm1 = _mm_shuffle_epi32(xmm1, _MM_SHUFFLE(2,1,0,3)); \
	xmm2 = _mm_shuffle_epi32(xmm2, _MM_SHUFFLE(1,0,3,2)); \
	xmm3 = _mm_shuffle_epi32(xmm3, _MM_SHUFFLE(0,3,2,1)); \
  } while(0)


/* FastKDF, a fast buffered key derivation function:
* FASTKDF_BUFFER_SIZE must be a power of 2;
* password_len, salt_len and output_len should not exceed FASTKDF_BUFFER_SIZE;
* prf_output_size must be <= prf_key_size; */
static void neoscrypt_fastkdf_1(const uchar *password, uint password_len, const uchar *salt, uint salt_len,
	uint N, uchar *output, uint output_len) {

	uint bufptr, i, j;
	__m128i *prf_input, *prf_key;
	__m128i A[20], B[18], prf_output[2];
	__m128i m[4];

	/* Initialise the password buffer */
	/* Initialise the salt buffer */
	A[0] = A[5] = A[10] = A[15] = A[16] = B[0] = B[5] = B[10] = B[15] = B[16] = _mm_loadu_si128((__m128i*)password + 0);
	A[1] = A[6] = A[11] = A[17] = B[1] = B[6] = B[11] = B[17] = _mm_loadu_si128((__m128i*)password + 1);
	A[2] = A[7] = A[12] = A[18] = B[2] = B[7] = B[12] = _mm_loadu_si128((__m128i*)password + 2);
	A[3] = A[8] = A[13] = A[19] = B[3] = B[8] = B[13] = _mm_loadu_si128((__m128i*)password + 3);
	A[4] = A[9] = A[14] = B[4] = B[9] = B[14] = _mm_loadu_si128((__m128i*)password + 4);

	/* The primary iteration */
	for (i = 0, bufptr = 0; i < N; i++) {

		/* Map the PRF input buffer */
		prf_input = (__m128i*)((uchar*)A + bufptr);

		/* Map the PRF key buffer */
		prf_key = (__m128i*)((uchar*)B + bufptr);

		/* PRF */
		register __m128i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5;
		xmm0 = xmm4 = _mm_setr_epi32(0x6A09E667 ^ 0x01012020, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A);
		xmm1 = xmm5 = _mm_setr_epi32(0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
		xmm2 = _mm_setr_epi32(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A);
		xmm3 = _mm_setr_epi32(0x510E527F ^ 64, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
		_mm_store_si128(m + 0, _mm_loadu_si128(prf_key + 0));
		_mm_store_si128(m + 1, _mm_loadu_si128(prf_key + 1));
		_mm_store_si128(m + 2, _mm_setzero_si128());
		_mm_store_si128(m + 3, _mm_setzero_si128());
		ROUND((uint*)m, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
		ROUND((uint*)m, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
		ROUND((uint*)m, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
		ROUND((uint*)m, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
		ROUND((uint*)m, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
		ROUND((uint*)m, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
		ROUND((uint*)m, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
		ROUND((uint*)m, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
		ROUND((uint*)m, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
		ROUND((uint*)m, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);

		xmm0 = xmm4 = _mm_xor_si128(_mm_xor_si128(xmm0, xmm2), xmm4);
		xmm1 = xmm5 = _mm_xor_si128(_mm_xor_si128(xmm1, xmm3), xmm5);
		xmm2 = _mm_setr_epi32(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A);
		xmm3 = _mm_setr_epi32(0x510E527F ^ 128, 0x9B05688C, 0x1F83D9AB ^ 0xFFFFFFFF, 0x5BE0CD19);
		ROUND((uint*)prf_input, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
		ROUND((uint*)prf_input, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
		ROUND((uint*)prf_input, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
		ROUND((uint*)prf_input, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
		ROUND((uint*)prf_input, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
		ROUND((uint*)prf_input, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
		ROUND((uint*)prf_input, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
		ROUND((uint*)prf_input, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
		ROUND((uint*)prf_input, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
		ROUND((uint*)prf_input, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);

		xmm0 = _mm_xor_si128(_mm_xor_si128(xmm0, xmm2), xmm4);
		xmm1 = _mm_xor_si128(_mm_xor_si128(xmm1, xmm3), xmm5);

		/* Calculate the next buffer pointer */
		xmm2 = _mm_add_epi8(xmm0, xmm1);
		xmm2 = _mm_add_epi8(_mm_shuffle_epi32(xmm2, _MM_SHUFFLE(2, 3, 0, 1)), xmm2);
		xmm2 = _mm_add_epi8(_mm_shuffle_epi32(xmm2, _MM_SHUFFLE(1, 0, 3, 2)), xmm2);
		uint tmp = (uint)_mm_cvtsi128_si32(xmm2);
		tmp = ((tmp >> 8) & 0x00FF00FF) + (tmp & 0x00FF00FF);
		tmp = ((tmp >> 16) & 0x0000FFFF) + (tmp & 0x0000FFFF);
		bufptr = tmp & 0xFF;

		/* Map the PRF key buffer */
		prf_key = (__m128i*)((uchar*)B + bufptr);

		/* Modify the salt buffer */
		_mm_storeu_si128(prf_key + 0, _mm_xor_si128(_mm_loadu_si128(prf_key + 0), xmm0));
		_mm_storeu_si128(prf_key + 1, _mm_xor_si128(_mm_loadu_si128(prf_key + 1), xmm1));

		/* Head modified, tail updated */
		if (bufptr < 32)
		{
			_mm_store_si128(B + 17, _mm_load_si128(B + 1));
			if (bufptr < 16)
				_mm_store_si128(B + 16, _mm_load_si128(B + 0));
		}

		/* Tail modified, head updated */
		if ((256 - bufptr) < 32)
		{
			_mm_store_si128(B + 0, _mm_load_si128(B + 16));
			if ((256 - bufptr) < 16)
				_mm_store_si128(B + 1, _mm_load_si128(B + 17));
		}
	}

	/* Modify and copy into the output buffer */
	for (i = 0; i < (output_len >> 4); i++)
	{
		_mm_store_si128((__m128i*)output + i, _mm_xor_si128(_mm_load_si128(A + i), _mm_loadu_si128(prf_key)));
		bufptr = (bufptr + 16) & 255;
		prf_key = (__m128i*)((uchar*)B + bufptr);
	}
}

/* FastKDF, a fast buffered key derivation function:
* FASTKDF_BUFFER_SIZE must be a power of 2;
* password_len, salt_len and output_len should not exceed FASTKDF_BUFFER_SIZE;
* prf_output_size must be <= prf_key_size; */
static void neoscrypt_fastkdf_2(const uchar *password, uint password_len, const uchar *salt, uint salt_len,
	uint N, uchar *output, uint output_len) {

	uint bufptr, i, j;
	__m128i *prf_input, *prf_key;
	__m128i A[20], B[18], prf_output[2];
	__m128i m[4];

	/* Initialise the password buffer */
	A[0] = A[5] = A[10] = A[15] = A[16] = _mm_loadu_si128((__m128i*)password + 0);
	A[1] = A[6] = A[11] = A[17] = _mm_loadu_si128((__m128i*)password + 1);
	A[2] = A[7] = A[12] = A[18] = _mm_loadu_si128((__m128i*)password + 2);
	A[3] = A[8] = A[13] = A[19] = _mm_loadu_si128((__m128i*)password + 3);
	A[4] = A[9] = A[14] = _mm_loadu_si128((__m128i*)password + 4);

	/* Initialise the salt buffer */
	B[0] = B[16] = _mm_load_si128((__m128i*)salt + 0);
	B[1] = B[17] = _mm_load_si128((__m128i*)salt + 1);
	B[2] = _mm_load_si128((__m128i*)salt + 2);
	B[3] = _mm_load_si128((__m128i*)salt + 3);
	B[4] = _mm_load_si128((__m128i*)salt + 4);
	B[5] = _mm_load_si128((__m128i*)salt + 5);
	B[6] = _mm_load_si128((__m128i*)salt + 6);
	B[7] = _mm_load_si128((__m128i*)salt + 7);
	B[8] = _mm_load_si128((__m128i*)salt + 8);
	B[9] = _mm_load_si128((__m128i*)salt + 9);
	B[10] = _mm_load_si128((__m128i*)salt + 10);
	B[11] = _mm_load_si128((__m128i*)salt + 11);
	B[12] = _mm_load_si128((__m128i*)salt + 12);
	B[13] = _mm_load_si128((__m128i*)salt + 13);
	B[14] = _mm_load_si128((__m128i*)salt + 14);
	B[15] = _mm_load_si128((__m128i*)salt + 15);

	/* The primary iteration */
	for (i = 0, bufptr = 0; i < N; i++) {

		/* Map the PRF input buffer */
		prf_input = (__m128i*)((uchar*)A + bufptr);

		/* Map the PRF key buffer */
		prf_key = (__m128i*)((uchar*)B + bufptr);

		/* PRF */
		register __m128i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5;
		xmm0 = xmm4 = _mm_setr_epi32(0x6A09E667 ^ 0x01012020, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A);
		xmm1 = xmm5 = _mm_setr_epi32(0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
		xmm2 = _mm_setr_epi32(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A);
		xmm3 = _mm_setr_epi32(0x510E527F ^ 64, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
		_mm_store_si128(m + 0, _mm_loadu_si128(prf_key + 0));
		_mm_store_si128(m + 1, _mm_loadu_si128(prf_key + 1));
		_mm_store_si128(m + 2, _mm_setzero_si128());
		_mm_store_si128(m + 3, _mm_setzero_si128());
		ROUND((uint*)m, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
		ROUND((uint*)m, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
		ROUND((uint*)m, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
		ROUND((uint*)m, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
		ROUND((uint*)m, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
		ROUND((uint*)m, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
		ROUND((uint*)m, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
		ROUND((uint*)m, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
		ROUND((uint*)m, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
		ROUND((uint*)m, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);

		xmm0 = xmm4 = _mm_xor_si128(_mm_xor_si128(xmm0, xmm2), xmm4);
		xmm1 = xmm5 = _mm_xor_si128(_mm_xor_si128(xmm1, xmm3), xmm5);
		xmm2 = _mm_setr_epi32(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A);
		xmm3 = _mm_setr_epi32(0x510E527F ^ 128, 0x9B05688C, 0x1F83D9AB ^ 0xFFFFFFFF, 0x5BE0CD19);
		ROUND((uint*)prf_input, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
		ROUND((uint*)prf_input, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
		ROUND((uint*)prf_input, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
		ROUND((uint*)prf_input, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
		ROUND((uint*)prf_input, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
		ROUND((uint*)prf_input, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
		ROUND((uint*)prf_input, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
		ROUND((uint*)prf_input, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
		ROUND((uint*)prf_input, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
		ROUND((uint*)prf_input, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);

		xmm0 = _mm_xor_si128(_mm_xor_si128(xmm0, xmm2), xmm4);
		xmm1 = _mm_xor_si128(_mm_xor_si128(xmm1, xmm3), xmm5);

		/* Calculate the next buffer pointer */
		xmm2 = _mm_add_epi8(xmm0, xmm1);
		xmm2 = _mm_add_epi8(_mm_shuffle_epi32(xmm2, _MM_SHUFFLE(2, 3, 0, 1)), xmm2);
		xmm2 = _mm_add_epi8(_mm_shuffle_epi32(xmm2, _MM_SHUFFLE(1, 0, 3, 2)), xmm2);
		uint tmp = (uint)_mm_cvtsi128_si32(xmm2);
		tmp = ((tmp >> 8) & 0x00FF00FF) + (tmp & 0x00FF00FF);
		tmp = ((tmp >> 16) & 0x0000FFFF) + (tmp & 0x0000FFFF);
		bufptr = tmp & 0xFF;

		/* Map the PRF key buffer */
		prf_key = (__m128i*)((uchar*)B + bufptr);

		/* Modify the salt buffer */
		_mm_storeu_si128(prf_key + 0, _mm_xor_si128(_mm_loadu_si128(prf_key + 0), xmm0));
		_mm_storeu_si128(prf_key + 1, _mm_xor_si128(_mm_loadu_si128(prf_key + 1), xmm1));

		/* Head modified, tail updated */
		if (bufptr < 32)
		{
			_mm_store_si128(B + 17, _mm_load_si128(B + 1));
			if (bufptr < 16)
				_mm_store_si128(B + 16, _mm_load_si128(B + 0));
		}

		/* Tail modified, head updated */
		if ((256 - bufptr) < 32)
		{
			_mm_store_si128(B + 0, _mm_load_si128(B + 16));
			if ((256 - bufptr) < 16)
				_mm_store_si128(B + 1, _mm_load_si128(B + 17));
		}
	}

	/* Modify and copy into the output buffer */
	for (i = 0; i < (output_len >> 4); i++)
	{
		_mm_store_si128((__m128i*)output + i, _mm_xor_si128(_mm_load_si128(A + i), _mm_loadu_si128(prf_key)));
		bufptr = (bufptr + 16) & 255;
		prf_key = (__m128i*)((uchar*)B + bufptr);
	}
}
#undef G
#undef ROUND

/* Configurable optimised block mixer */
static void neoscrypt_blkmix_chacha(__m128i *X) {
	/* NeoScrypt flow:                   Scrypt flow:
	Xa ^= Xd;  M(Xa'); Ya = Xa";      Xa ^= Xb;  M(Xa'); Ya = Xa";
	Xb ^= Xa"; M(Xb'); Yb = Xb";      Xb ^= Xa"; M(Xb'); Yb = Xb";
	Xc ^= Xb"; M(Xc'); Yc = Xc";      Xa" = Ya;
	Xd ^= Xc"; M(Xd'); Yd = Xd";      Xb" = Yb;
	Xa" = Ya; Xb" = Yc;
	Xc" = Yb; Xd" = Yd; */

	__m128i temp[4];
	_mm_store_si128(X + 0, _mm_xor_si128(_mm_load_si128(X + 0), _mm_load_si128(X + 12)));
	_mm_store_si128(X + 1, _mm_xor_si128(_mm_load_si128(X + 1), _mm_load_si128(X + 13)));
	_mm_store_si128(X + 2, _mm_xor_si128(_mm_load_si128(X + 2), _mm_load_si128(X + 14)));
	_mm_store_si128(X + 3, _mm_xor_si128(_mm_load_si128(X + 3), _mm_load_si128(X + 15)));
	neoscrypt_chacha(&X[0], 20);
	_mm_store_si128(temp + 0, _mm_xor_si128(_mm_load_si128(X + 4), _mm_load_si128(X + 0)));
	_mm_store_si128(temp + 1, _mm_xor_si128(_mm_load_si128(X + 5), _mm_load_si128(X + 1)));
	_mm_store_si128(temp + 2, _mm_xor_si128(_mm_load_si128(X + 6), _mm_load_si128(X + 2)));
	_mm_store_si128(temp + 3, _mm_xor_si128(_mm_load_si128(X + 7), _mm_load_si128(X + 3)));
	neoscrypt_chacha(temp, 20);
	_mm_store_si128(X + 4, _mm_xor_si128(_mm_load_si128(X + 8), _mm_load_si128(temp + 0)));
	_mm_store_si128(X + 5, _mm_xor_si128(_mm_load_si128(X + 9), _mm_load_si128(temp + 1)));
	_mm_store_si128(X + 6, _mm_xor_si128(_mm_load_si128(X + 10), _mm_load_si128(temp + 2)));
	_mm_store_si128(X + 7, _mm_xor_si128(_mm_load_si128(X + 11), _mm_load_si128(temp + 3)));
	neoscrypt_chacha(&X[4], 20);
	_mm_store_si128(X + 12, _mm_xor_si128(_mm_load_si128(X + 12), _mm_load_si128(X + 4)));
	_mm_store_si128(X + 13, _mm_xor_si128(_mm_load_si128(X + 13), _mm_load_si128(X + 5)));
	_mm_store_si128(X + 14, _mm_xor_si128(_mm_load_si128(X + 14), _mm_load_si128(X + 6)));
	_mm_store_si128(X + 15, _mm_xor_si128(_mm_load_si128(X + 15), _mm_load_si128(X + 7)));
	neoscrypt_chacha(&X[12], 20);
	_mm_store_si128(X + 8, _mm_load_si128(temp + 0));
	_mm_store_si128(X + 9, _mm_load_si128(temp + 1));
	_mm_store_si128(X + 10, _mm_load_si128(temp + 2));
	_mm_store_si128(X + 11, _mm_load_si128(temp + 3));
}

/* Configurable optimised block mixer */
static void neoscrypt_blkmix_salsa(__m128i *X) {
	/* NeoScrypt flow:                   Scrypt flow:
	Xa ^= Xd;  M(Xa'); Ya = Xa";      Xa ^= Xb;  M(Xa'); Ya = Xa";
	Xb ^= Xa"; M(Xb'); Yb = Xb";      Xb ^= Xa"; M(Xb'); Yb = Xb";
	Xc ^= Xb"; M(Xc'); Yc = Xc";      Xa" = Ya;
	Xd ^= Xc"; M(Xd'); Yd = Xd";      Xb" = Yb;
	Xa" = Ya; Xb" = Yc;
	Xc" = Yb; Xd" = Yd; */

	__m128i temp[4];
	_mm_store_si128(X + 0, _mm_xor_si128(_mm_load_si128(X + 0), _mm_load_si128(X + 12)));
	_mm_store_si128(X + 1, _mm_xor_si128(_mm_load_si128(X + 1), _mm_load_si128(X + 13)));
	_mm_store_si128(X + 2, _mm_xor_si128(_mm_load_si128(X + 2), _mm_load_si128(X + 14)));
	_mm_store_si128(X + 3, _mm_xor_si128(_mm_load_si128(X + 3), _mm_load_si128(X + 15)));
	neoscrypt_salsa(&X[0], 20);
	_mm_store_si128(temp + 0, _mm_xor_si128(_mm_load_si128(X + 4), _mm_load_si128(X + 0)));
	_mm_store_si128(temp + 1, _mm_xor_si128(_mm_load_si128(X + 5), _mm_load_si128(X + 1)));
	_mm_store_si128(temp + 2, _mm_xor_si128(_mm_load_si128(X + 6), _mm_load_si128(X + 2)));
	_mm_store_si128(temp + 3, _mm_xor_si128(_mm_load_si128(X + 7), _mm_load_si128(X + 3)));
	neoscrypt_salsa(temp, 20);
	_mm_store_si128(X + 4, _mm_xor_si128(_mm_load_si128(X + 8), _mm_load_si128(temp + 0)));
	_mm_store_si128(X + 5, _mm_xor_si128(_mm_load_si128(X + 9), _mm_load_si128(temp + 1)));
	_mm_store_si128(X + 6, _mm_xor_si128(_mm_load_si128(X + 10), _mm_load_si128(temp + 2)));
	_mm_store_si128(X + 7, _mm_xor_si128(_mm_load_si128(X + 11), _mm_load_si128(temp + 3)));
	neoscrypt_salsa(&X[4], 20);
	_mm_store_si128(X + 12, _mm_xor_si128(_mm_load_si128(X + 12), _mm_load_si128(X + 4)));
	_mm_store_si128(X + 13, _mm_xor_si128(_mm_load_si128(X + 13), _mm_load_si128(X + 5)));
	_mm_store_si128(X + 14, _mm_xor_si128(_mm_load_si128(X + 14), _mm_load_si128(X + 6)));
	_mm_store_si128(X + 15, _mm_xor_si128(_mm_load_si128(X + 15), _mm_load_si128(X + 7)));
	neoscrypt_salsa(&X[12], 20);
	_mm_store_si128(X + 8, _mm_load_si128(temp + 0));
	_mm_store_si128(X + 9, _mm_load_si128(temp + 1));
	_mm_store_si128(X + 10, _mm_load_si128(temp + 2));
	_mm_store_si128(X + 11, _mm_load_si128(temp + 3));
}

/* NeoScrypt core engine:
* p = 1, salt = password;
* Basic customisation (required):
*   profile bit 0:
*     0 = NeoScrypt(128, 2, 1) with Salsa20/20 and ChaCha20/20;
*     1 = Scrypt(1024, 1, 1) with Salsa20/8;
*   profile bits 4 to 1:
*     0000 = FastKDF-BLAKE2s;
*     0001 = PBKDF2-HMAC-SHA256;
* Extended customisation (optional):
*   profile bit 31:
*     0 = extended customisation absent;
*     1 = extended customisation present;
*   profile bits 7 to 5 (rfactor):
*     000 = r of 1;
*     001 = r of 2;
*     010 = r of 4;
*     ...
*     111 = r of 128;
*   profile bits 12 to 8 (Nfactor):
*     00000 = N of 2;
*     00001 = N of 4;
*     00010 = N of 8;
*     .....
*     00110 = N of 128;
*     .....
*     01001 = N of 1024;
*     .....
*     11110 = N of 2147483648;
*   profile bits 30 to 13 are reserved */
void neoscrypt(uchar *output, const uchar *password, uint32_t profile)
{
	uint i, j, k;
	__m128i X[32];
	__m128i Z[32];
	__m128i V[128 * 32];

	neoscrypt_fastkdf_1(password, 80, password, 80, 32, (uchar *)(X + 0), 256);
	neoscrypt_fastkdf_1(password, 80, password, 80, 32, (uchar *)(X + 16), 256);

	/* Process ChaCha 1st, Salsa 2nd and XOR them into FastKDF; otherwise Salsa only */
	/* blkcpy(Z, X) */
	neoscrypt_blkcpy(Z + 0, X + 0);
	neoscrypt_blkcpy(Z + 16, X + 16);

	/* Z = SMix(Z) */
	for (i = 0; i < 128; i++) {
		/* blkcpy(V, Z) */
		neoscrypt_blkcpy(V + i * 32 + 0, Z + 0);
		neoscrypt_blkcpy(V + i * 32 + 16, Z + 16);
		/* blkmix(Z, Y) */
		neoscrypt_blkmix_chacha(Z + 0);
		neoscrypt_blkmix_chacha(Z + 16);
	}
	for (i = 0; i < 128; i++) {
		/* integerify(Z) mod N */
		j = Z[12].m128i_u32[0] & 127;
		k = Z[28].m128i_u32[0] & 127;
		/* blkxor(Z, V) */
		neoscrypt_blkxor(Z + 0, V + 32 * j + 0);
		neoscrypt_blkxor(Z + 16, V + 32 * k + 16);
		/* blkmix(Z, Y) */
		neoscrypt_blkmix_chacha(Z + 0);
		neoscrypt_blkmix_chacha(Z + 16);
	}

	/* Must be called before and after SSE2 Salsa */
	neoscrypt_salsa_tangle(X + 0);
	neoscrypt_salsa_tangle(X + 16);

	/* X = SMix(X) */
	for (i = 0; i < 128; i++) {
		/* blkcpy(V, X) */
		neoscrypt_blkcpy(V + i * 32 + 0, X + 0);
		neoscrypt_blkcpy(V + i * 32 + 16, X + 16);
		/* blkmix(X, Y) */
		neoscrypt_blkmix_salsa(X + 0);
		neoscrypt_blkmix_salsa(X + 16);
	}
	for (i = 0; i < 128; i++) {
		/* integerify(X) mod N */
		j = X[12].m128i_u32[0] & 127;
		k = X[28].m128i_u32[0] & 127;
		/* blkxor(X, V) */
		neoscrypt_blkxor(X + 0, V + 32 * j + 0);
		neoscrypt_blkxor(X + 16, V + 32 * k + 16);
		/* blkmix(X, Y) */
		neoscrypt_blkmix_salsa(X + 0);
		neoscrypt_blkmix_salsa(X + 16);
	}

	neoscrypt_salsa_tangle(X + 0);
	neoscrypt_salsa_tangle(X + 16);

	/* blkxor(X, Z) */
	neoscrypt_blkxor(X + 0, Z + 0);
	neoscrypt_blkxor(X + 16, Z + 16);

	/* output = KDF(password, X) */
	neoscrypt_fastkdf_2(password, 80, (uchar *)(X + 0), 256, 32, output + 0, 32);
	neoscrypt_fastkdf_2(password, 80, (uchar *)(X + 16), 256, 32, output + 32, 32);
}

#endif
static bool fulltest_le(const uint *hash, const uint *target)
{
	bool rc = false;

	for (int i = 7; i >= 0; i--) {
		if (hash[i] > target[i]) {
			rc = false;
			break;
		}
		if (hash[i] < target[i]) {
			rc = true;
			break;
		}
	}

	if (opt_debug) {
		uchar hash_str[65], target_str[65];

		bin2hex(hash_str, (uint8_t *)hash, 32);
		bin2hex(target_str, (uint8_t *)target, 32);

		applog(LOG_DEBUG, "DEBUG (little endian): %s\nHash:   %sx0\nTarget: %sx0",
			rc ? "hash <= target" : "hash > target (false positive)",
			hash_str, target_str);
	}

	return(rc);
}

int scanhash_neoscrypt(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
	uint32_t profile)
{
	uint32_t _ALIGN(128) hash[16];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	while (pdata[19] < max_nonce && !work_restart[thr_id].restart)
	{
		neoscrypt((uint8_t *)hash, (uint8_t *)pdata, profile);

		/* Quick hash check */
		if (hash[7] <= Htarg && fulltest_le(hash + 0, ptarget)) {
			work_set_target_ratio(work, hash + 0);
			*hashes_done = pdata[19] - first_nonce + 1;
			return 1;
		}
		pdata[19]++;

		if (hash[15] <= Htarg && fulltest_le(hash + 8, ptarget)) {
			work_set_target_ratio(work, hash + 8);
			*hashes_done = pdata[19] - first_nonce + 1;
			return 1;
		}
		pdata[19]++;
	}

	*hashes_done = pdata[19] - first_nonce;
	return 0;
}
