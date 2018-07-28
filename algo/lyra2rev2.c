#include <memory.h>
#ifndef SSE
#include <immintrin.h>
#else
#ifdef SSE3
#include <tmmintrin.h>
#else
#include <emmintrin.h> //SSE2
#endif
#endif

#include "sha3/sph_blake.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_bmw.h"

#include "lyra2/Lyra2.h"

#include "miner.h"

#ifndef SSE

void lyra2rev2_hash_AVX(void *state, const void *input, __m256i *wholeMatrix, int32_t *flag, __m256i *wholeMatrix2)
{
	__m256i hashA[8], hashB[8];

	if (flag) {
		sph_blake256_80_init(wholeMatrix2, input, 80);
		flag = 0;
	}

	sph_blake256_80_AVX(hashA, input, 80, wholeMatrix2);

	hashB[0] = _mm256_unpacklo_epi32(hashA[0], hashA[1]); // 00 01 08 09 20 21 28 29
	hashB[1] = _mm256_unpacklo_epi32(hashA[2], hashA[3]); // 02 03 0A 0B 22 23 2A 2B
	hashB[2] = _mm256_unpacklo_epi32(hashA[4], hashA[5]); // 04 05 0C 0D 24 25 2C 2D
	hashB[3] = _mm256_unpacklo_epi32(hashA[6], hashA[7]); // 06 07 0E 0F 26 27 2E 2F
	hashB[4] = _mm256_unpackhi_epi32(hashA[0], hashA[1]); // 10 11 18 19 30 31 38 39
	hashB[5] = _mm256_unpackhi_epi32(hashA[2], hashA[3]); // 12 13 1A 1B 32 33 3A 3B
	hashB[6] = _mm256_unpackhi_epi32(hashA[4], hashA[5]); // 14 15 1C 1D 34 35 3C 3D
	hashB[7] = _mm256_unpackhi_epi32(hashA[6], hashA[7]); // 16 17 1E 1F 36 37 3E 3F

	sph_keccak256_32_AVX(hashA + 0, hashB + 0, 32);
	sph_keccak256_32_AVX(hashA + 4, hashB + 4, 32);

	hashB[0] = _mm256_unpacklo_epi64(hashA[0], hashA[1]); // 00 01 02 03 20 21 22 23
	hashB[1] = _mm256_unpacklo_epi64(hashA[2], hashA[3]); // 04 05 06 07 24 25 26 27
	hashB[2] = _mm256_unpacklo_epi64(hashA[4], hashA[5]); // 10 11 12 13 30 31 32 33
	hashB[3] = _mm256_unpacklo_epi64(hashA[6], hashA[7]); // 14 15 16 17 34 35 36 37
	hashB[4] = _mm256_unpackhi_epi64(hashA[0], hashA[1]); // 08 09 0A 0B 28 29 2A 2B
	hashB[5] = _mm256_unpackhi_epi64(hashA[2], hashA[3]); // 0C 0D 0E 0F 2C 2D 2E 2F
	hashB[6] = _mm256_unpackhi_epi64(hashA[4], hashA[5]); // 18 19 1A 1B 38 39 3A 3B
	hashB[7] = _mm256_unpackhi_epi64(hashA[6], hashA[7]); // 1C 1D 1E 1F 3C 3D 3E 3F

	hashA[0] = _mm256_permute2x128_si256(hashB[0], hashB[1], 0x20); // 00 01 02 03 04 05 06 07
	hashA[1] = _mm256_permute2x128_si256(hashB[4], hashB[5], 0x20); // 08 09 0A 0B 0C 0D 0E 0F
	hashA[2] = _mm256_permute2x128_si256(hashB[2], hashB[3], 0x20); // 10 11 12 13 14 15 16 17
	hashA[3] = _mm256_permute2x128_si256(hashB[6], hashB[7], 0x20); // 18 19 1A 1B 1C 1D 1E 1F
	hashA[4] = _mm256_permute2x128_si256(hashB[0], hashB[1], 0x31); // 20 21 22 23 24 25 26 27
	hashA[5] = _mm256_permute2x128_si256(hashB[4], hashB[5], 0x31); // 28 29 2A 2B 2C 2D 2E 2F
	hashA[6] = _mm256_permute2x128_si256(hashB[2], hashB[3], 0x31); // 30 31 32 33 34 35 36 37
	hashA[7] = _mm256_permute2x128_si256(hashB[6], hashB[7], 0x31); // 38 39 3A 3B 3C 3D 3E 3F
	for (int i = 0; i < 8; i++)
	{
		sph_cubehash256(hashB + i, hashA + i, 32);
		LYRA2v2(hashA + i, hashB + i, wholeMatrix);
	}

	hashB[0] = _mm256_unpacklo_epi64(hashA[0], hashA[2]); // 00 01 10 11 04 05 14 15
	hashB[1] = _mm256_unpackhi_epi64(hashA[0], hashA[2]); // 02 03 12 13 06 07 16 17
	hashB[2] = _mm256_unpacklo_epi64(hashA[1], hashA[3]); // 08 09 18 19 0C 0D 1C 1D
	hashB[3] = _mm256_unpackhi_epi64(hashA[1], hashA[3]); // 0A 0B 1A 1B 0E 0F 1E 1F
	hashB[4] = _mm256_unpacklo_epi64(hashA[4], hashA[6]); // 20 21 30 31 24 25 34 35
	hashB[5] = _mm256_unpackhi_epi64(hashA[4], hashA[6]); // 22 23 32 33 26 27 36 37
	hashB[6] = _mm256_unpacklo_epi64(hashA[5], hashA[7]); // 28 29 38 39 2C 2D 3C 3D
	hashB[7] = _mm256_unpackhi_epi64(hashA[5], hashA[7]); // 2A 2B 3A 3B 2E 2F 3E 3F

	hashA[0] = _mm256_permute2x128_si256(hashB[0], hashB[2], 0x20); // 00 01 10 11 08 09 18 19
	hashA[1] = _mm256_permute2x128_si256(hashB[1], hashB[3], 0x20); // 02 03 12 13 0A 0B 1A 1B
	hashA[2] = _mm256_permute2x128_si256(hashB[0], hashB[2], 0x31); // 04 05 14 15 0C 0D 1C 1D
	hashA[3] = _mm256_permute2x128_si256(hashB[1], hashB[3], 0x31); // 06 07 16 17 0E 0F 1E 1F
	hashA[4] = _mm256_permute2x128_si256(hashB[4], hashB[6], 0x20); // 20 21 30 31 28 29 38 39
	hashA[5] = _mm256_permute2x128_si256(hashB[5], hashB[7], 0x20); // 22 23 32 33 2A 2B 3A 3B
	hashA[6] = _mm256_permute2x128_si256(hashB[4], hashB[6], 0x31); // 24 25 34 35 2C 2D 3C 3D
	hashA[7] = _mm256_permute2x128_si256(hashB[5], hashB[7], 0x31); // 26 27 36 37 2E 2F 3E 3F

	hashB[0] = _mm256_permute2x128_si256(hashA[0], hashA[4], 0x20); // 00 01 10 11 20 21 30 31
	hashB[1] = _mm256_permute2x128_si256(hashA[1], hashA[5], 0x20); // 02 03 12 13 22 23 32 33
	hashB[2] = _mm256_permute2x128_si256(hashA[2], hashA[6], 0x20); // 04 05 14 15 24 25 34 35
	hashB[3] = _mm256_permute2x128_si256(hashA[3], hashA[7], 0x20); // 06 07 16 17 26 27 36 37
	hashB[4] = _mm256_permute2x128_si256(hashA[0], hashA[4], 0x31); // 08 09 18 19 28 29 38 39
	hashB[5] = _mm256_permute2x128_si256(hashA[1], hashA[5], 0x31); // 0A 0B 1A 1B 2A 2B 3A 3B
	hashB[6] = _mm256_permute2x128_si256(hashA[2], hashA[6], 0x31); // 0C 0D 1C 1D 2C 2D 3C 3D
	hashB[7] = _mm256_permute2x128_si256(hashA[3], hashA[7], 0x31); // 0E 0F 1E 1F 2E 2F 3D 3F

	sph_skein256_32_AVX(hashA + 0, hashB + 0, 32);
	sph_skein256_32_AVX(hashA + 4, hashB + 4, 32);

	hashB[0] = _mm256_unpacklo_epi64(hashA[0], hashA[1]); // 00 01 02 03 20 21 22 23
	hashB[1] = _mm256_unpacklo_epi64(hashA[2], hashA[3]); // 04 05 06 07 24 25 26 27
	hashB[2] = _mm256_unpackhi_epi64(hashA[0], hashA[1]); // 10 11 12 13 30 31 32 33
	hashB[3] = _mm256_unpackhi_epi64(hashA[2], hashA[3]); // 14 15 16 17 34 35 36 37
	hashB[4] = _mm256_unpacklo_epi64(hashA[4], hashA[5]); // 08 09 0A 0B 28 29 2A 2B
	hashB[5] = _mm256_unpacklo_epi64(hashA[6], hashA[7]); // 0C 0D 0E 0F 2C 2D 2E 2F
	hashB[6] = _mm256_unpackhi_epi64(hashA[4], hashA[5]); // 18 19 1A 1B 38 39 3A 3B
	hashB[7] = _mm256_unpackhi_epi64(hashA[6], hashA[7]); // 1C 1D 1E 1F 3C 3D 3E 3F

	hashA[0] = _mm256_permute2x128_si256(hashB[0], hashB[1], 0x20); // 00 01 02 03 04 05 06 07
	hashA[1] = _mm256_permute2x128_si256(hashB[4], hashB[5], 0x20); // 08 09 0A 0B 0C 0D 0E 0F
	hashA[2] = _mm256_permute2x128_si256(hashB[2], hashB[3], 0x20); // 10 11 12 13 14 15 16 17
	hashA[3] = _mm256_permute2x128_si256(hashB[6], hashB[7], 0x20); // 18 19 1A 1B 1C 1D 1E 1F
	hashA[4] = _mm256_permute2x128_si256(hashB[0], hashB[1], 0x31); // 20 21 22 23 24 25 26 27
	hashA[5] = _mm256_permute2x128_si256(hashB[4], hashB[5], 0x31); // 28 29 2A 2B 2C 2D 2E 2F
	hashA[6] = _mm256_permute2x128_si256(hashB[2], hashB[3], 0x31); // 30 31 32 33 34 35 36 37
	hashA[7] = _mm256_permute2x128_si256(hashB[6], hashB[7], 0x31); // 38 39 3A 3B 3C 3D 3E 3F

	for (int i = 0; i < 8; i++)
	{
		sph_cubehash256(hashB + i, hashA + i, 32);
	}

	hashA[0] = _mm256_unpacklo_epi32(hashB[0], hashB[1]); // 00 10 01 11 04 14 05 15
	hashA[1] = _mm256_unpackhi_epi32(hashB[0], hashB[1]); // 02 12 03 13 06 16 07 17
	hashA[2] = _mm256_unpacklo_epi32(hashB[2], hashB[3]); // 20 30 21 31 24 34 25 35
	hashA[3] = _mm256_unpackhi_epi32(hashB[2], hashB[3]); // 22 32 23 33 26 36 27 37
	hashA[4] = _mm256_unpacklo_epi32(hashB[4], hashB[5]); // 40 50 41 51 44 54 45 55
	hashA[5] = _mm256_unpackhi_epi32(hashB[4], hashB[5]); // 42 52 43 53 46 56 47 57
	hashA[6] = _mm256_unpacklo_epi32(hashB[6], hashB[7]); // 60 70 61 71 64 74 65 75
	hashA[7] = _mm256_unpackhi_epi32(hashB[6], hashB[7]); // 62 72 63 73 66 76 67 77

	hashB[0] = _mm256_unpacklo_epi64(hashA[0], hashA[2]); // 00 10 20 30 04 14 24 34
	hashB[1] = _mm256_unpackhi_epi64(hashA[0], hashA[2]); // 01 11 21 31 05 15 25 35
	hashB[2] = _mm256_unpacklo_epi64(hashA[1], hashA[3]); // 02 12 22 32 06 16 26 36
	hashB[3] = _mm256_unpackhi_epi64(hashA[1], hashA[3]); // 03 13 23 33 07 17 27 37
	hashB[4] = _mm256_unpacklo_epi64(hashA[4], hashA[6]); // 40 50 60 70 44 54 64 74
	hashB[5] = _mm256_unpackhi_epi64(hashA[4], hashA[6]); // 41 51 61 71 45 55 65 75
	hashB[6] = _mm256_unpacklo_epi64(hashA[5], hashA[7]); // 42 52 62 72 46 56 66 76
	hashB[7] = _mm256_unpackhi_epi64(hashA[5], hashA[7]); // 43 53 63 73 47 57 67 77

	hashA[0] = _mm256_permute2x128_si256(hashB[0], hashB[4], 0x20); // 00 10 20 30 40 50 60 70
	hashA[1] = _mm256_permute2x128_si256(hashB[1], hashB[5], 0x20); // 01 11 21 31 41 51 61 71
	hashA[2] = _mm256_permute2x128_si256(hashB[2], hashB[6], 0x20); // 02 12 22 32 42 52 62 72
	hashA[3] = _mm256_permute2x128_si256(hashB[3], hashB[7], 0x20); // 03 13 23 33 43 53 63 73
	hashA[4] = _mm256_permute2x128_si256(hashB[0], hashB[4], 0x31); // 04 14 24 34 44 54 64 74
	hashA[5] = _mm256_permute2x128_si256(hashB[1], hashB[5], 0x31); // 05 15 25 35 45 55 65 75
	hashA[6] = _mm256_permute2x128_si256(hashB[2], hashB[6], 0x31); // 06 16 26 36 46 56 66 76
	hashA[7] = _mm256_permute2x128_si256(hashB[3], hashB[7], 0x31); // 07 17 27 37 47 57 67 77

	sph_bmw256_AVX(hashB, hashA, 32);

	hashA[0] = _mm256_unpacklo_epi32(hashB[0], hashB[1]); // 00 01 10 11 40 41 50 51
	hashA[1] = _mm256_unpackhi_epi32(hashB[0], hashB[1]); // 20 21 30 31 60 61 70 71
	hashA[2] = _mm256_unpacklo_epi32(hashB[2], hashB[3]); // 02 03 12 13 42 43 52 53
	hashA[3] = _mm256_unpackhi_epi32(hashB[2], hashB[3]); // 22 23 32 33 62 63 72 73
	hashA[4] = _mm256_unpacklo_epi32(hashB[4], hashB[5]); // 04 05 14 15 44 45 54 55
	hashA[5] = _mm256_unpackhi_epi32(hashB[4], hashB[5]); // 24 25 34 35 64 65 74 75
	hashA[6] = _mm256_unpacklo_epi32(hashB[6], hashB[7]); // 06 07 16 17 46 47 56 57
	hashA[7] = _mm256_unpackhi_epi32(hashB[6], hashB[7]); // 26 27 36 37 66 67 76 77

	hashB[0] = _mm256_unpacklo_epi64(hashA[0], hashA[2]); // 00 01 02 03 40 41 42 43
	hashB[1] = _mm256_unpackhi_epi64(hashA[0], hashA[2]); // 10 11 12 13 50 51 52 53
	hashB[2] = _mm256_unpacklo_epi64(hashA[1], hashA[3]); // 20 21 22 23 60 61 62 63
	hashB[3] = _mm256_unpackhi_epi64(hashA[1], hashA[3]); // 30 31 32 33 70 71 72 73
	hashB[4] = _mm256_unpacklo_epi64(hashA[4], hashA[6]); // 04 05 06 07 44 45 46 47
	hashB[5] = _mm256_unpackhi_epi64(hashA[4], hashA[6]); // 14 15 16 17 54 55 56 57
	hashB[6] = _mm256_unpacklo_epi64(hashA[5], hashA[7]); // 24 25 26 27 64 65 66 67
	hashB[7] = _mm256_unpackhi_epi64(hashA[5], hashA[7]); // 34 35 36 37 74 75 76 77

	hashA[0] = _mm256_permute2x128_si256(hashB[0], hashB[4], 0x20); // 00 01 02 03 04 05 06 07
	hashA[1] = _mm256_permute2x128_si256(hashB[1], hashB[5], 0x20); // 10 11 12 13 14 15 16 17
	hashA[2] = _mm256_permute2x128_si256(hashB[2], hashB[6], 0x20); // 20 21 22 23 24 25 26 27
	hashA[3] = _mm256_permute2x128_si256(hashB[3], hashB[7], 0x20); // 30 31 32 33 34 35 36 37
	hashA[4] = _mm256_permute2x128_si256(hashB[0], hashB[4], 0x31); // 40 41 42 43 44 45 46 47
	hashA[5] = _mm256_permute2x128_si256(hashB[1], hashB[5], 0x31); // 50 51 52 53 54 55 56 57
	hashA[6] = _mm256_permute2x128_si256(hashB[2], hashB[6], 0x31); // 60 61 62 63 64 65 66 67
	hashA[7] = _mm256_permute2x128_si256(hashB[3], hashB[7], 0x31); // 70 71 72 73 74 75 76 77

	for (int i = 0; i < 8; i++)
		_mm256_storeu_si256(((__m256i*)state) + i, hashA[i]);
	_mm256_zeroupper();
}
#else

void lyra2rev2_hash_SSE(void *state, const void *input, __m128i *wholeMatrix, int32_t *flag, __m128i *wholeMatrix2)
{
	__m128i hash[32];
	__m128i *hashA = hash;
	__m128i *hashB = hash + 16;

	if (flag) {
		sph_blake256_80_init(wholeMatrix2, input, 80);
		flag = 0;
	}

	for (int j = 0; j < 2; j++, hashA += 8, hashB += 8)
	{
		sph_blake256_80_SSE2(hashA, input, 80, wholeMatrix2);

		hashB[0] = _mm_unpacklo_epi32(hashA[0], hashA[1]); // 00 01 08 09
		hashB[1] = _mm_unpacklo_epi32(hashA[2], hashA[3]); // 02 03 0A 0B
		hashB[2] = _mm_unpacklo_epi32(hashA[4], hashA[5]); // 04 05 0C 0D
		hashB[3] = _mm_unpacklo_epi32(hashA[6], hashA[7]); // 06 07 0E 0F
		hashB[4] = _mm_unpackhi_epi32(hashA[0], hashA[1]); // 10 11 18 19
		hashB[5] = _mm_unpackhi_epi32(hashA[2], hashA[3]); // 12 13 1A 1B
		hashB[6] = _mm_unpackhi_epi32(hashA[4], hashA[5]); // 14 15 1C 1D
		hashB[7] = _mm_unpackhi_epi32(hashA[6], hashA[7]); // 16 17 1E 1F

		sph_keccak256_32_SSE2(hashA + 0, hashB + 0, 32);
		sph_keccak256_32_SSE2(hashA + 4, hashB + 4, 32);

		hashB[0] = _mm_unpacklo_epi64(hashA[0], hashA[1]); // 00 01 02 03
		hashB[1] = _mm_unpacklo_epi64(hashA[2], hashA[3]); // 04 05 06 07
		hashB[2] = _mm_unpackhi_epi64(hashA[0], hashA[1]); // 08 09 0A 0B
		hashB[3] = _mm_unpackhi_epi64(hashA[2], hashA[3]); // 0C 0D 0E 0F
		hashB[4] = _mm_unpacklo_epi64(hashA[4], hashA[5]); // 10 11 12 13
		hashB[5] = _mm_unpacklo_epi64(hashA[6], hashA[7]); // 14 15 16 17
		hashB[6] = _mm_unpackhi_epi64(hashA[4], hashA[5]); // 18 19 1A 1B
		hashB[7] = _mm_unpackhi_epi64(hashA[6], hashA[7]); // 1C 1D 1E 1F

		for (int i = 0; i < 8; i += 2)
		{
			sph_cubehash256_SSE2(hashA + i, hashB + i, 32);
#ifdef SSE3
			LYRA2v2_SSSE3(hashB + i, hashA + i, wholeMatrix);
#else
			LYRA2v2_SSE2(hashB + i, hashA + i, wholeMatrix);
#endif
		}

		hashA[0] = _mm_unpacklo_epi64(hashB[0], hashB[2]); // 00 01 08 09
		hashA[1] = _mm_unpackhi_epi64(hashB[0], hashB[2]); // 02 03 0A 0B
		hashA[2] = _mm_unpacklo_epi64(hashB[1], hashB[3]); // 04 05 0C 0D
		hashA[3] = _mm_unpackhi_epi64(hashB[1], hashB[3]); // 06 07 0E 0F
		hashA[4] = _mm_unpacklo_epi64(hashB[4], hashB[6]); // 10 11 18 19
		hashA[5] = _mm_unpackhi_epi64(hashB[4], hashB[6]); // 12 13 1A 1B
		hashA[6] = _mm_unpacklo_epi64(hashB[5], hashB[7]); // 14 15 1C 1D
		hashA[7] = _mm_unpackhi_epi64(hashB[5], hashB[7]); // 16 17 1E 1F

		sph_skein256_32_SSE2(hashB + 0, hashA + 0, 32);
		sph_skein256_32_SSE2(hashB + 4, hashA + 4, 32);

		hashA[0] = _mm_unpacklo_epi64(hashB[0], hashB[1]); // 00 01 02 03
		hashA[1] = _mm_unpacklo_epi64(hashB[2], hashB[3]); // 04 05 06 07
		hashA[2] = _mm_unpackhi_epi64(hashB[0], hashB[1]); // 08 09 0A 0B
		hashA[3] = _mm_unpackhi_epi64(hashB[2], hashB[3]); // 0C 0D 0E 0F
		hashA[4] = _mm_unpacklo_epi64(hashB[4], hashB[5]); // 10 11 12 13
		hashA[5] = _mm_unpacklo_epi64(hashB[6], hashB[7]); // 14 15 16 17
		hashA[6] = _mm_unpackhi_epi64(hashB[4], hashB[5]); // 18 19 1A 1B
		hashA[7] = _mm_unpackhi_epi64(hashB[6], hashB[7]); // 1C 1D 1E 1F

		for (int i = 0; i < 8; i += 2)
		{
			sph_cubehash256_SSE2(hashB + i, hashA + i, 32);
			//sph_cubehash256(hashB + i, hashA + i, 32);
		}

		hashA[0] = _mm_unpacklo_epi32(hashB[0], hashB[2]); // 00 08 01 09
		hashA[1] = _mm_unpackhi_epi32(hashB[0], hashB[2]); // 02 0A 03 0B
		hashA[2] = _mm_unpacklo_epi32(hashB[1], hashB[3]); // 04 0C 05 0D
		hashA[3] = _mm_unpackhi_epi32(hashB[1], hashB[3]); // 06 0E 07 0F
		hashA[4] = _mm_unpacklo_epi32(hashB[4], hashB[6]); // 10 18 11 19
		hashA[5] = _mm_unpackhi_epi32(hashB[4], hashB[6]); // 12 1A 13 1B
		hashA[6] = _mm_unpacklo_epi32(hashB[5], hashB[7]); // 14 1C 15 1D
		hashA[7] = _mm_unpackhi_epi32(hashB[5], hashB[7]); // 16 1E 17 1F

		hashB[0] = _mm_unpacklo_epi64(hashA[0], hashA[4]); // 00 08 10 18
		hashB[1] = _mm_unpackhi_epi64(hashA[0], hashA[4]); // 01 09 11 19
		hashB[2] = _mm_unpacklo_epi64(hashA[1], hashA[5]); // 02 0A 12 1A
		hashB[3] = _mm_unpackhi_epi64(hashA[1], hashA[5]); // 03 0B 13 1B
		hashB[4] = _mm_unpacklo_epi64(hashA[2], hashA[6]); // 04 1C 14 1C
		hashB[5] = _mm_unpackhi_epi64(hashA[2], hashA[6]); // 05 1D 15 1D
		hashB[6] = _mm_unpacklo_epi64(hashA[3], hashA[7]); // 06 1E 16 1E
		hashB[7] = _mm_unpackhi_epi64(hashA[3], hashA[7]); // 07 1F 17 1F

		sph_bmw256_SSE2(hashA, hashB, 32);

		hashB[0] = _mm_unpacklo_epi32(hashA[0], hashA[1]); // 00 01 08 09
		hashB[1] = _mm_unpacklo_epi32(hashA[2], hashA[3]); // 02 03 0A 0B
		hashB[2] = _mm_unpacklo_epi32(hashA[4], hashA[5]); // 04 05 0C 0D
		hashB[3] = _mm_unpacklo_epi32(hashA[6], hashA[7]); // 06 07 0E 0F
		hashB[4] = _mm_unpackhi_epi32(hashA[0], hashA[1]); // 10 11 18 19
		hashB[5] = _mm_unpackhi_epi32(hashA[2], hashA[3]); // 12 13 1A 1B
		hashB[6] = _mm_unpackhi_epi32(hashA[4], hashA[5]); // 14 15 1C 1D
		hashB[7] = _mm_unpackhi_epi32(hashA[6], hashA[7]); // 16 17 1E 1F

		hashA[0] = _mm_unpacklo_epi64(hashB[0], hashB[1]); // 00 01 02 03
		hashA[1] = _mm_unpacklo_epi64(hashB[2], hashB[3]); // 04 05 06 07
		hashA[2] = _mm_unpackhi_epi64(hashB[0], hashB[1]); // 08 09 0A 0B
		hashA[3] = _mm_unpackhi_epi64(hashB[2], hashB[3]); // 0C 0D 0E 0F
		hashA[4] = _mm_unpacklo_epi64(hashB[4], hashB[5]); // 10 11 12 13
		hashA[5] = _mm_unpacklo_epi64(hashB[6], hashB[7]); // 14 15 16 17
		hashA[6] = _mm_unpackhi_epi64(hashB[4], hashB[5]); // 18 19 1A 1B
		hashA[7] = _mm_unpackhi_epi64(hashB[6], hashB[7]); // 1C 1D 1E 1F

		for (int i = 0; i < 8; i++)
			_mm_storeu_si128(((__m128i*)state) + i + j * 8, hashA[i]);
	}
}
#endif

int scanhash_lyra2rev2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash[64];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t _ALIGN(128) wholeMatrix[384];
	uint32_t _ALIGN(128) wholeMatrix2[8];

	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	int32_t flag = -1;

	if (opt_benchmark)
		ptarget[7] = 0x0000ff;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	do {
		be32enc(&endiandata[19], nonce);
#ifndef SSE
		lyra2rev2_hash_AVX(hash, endiandata, wholeMatrix, &flag, wholeMatrix2);
#else
		lyra2rev2_hash_SSE(hash, endiandata, wholeMatrix, &flag, wholeMatrix2);
#endif
		for (int i = 0; i < 8; i++) {
			if (hash[7 + i * 8] <= Htarg && fulltest(hash + i * 8, ptarget)) {
				work_set_target_ratio(work, hash + i * 8);
				pdata[19] = nonce;
				*hashes_done = pdata[19] - first_nonce;
				return 1;
			}
			nonce ++;
		}

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
