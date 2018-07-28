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
#include "sha3/sph_groestl.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_keccak.h"

#include "lyra2/Lyra2.h"

#include "miner.h"

#ifndef SSE
void lyra2_hash(void *state, const void *input, __m256i *wholeMatrix)
{
	sph_blake256_context     ctx_blake;
	sph_keccak256_context    ctx_keccak;
	sph_skein256_context     ctx_skein;
	sph_groestl256_context   ctx_groestl;

	uint32_t hashA[8], hashB[8];

	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, input, 80);
	sph_blake256_close(&ctx_blake, hashA);

	sph_keccak256_init(&ctx_keccak);
	sph_keccak256(&ctx_keccak, hashA, 32);
	sph_keccak256_close(&ctx_keccak, hashB);
	LYRA2(hashA, 32, hashB, 32, hashB, 32, 1, 8, 8, wholeMatrix);
	sph_skein256_init(&ctx_skein);
	sph_skein256(&ctx_skein, hashA, 32);
	sph_skein256_close(&ctx_skein, hashB);

	sph_groestl256_init(&ctx_groestl);
	sph_groestl256(&ctx_groestl, hashB, 32);
	sph_groestl256_close(&ctx_groestl, hashA);

	memcpy(state, hashA, 32);
}

#else
void lyra2_hash_SSE(void *state, const void *input, __m128i *wholeMatrix)
{
	sph_blake256_context     ctx_blake;
	sph_keccak256_context    ctx_keccak;
	sph_skein256_context     ctx_skein;
	sph_groestl256_context   ctx_groestl;

	uint32_t _ALIGN(128) hashA[8], hashB[8];
	uint32_t _ALIGN(128) hashC[8];

	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, input, 80);
	sph_blake256_close(&ctx_blake, hashA);

	sph_keccak256_init(&ctx_keccak);
	sph_keccak256(&ctx_keccak, hashA, 32);
	sph_keccak256_close(&ctx_keccak, hashB);
#ifdef SSE3
	LYRA2_SSSE3(hashA, 32, hashB, 32, hashB, 32, 1, 8, 8, wholeMatrix);
#else
	LYRA2_SSE2(hashA, 32, hashB, 32, hashB, 32, 1, 8, 8, wholeMatrix);
#endif
	sph_skein256_init(&ctx_skein);
	sph_skein256(&ctx_skein, hashA, 32);
	sph_skein256_close(&ctx_skein, hashB);

	sph_groestl256_init(&ctx_groestl);
	sph_groestl256(&ctx_groestl, hashB, 32);
	sph_groestl256_close(&ctx_groestl, hashA);

	memcpy(state, hashA, 32);
}
#endif

int scanhash_lyra2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	if (opt_benchmark)
		ptarget[7] = 0x0000ff;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	__m128i *wholeMatrix = _aligned_malloc(6144, 32);
	if (wholeMatrix == NULL) {
		return -1;
	}
	memset(wholeMatrix, 0, 6144);

	do {
		be32enc(&endiandata[19], nonce);
#ifndef SSE
		lyra2_hash(hash, endiandata, (__m256i*)wholeMatrix);
#else
		lyra2_hash_SSE(hash, endiandata, wholeMatrix);
#endif
		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			_aligned_free(wholeMatrix);
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	_aligned_free(wholeMatrix);
	return 0;
}
