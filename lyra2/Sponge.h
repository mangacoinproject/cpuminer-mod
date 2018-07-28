/**
 * Header file for Blake2b's internal permutation in the form of a sponge.
 * This code is based on the original Blake2b's implementation provided by
 * Samuel Neves (https://blake2.net/)
 *
 * Author: The Lyra PHC team (http://www.lyra-kdf.net/) -- 2014.
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef SPONGE_H_
#define SPONGE_H_

#include <stdint.h>
#ifndef SSE
#include <immintrin.h>
#else
#ifdef SSE3
#include <tmmintrin.h>
#else
#include <emmintrin.h> //SSE2
#endif
#endif
 
 /* Blake2b's G function */
#define G(r,i,a,b,c,d) do { \
	a = _mm256_add_epi64(a, b); \
	d = _mm256_xor_si256(d, a); \
	d = _mm256_or_si256(_mm256_srli_epi64(d, 32),_mm256_slli_epi64(d, 32)); \
	c = _mm256_add_epi64(c, d); \
	b = _mm256_xor_si256(b, c); \
	b = _mm256_or_si256(_mm256_srli_epi64(b, 24),_mm256_slli_epi64(b, 40)); \
	a = _mm256_add_epi64(a, b); \
	d = _mm256_xor_si256(d, a); \
	d = _mm256_or_si256(_mm256_srli_epi64(d, 16),_mm256_slli_epi64(d, 48)); \
	c = _mm256_add_epi64(c, d); \
	b = _mm256_xor_si256(b, c); \
	b = _mm256_or_si256(_mm256_srli_epi64(b, 63),_mm256_slli_epi64(b, 1)); \
  } while(0)

#define G_SSE2(r,i,a,b,c,d) do { \
	a = _mm_add_epi64(a, b); \
	d = _mm_xor_si128(d, a); \
	d = _mm_or_si128(_mm_srli_epi64(d, 32),_mm_slli_epi64(d, 32)); \
	c = _mm_add_epi64(c, d); \
	b = _mm_xor_si128(b, c); \
	b = _mm_or_si128(_mm_srli_epi64(b, 24),_mm_slli_epi64(b, 40)); \
	a = _mm_add_epi64(a, b); \
	d = _mm_xor_si128(d, a); \
	d = _mm_or_si128(_mm_srli_epi64(d, 16),_mm_slli_epi64(d, 48)); \
	c = _mm_add_epi64(c, d); \
	b = _mm_xor_si128(b, c); \
	b = _mm_or_si128(_mm_srli_epi64(b, 63),_mm_slli_epi64(b, 1)); \
  } while(0)

/*One Round of the Blake2b's compression function*/
#define ROUND_LYRA(r) \
	G(r,0,state0,state1,state2,state3); \
	state1 = _mm256_permute4x64_epi64(state1, 0x39); \
	state2 = _mm256_permute4x64_epi64(state2, 0x4e); \
	state3 = _mm256_permute4x64_epi64(state3, 0x93); \
	G(r,1,state0,state1,state2,state3); \
	state1 = _mm256_permute4x64_epi64(state1, 0x93); \
	state2 = _mm256_permute4x64_epi64(state2, 0x4e); \
	state3 = _mm256_permute4x64_epi64(state3, 0x39);

#define ROUND_LYRA_SSSE3(r) {\
	G_SSE2(r,0,state0,state2,state4,state6); \
	G_SSE2(r,1,state1,state3,state5,state7); \
	__m128i buffer0 = _mm_alignr_epi8(state3, state2, 8); \
	__m128i buffer1 = _mm_alignr_epi8(state2, state3, 8); \
	__m128i buffer2 = _mm_alignr_epi8(state6, state7, 8); \
	__m128i buffer3 = _mm_alignr_epi8(state7, state6, 8); \
	G_SSE2(r,2,state0,buffer0,state5,buffer2); \
	G_SSE2(r,3,state1,buffer1,state4,buffer3); \
	state2 = _mm_alignr_epi8(buffer0, buffer1, 8); \
	state3 = _mm_alignr_epi8(buffer1, buffer0, 8); \
	state6 = _mm_alignr_epi8(buffer3, buffer2, 8); \
	state7 = _mm_alignr_epi8(buffer2, buffer3, 8); \
}

#define ROUND_LYRA_SSE2(r) {\
	G_SSE2(r,0,state0,state2,state4,state6); \
	G_SSE2(r,1,state1,state3,state5,state7); \
	__m128i buffer0 = _mm_or_si128(_mm_srli_si128(state2, 8), _mm_slli_si128(state3, 8)); \
	__m128i buffer1 = _mm_or_si128(_mm_srli_si128(state3, 8), _mm_slli_si128(state2, 8)); \
	__m128i buffer2 = _mm_or_si128(_mm_srli_si128(state7, 8), _mm_slli_si128(state6, 8)); \
	__m128i buffer3 = _mm_or_si128(_mm_srli_si128(state6, 8), _mm_slli_si128(state7, 8)); \
	G_SSE2(r,2,state0,buffer0,state5,buffer2); \
	G_SSE2(r,3,state1,buffer1,state4,buffer3); \
	state2 = _mm_or_si128(_mm_srli_si128(buffer1, 8), _mm_slli_si128(buffer0, 8)); \
	state3 = _mm_or_si128(_mm_srli_si128(buffer0, 8), _mm_slli_si128(buffer1, 8)); \
	state6 = _mm_or_si128(_mm_srli_si128(buffer2, 8), _mm_slli_si128(buffer3, 8)); \
	state7 = _mm_or_si128(_mm_srli_si128(buffer3, 8), _mm_slli_si128(buffer2, 8)); \
}

#define blake2bLyra(r) \
	ROUND_LYRA(0); \
	ROUND_LYRA(1); \
	ROUND_LYRA(2); \
	ROUND_LYRA(3); \
	ROUND_LYRA(4); \
	ROUND_LYRA(5); \
	ROUND_LYRA(6); \
	ROUND_LYRA(7); \
	ROUND_LYRA(8); \
	ROUND_LYRA(9); \
	ROUND_LYRA(10); \
	ROUND_LYRA(11);

#define blake2bLyra_SSE2(r) \
	ROUND_LYRA_SSE2(0); \
	ROUND_LYRA_SSE2(1); \
	ROUND_LYRA_SSE2(2); \
	ROUND_LYRA_SSE2(3); \
	ROUND_LYRA_SSE2(4); \
	ROUND_LYRA_SSE2(5); \
	ROUND_LYRA_SSE2(6); \
	ROUND_LYRA_SSE2(7); \
	ROUND_LYRA_SSE2(8); \
	ROUND_LYRA_SSE2(9); \
	ROUND_LYRA_SSE2(10); \
	ROUND_LYRA_SSE2(11);

#define blake2bLyra_SSSE3(r) \
	ROUND_LYRA_SSSE3(0); \
	ROUND_LYRA_SSSE3(1); \
	ROUND_LYRA_SSSE3(2); \
	ROUND_LYRA_SSSE3(3); \
	ROUND_LYRA_SSSE3(4); \
	ROUND_LYRA_SSSE3(5); \
	ROUND_LYRA_SSSE3(6); \
	ROUND_LYRA_SSSE3(7); \
	ROUND_LYRA_SSSE3(8); \
	ROUND_LYRA_SSSE3(9); \
	ROUND_LYRA_SSSE3(10); \
	ROUND_LYRA_SSSE3(11);

#define reducedBlake2bLyra(r) \
	ROUND_LYRA(0);

#define reducedBlake2bLyra_SSE2(r) \
	ROUND_LYRA_SSE2(0);

#define reducedBlake2bLyra_SSSE3(r) \
	ROUND_LYRA_SSSE3(0);

#endif /* SPONGE_H_ */
