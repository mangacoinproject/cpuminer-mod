/**
 * Implementation of the Lyra2 Password Hashing Scheme (PHS).
 *
 * Author: The Lyra PHC team (http://www.lyra-kdf.net/) -- 2014.
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "Lyra2.h"
#include "Sponge.h"

/**
* Prints an array of unsigned chars
*/
void printArray(unsigned char *array, unsigned int size, char *name)
{
	unsigned int i;
	printf("%s: ", name);
	for (i = 0; i < size; i++) {
		printf("%2x|", array[i]);
	}
	printf("\n");
}

////////////////////////////////////////////////////////////////////////////////////////////////


/**
 * Executes Lyra2 based on the G function from Blake2b. This version supports salts and passwords
 * whose combined length is smaller than the size of the memory matrix, (i.e., (nRows x nCols x b) bits,
 * where "b" is the underlying sponge's bitrate). In this implementation, the "basil" is composed by all
 * integer parameters (treated as type "unsigned int") in the order they are provided, plus the value
 * of nCols, (i.e., basil = kLen || pwdlen || saltlen || timeCost || nRows || nCols).
 *
 * @param K The derived key to be output by the algorithm
 * @param kLen Desired key length
 * @param pwd User password
 * @param pwdlen Password length
 * @param salt Salt
 * @param saltlen Salt length
 * @param timeCost Parameter to determine the processing time (T)
 * @param nRows Number or rows of the memory matrix (R)
 * @param nCols Number of columns of the memory matrix (C)
 *
 * @return 0 if the key is generated correctly; -1 if there is an error (usually due to lack of memory for allocation)
 */
#ifndef SSE
int LYRA2(void *K, int64_t kLen, const void *pwd, int32_t pwdlen, const void *salt, int32_t saltlen, int64_t timeCost, const int16_t nRows, const int16_t nCols, __m256i *wholeMatrix)
{
	//============================= Basic variables ============================//
	int64_t row = 2; //index of row to be processed
	int64_t prev = 1; //index of prev (last row ever computed/modified)
	int64_t rowa = 0; //index of row* (a previous row, deterministically picked during Setup and randomly picked while Wandering)
	int64_t tau; //Time Loop iterator
	int64_t step = 1; //Visitation step (used during Setup and Wandering phases)
	int64_t window = 2; //Visitation window (used to define which rows can be revisited during Setup)
	int64_t gap = 1; //Modifier to the step, assuming the values 1 or -1
	int64_t i; //auxiliary iteration counter
	int64_t v64; // 64bit var for memcpy
	//==========================================================================/

	//========== Initializing the Memory Matrix and pointers to it =============//
	//Tries to allocate enough space for the whole memory matrix

	const int64_t ROW_LEN_YMM = BLOCK_LEN_YMM * nCols;
	const int64_t ROW_LEN_BYTES = ROW_LEN_YMM * 32;
	// for Lyra2REv2, nCols = 4, v1 was using 8
	const int64_t BLOCK_LEN = (nCols == 4) ? BLOCK_LEN_BLAKE2_SAFE_INT64 : BLOCK_LEN_BLAKE2_SAFE_BYTES;

	i = (int64_t)ROW_LEN_BYTES * nRows;

	//Allocates pointers to each row of the matrix
	__m256i **memMatrix = malloc(sizeof(__m256i*) * nRows);
	if (memMatrix == NULL) {
		return -1;
	}
	//Places the pointers in the correct positions
	__m256i *ptrWord = wholeMatrix;
	for (i = 0; i < nRows; i++) {
		memMatrix[i] = ptrWord;
		ptrWord += ROW_LEN_YMM;
	}
	//==========================================================================/

	//============= Getting the password + salt + basil padded with 10*1 ===============//
	//OBS.:The memory matrix will temporarily hold the password: not for saving memory,
	//but this ensures that the password copied locally will be overwritten as soon as possible

	//First, we clean enough blocks for the password, salt, basil and padding
	int64_t nBlocksInput = ((saltlen + pwdlen + 6 * sizeof(uint64_t)) / BLOCK_LEN_BLAKE2_SAFE_BYTES) + 1;

	byte *ptrByte = (byte*)wholeMatrix;

	//Prepends the password
	memcpy(ptrByte, pwd, pwdlen);
	ptrByte += pwdlen;

	//Concatenates the salt
	memcpy(ptrByte, salt, saltlen);
	ptrByte += saltlen;

	memset(ptrByte, 0, nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - (saltlen + pwdlen));

	//Concatenates the basil: every integer passed as parameter, in the order they are provided by the interface
	memcpy(ptrByte, &kLen, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = pwdlen;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = saltlen;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = timeCost;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = nRows;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = nCols;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);

	//Now comes the padding
	*ptrByte = 0x80; //first byte of padding: right after the password
	ptrByte = (byte*)wholeMatrix; //resets the pointer to the start of the memory matrix
	ptrByte += nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - 1; //sets the pointer to the correct position: end of incomplete block
	*ptrByte ^= 0x01; //last byte of padding: at the end of the last incomplete block
	//==========================================================================/

	//======================= Initializing the Sponge State ====================//
	//Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)
	register __m256i state0, state1, state2, state3;
	//First 512 bis are zeros
	state0 = state1 = _mm256_setzero_si256();
	//Remainder BLOCK_LEN_BLAKE2_SAFE_BYTES are reserved to the IV
	state2 = _mm256_setr_epi64x(0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL);
	state3 = _mm256_setr_epi64x(0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL);
	//==========================================================================/

	//================================ Setup Phase =============================//
	//Absorbing salt, password and basil: this is the only place in which the block length is hard-coded to 512 bits
	ptrWord = wholeMatrix;
	for (i = 0; i < nBlocksInput; i++) {
		//XORs the first BLOCK_LEN_BLAKE2_SAFE_INT64 words of "in" with the current state
		state0 = _mm256_xor_si256(state0, ptrWord[0]);
		state1 = _mm256_xor_si256(state1, ptrWord[1]);

		//Applies the transformation f to the sponge's state
		blake2bLyra(state);

		ptrWord += BLOCK_LEN >> 2; //goes to next block of pad(pwd || salt || basil)
	}

	//Initializes M[0] and M[1]
	ptrWord = memMatrix[0] + (nCols - 1)*BLOCK_LEN_YMM; //In Lyra2: pointer to M[0][C-1]
														//M[row][C-1-col] = H.reduced_squeeze()
	for (i = 0; i < nCols; i++) {
		ptrWord[0] = state0;
		ptrWord[1] = state1;
		ptrWord[2] = state2;

		//Goes to next block (column) that will receive the squeezed data
		ptrWord -= BLOCK_LEN_YMM;

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra(state);
	}

	__m256i* ptrWordIn = memMatrix[0];				//In Lyra2: pointer to prev
	__m256i* ptrWordOut = memMatrix[1] + (nCols - 1)*BLOCK_LEN_YMM; //In Lyra2: pointer to row

	for (i = 0; i < nCols; i++) {

		//Absorbing "M[prev][col]"
		state0 = _mm256_xor_si256(state0, ptrWordIn[0]);
		state1 = _mm256_xor_si256(state1, ptrWordIn[1]);
		state2 = _mm256_xor_si256(state2, ptrWordIn[2]);

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra(state);

		//M[row][C-1-col] = M[prev][col] XOR rand
		ptrWordOut[0] = _mm256_xor_si256(ptrWordIn[0], state0);
		ptrWordOut[1] = _mm256_xor_si256(ptrWordIn[1], state1);
		ptrWordOut[2] = _mm256_xor_si256(ptrWordIn[2], state2);

		//Input: next column (i.e., next block in sequence)
		ptrWordIn += BLOCK_LEN_YMM;
		//Output: goes to previous column
		ptrWordOut -= BLOCK_LEN_YMM;
	}

	do {
		//M[row] = rand; //M[row*] = M[row*] XOR rotW(rand)
		ptrWordIn = memMatrix[prev];				//In Lyra2: pointer to prev
		__m256i* ptrWordInOut = memMatrix[rowa];				//In Lyra2: pointer to row*
		ptrWordOut = memMatrix[row] + (nCols - 1)*BLOCK_LEN_YMM; //In Lyra2: pointer to row

		for (i = 0; i < nCols; i++) {

			//Absorbing "M[prev] [+] M[row*]"
			state0 = _mm256_xor_si256(state0, _mm256_add_epi64(ptrWordIn[0], ptrWordInOut[0]));
			state1 = _mm256_xor_si256(state1, _mm256_add_epi64(ptrWordIn[1], ptrWordInOut[1]));
			state2 = _mm256_xor_si256(state2, _mm256_add_epi64(ptrWordIn[2], ptrWordInOut[2]));

			//Applies the reduced-round transformation f to the sponge's state
			reducedBlake2bLyra(state);

			//M[row][col] = M[prev][col] XOR rand
			ptrWordOut[0] = _mm256_xor_si256(ptrWordIn[0], state0);
			ptrWordOut[1] = _mm256_xor_si256(ptrWordIn[1], state1);
			ptrWordOut[2] = _mm256_xor_si256(ptrWordIn[2], state2);

			//M[row*][col] = M[row*][col] XOR rotW(rand)
			ptrWordInOut[0] = _mm256_xor_si256(ptrWordInOut[0], _mm256_alignr_epi8(state0, _mm256_permute2x128_si256(state0, state2, 0x03), 8));
			ptrWordInOut[1] = _mm256_xor_si256(ptrWordInOut[1], _mm256_alignr_epi8(state1, _mm256_permute2x128_si256(state1, state0, 0x03), 8));
			ptrWordInOut[2] = _mm256_xor_si256(ptrWordInOut[2], _mm256_alignr_epi8(state2, _mm256_permute2x128_si256(state2, state1, 0x03), 8));

			//Inputs: next column (i.e., next block in sequence)
			ptrWordInOut += BLOCK_LEN_YMM;
			ptrWordIn += BLOCK_LEN_YMM;
			//Output: goes to previous column
			ptrWordOut -= BLOCK_LEN_YMM;
		}

		//updates the value of row* (deterministically picked during Setup))
		rowa = (rowa + step) & (window - 1);
		//update prev: it now points to the last row ever computed
		prev = row;
		//updates row: goes to the next row to be computed
		row++;

		//Checks if all rows in the window where visited.
		if (rowa == 0) {
			step = window + gap; //changes the step: approximately doubles its value
			window *= 2; //doubles the size of the re-visitation window
			gap = -gap; //inverts the modifier to the step
		}

	} while (row < nRows);
	//==========================================================================/

	//============================ Wandering Phase =============================//
	row = 0; //Resets the visitation to the first row of the memory matrix
	for (tau = 1; tau <= timeCost; tau++) {
		//Step is approximately half the number of all rows of the memory matrix for an odd tau; otherwise, it is -1
		step = (tau % 2 == 0) ? -1 : nRows / 2 - 1;
		do {
			//Selects a pseudorandom index row*
			//------------------------------------------------------------------------------------------
			rowa = state0.m256i_u64[0] & (unsigned int)(nRows - 1);  //(USE THIS IF nRows IS A POWER OF 2)
																	 //rowa = state0 % nRows; //(USE THIS FOR THE "GENERIC" CASE)
			//------------------------------------------------------------------------------------------

																	 //Performs a reduced-round duplexing operation over M[row*] XOR M[prev], updating both M[row*] and M[row]
			ptrWordIn = memMatrix[prev]; //In Lyra2: pointer to prev
			__m256i* ptrWordInOut = memMatrix[rowa]; //In Lyra2: pointer to row*
			ptrWordOut = memMatrix[row]; //In Lyra2: pointer to row

			for (i = 0; i < nCols; i++) {

				//Absorbing "M[prev] [+] M[row*]"
				state0 = _mm256_xor_si256(state0, _mm256_add_epi64(ptrWordIn[0], ptrWordInOut[0]));
				state1 = _mm256_xor_si256(state1, _mm256_add_epi64(ptrWordIn[1], ptrWordInOut[1]));
				state2 = _mm256_xor_si256(state2, _mm256_add_epi64(ptrWordIn[2], ptrWordInOut[2]));

				//Applies the reduced-round transformation f to the sponge's state
				reducedBlake2bLyra(state);

				//M[rowOut][col] = M[rowOut][col] XOR rand
				ptrWordOut[0] = _mm256_xor_si256(ptrWordOut[0], state0);
				ptrWordOut[1] = _mm256_xor_si256(ptrWordOut[1], state1);
				ptrWordOut[2] = _mm256_xor_si256(ptrWordOut[2], state2);

				//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
				ptrWordInOut[0] = _mm256_xor_si256(ptrWordInOut[0], _mm256_alignr_epi8(state0, _mm256_permute2x128_si256(state0, state2, 0x03), 8));
				ptrWordInOut[1] = _mm256_xor_si256(ptrWordInOut[1], _mm256_alignr_epi8(state1, _mm256_permute2x128_si256(state1, state0, 0x03), 8));
				ptrWordInOut[2] = _mm256_xor_si256(ptrWordInOut[2], _mm256_alignr_epi8(state2, _mm256_permute2x128_si256(state2, state1, 0x03), 8));

				//Goes to next block
				ptrWordOut += BLOCK_LEN_YMM;
				ptrWordInOut += BLOCK_LEN_YMM;
				ptrWordIn += BLOCK_LEN_YMM;
			}
			//update prev: it now points to the last row ever computed
			prev = row;

			//updates row: goes to the next row to be computed
			//------------------------------------------------------------------------------------------
			row = (row + step) & (unsigned int)(nRows - 1); //(USE THIS IF nRows IS A POWER OF 2)
															//row = (row + step) % nRows; //(USE THIS FOR THE "GENERIC" CASE)
			//------------------------------------------------------------------------------------------

		} while (row != 0);
	}

	//============================ Wrap-up Phase ===============================//
	//XORs the first BLOCK_LEN_INT64 words of "in" with the current state
	state0 = _mm256_xor_si256(state0, memMatrix[rowa][0]);
	state1 = _mm256_xor_si256(state1, memMatrix[rowa][1]);
	state2 = _mm256_xor_si256(state2, memMatrix[rowa][2]);

	//Applies the transformation f to the sponge's state
	blake2bLyra(state);


	//Squeezes the key
	int64_t fullBlocks = kLen / BLOCK_LEN_BYTES;
	__m256i *ptr = (__m256i*)K;
	//Squeezes full blocks
	for (i = 0; i < fullBlocks; i++) {
		_mm256_storeu_si256(ptr + 0, state0);
		_mm256_storeu_si256(ptr + 1, state1);
		_mm256_storeu_si256(ptr + 2, state2);
		blake2bLyra(state);
		ptr += BLOCK_LEN_YMM;
	}

	//Squeezes remaining bytes
	int remain = kLen % BLOCK_LEN_BYTES;
	if (remain > 0) _mm256_storeu_si256(ptr + 0, state0);
	if (remain > 32) _mm256_storeu_si256(ptr + 1, state1);
	if (remain > 64) _mm256_storeu_si256(ptr + 2, state2);

	//========================= Freeing the memory =============================//
	free(memMatrix);
	_mm256_zeroupper();

	return 0;
}

#else
#ifdef SSE3
int LYRA2_SSSE3(void *K, int64_t kLen, const void *pwd, int32_t pwdlen, const void *salt, int32_t saltlen, int64_t timeCost, const int16_t nRows, const int16_t nCols, __m128i *wholeMatrix)
{
	//============================= Basic variables ============================//
	int64_t row = 2; //index of row to be processed
	int64_t prev = 1; //index of prev (last row ever computed/modified)
	int64_t rowa = 0; //index of row* (a previous row, deterministically picked during Setup and randomly picked while Wandering)
	int64_t tau; //Time Loop iterator
	int64_t step = 1; //Visitation step (used during Setup and Wandering phases)
	int64_t window = 2; //Visitation window (used to define which rows can be revisited during Setup)
	int64_t gap = 1; //Modifier to the step, assuming the values 1 or -1
	int64_t i; //auxiliary iteration counter
	int64_t v64; // 64bit var for memcpy
				 //==========================================================================/

				 //========== Initializing the Memory Matrix and pointers to it =============//
				 //Tries to allocate enough space for the whole memory matrix

	const int64_t ROW_LEN_XMM = BLOCK_LEN_XMM * nCols;
	const int64_t ROW_LEN_BYTES = ROW_LEN_XMM * 16;
	// for Lyra2REv2, nCols = 4, v1 was using 8
	const int64_t BLOCK_LEN = (nCols == 4) ? BLOCK_LEN_BLAKE2_SAFE_INT64 : BLOCK_LEN_BLAKE2_SAFE_BYTES;

	i = (int64_t)ROW_LEN_BYTES * nRows;

	//Allocates pointers to each row of the matrix
	__m128i **memMatrix = malloc(sizeof(__m128i*) * nRows);
	if (memMatrix == NULL) {
		return -1;
	}
	//Places the pointers in the correct positions
	__m128i *ptrWord = wholeMatrix;
	for (i = 0; i < nRows; i++) {
		memMatrix[i] = ptrWord;
		ptrWord += ROW_LEN_XMM;
	}
	//==========================================================================/

	//============= Getting the password + salt + basil padded with 10*1 ===============//
	//OBS.:The memory matrix will temporarily hold the password: not for saving memory,
	//but this ensures that the password copied locally will be overwritten as soon as possible

	//First, we clean enough blocks for the password, salt, basil and padding
	int64_t nBlocksInput = ((saltlen + pwdlen + 6 * sizeof(uint64_t)) / BLOCK_LEN_BLAKE2_SAFE_BYTES) + 1;

	byte *ptrByte = (byte*)wholeMatrix;

	//Prepends the password
	memcpy(ptrByte, pwd, pwdlen);
	ptrByte += pwdlen;

	//Concatenates the salt
	memcpy(ptrByte, salt, saltlen);
	ptrByte += saltlen;

	memset(ptrByte, 0, nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - (saltlen + pwdlen));
	memset((byte*)wholeMatrix + BLOCK_LEN * 8, 0, 64);

	//Concatenates the basil: every integer passed as parameter, in the order they are provided by the interface
	memcpy(ptrByte, &kLen, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = pwdlen;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = saltlen;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = timeCost;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = nRows;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = nCols;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);

	//Now comes the padding
	*ptrByte = 0x80; //first byte of padding: right after the password
	ptrByte = (byte*)wholeMatrix; //resets the pointer to the start of the memory matrix
	ptrByte += nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - 1; //sets the pointer to the correct position: end of incomplete block
	*ptrByte ^= 0x01; //last byte of padding: at the end of the last incomplete block
					  //==========================================================================/

					  //======================= Initializing the Sponge State ====================//
					  //Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)
	__m128i state0, state1, state2, state3, state4, state5, state6, state7;
	//First 512 bis are zeros
	state0 = state1 = state2 = state3 = _mm_setzero_si128();
	//Remainder BLOCK_LEN_BLAKE2_SAFE_BYTES are reserved to the IV
	state4 = _mm_setr_epi32(0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85);
	state5 = _mm_setr_epi32(0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a);
	state6 = _mm_setr_epi32(0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c);
	state7 = _mm_setr_epi32(0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19);
	//==========================================================================/

	//================================ Setup Phase =============================//
	//Absorbing salt, password and basil: this is the only place in which the block length is hard-coded to 512 bits
	ptrWord = wholeMatrix;
	for (i = 0; i < nBlocksInput; i++) {
		//XORs the first BLOCK_LEN_BLAKE2_SAFE_INT64 words of "in" with the current state
		state0 = _mm_xor_si128(state0, ptrWord[0]);
		state1 = _mm_xor_si128(state1, ptrWord[1]);
		state2 = _mm_xor_si128(state2, ptrWord[2]);
		state3 = _mm_xor_si128(state3, ptrWord[3]);

		//Applies the transformation f to the sponge's state
		blake2bLyra_SSSE3(state);

		ptrWord += BLOCK_LEN >> 1; //goes to next block of pad(pwd || salt || basil)
	}

	//Initializes M[0] and M[1]
	ptrWord = memMatrix[0] + (nCols - 1)*BLOCK_LEN_XMM; //In Lyra2: pointer to M[0][C-1]
														//M[row][C-1-col] = H.reduced_squeeze()
	for (i = 0; i < nCols; i++) {
		ptrWord[0] = state0;
		ptrWord[1] = state1;
		ptrWord[2] = state2;
		ptrWord[3] = state3;
		ptrWord[4] = state4;
		ptrWord[5] = state5;

		//Goes to next block (column) that will receive the squeezed data
		ptrWord -= BLOCK_LEN_XMM;

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSSE3(state);
	}

	__m128i* ptrWordIn = memMatrix[0];				//In Lyra2: pointer to prev
	__m128i* ptrWordOut = memMatrix[1] + (nCols - 1)*BLOCK_LEN_XMM; //In Lyra2: pointer to row

	for (i = 0; i < nCols; i++) {

		//Absorbing "M[prev][col]"
		state0 = _mm_xor_si128(state0, ptrWordIn[0]);
		state1 = _mm_xor_si128(state1, ptrWordIn[1]);
		state2 = _mm_xor_si128(state2, ptrWordIn[2]);
		state3 = _mm_xor_si128(state3, ptrWordIn[3]);
		state4 = _mm_xor_si128(state4, ptrWordIn[4]);
		state5 = _mm_xor_si128(state5, ptrWordIn[5]);

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSSE3(state);

		//M[row][C-1-col] = M[prev][col] XOR rand
		ptrWordOut[0] = _mm_xor_si128(ptrWordIn[0], state0);
		ptrWordOut[1] = _mm_xor_si128(ptrWordIn[1], state1);
		ptrWordOut[2] = _mm_xor_si128(ptrWordIn[2], state2);
		ptrWordOut[3] = _mm_xor_si128(ptrWordIn[3], state3);
		ptrWordOut[4] = _mm_xor_si128(ptrWordIn[4], state4);
		ptrWordOut[5] = _mm_xor_si128(ptrWordIn[5], state5);

		//Input: next column (i.e., next block in sequence)
		ptrWordIn += BLOCK_LEN_XMM;
		//Output: goes to previous column
		ptrWordOut -= BLOCK_LEN_XMM;
	}

	do {
		//M[row] = rand; //M[row*] = M[row*] XOR rotW(rand)
		ptrWordIn = memMatrix[prev];				//In Lyra2: pointer to prev
		__m128i* ptrWordInOut = memMatrix[rowa];				//In Lyra2: pointer to row*
		ptrWordOut = memMatrix[row] + (nCols - 1)*BLOCK_LEN_XMM; //In Lyra2: pointer to row

		for (i = 0; i < nCols; i++) {

			//Absorbing "M[prev] [+] M[row*]"
			state0 = _mm_xor_si128(state0, _mm_add_epi64(ptrWordIn[0], ptrWordInOut[0]));
			state1 = _mm_xor_si128(state1, _mm_add_epi64(ptrWordIn[1], ptrWordInOut[1]));
			state2 = _mm_xor_si128(state2, _mm_add_epi64(ptrWordIn[2], ptrWordInOut[2]));
			state3 = _mm_xor_si128(state3, _mm_add_epi64(ptrWordIn[3], ptrWordInOut[3]));
			state4 = _mm_xor_si128(state4, _mm_add_epi64(ptrWordIn[4], ptrWordInOut[4]));
			state5 = _mm_xor_si128(state5, _mm_add_epi64(ptrWordIn[5], ptrWordInOut[5]));

			//Applies the reduced-round transformation f to the sponge's state
			reducedBlake2bLyra_SSSE3(state);

			//M[row][col] = M[prev][col] XOR rand
			ptrWordOut[0] = _mm_xor_si128(ptrWordIn[0], state0);
			ptrWordOut[1] = _mm_xor_si128(ptrWordIn[1], state1);
			ptrWordOut[2] = _mm_xor_si128(ptrWordIn[2], state2);
			ptrWordOut[3] = _mm_xor_si128(ptrWordIn[3], state3);
			ptrWordOut[4] = _mm_xor_si128(ptrWordIn[4], state4);
			ptrWordOut[5] = _mm_xor_si128(ptrWordIn[5], state5);

			//M[row*][col] = M[row*][col] XOR rotW(rand)
			ptrWordInOut[0] = _mm_xor_si128(ptrWordInOut[0], _mm_alignr_epi8(state0, state5, 8));
			ptrWordInOut[1] = _mm_xor_si128(ptrWordInOut[1], _mm_alignr_epi8(state1, state0, 8));
			ptrWordInOut[2] = _mm_xor_si128(ptrWordInOut[2], _mm_alignr_epi8(state2, state1, 8));
			ptrWordInOut[3] = _mm_xor_si128(ptrWordInOut[3], _mm_alignr_epi8(state3, state2, 8));
			ptrWordInOut[4] = _mm_xor_si128(ptrWordInOut[4], _mm_alignr_epi8(state4, state3, 8));
			ptrWordInOut[5] = _mm_xor_si128(ptrWordInOut[5], _mm_alignr_epi8(state5, state4, 8));

			//Inputs: next column (i.e., next block in sequence)
			ptrWordInOut += BLOCK_LEN_XMM;
			ptrWordIn += BLOCK_LEN_XMM;
			//Output: goes to previous column
			ptrWordOut -= BLOCK_LEN_XMM;
		}

		//updates the value of row* (deterministically picked during Setup))
		rowa = (rowa + step) & (window - 1);
		//update prev: it now points to the last row ever computed
		prev = row;
		//updates row: goes to the next row to be computed
		row++;

		//Checks if all rows in the window where visited.
		if (rowa == 0) {
			step = window + gap; //changes the step: approximately doubles its value
			window *= 2; //doubles the size of the re-visitation window
			gap = -gap; //inverts the modifier to the step
		}

	} while (row < nRows);
	//==========================================================================/

	//============================ Wandering Phase =============================//
	row = 0; //Resets the visitation to the first row of the memory matrix
	for (tau = 1; tau <= timeCost; tau++) {
		//Step is approximately half the number of all rows of the memory matrix for an odd tau; otherwise, it is -1
		step = (tau % 2 == 0) ? -1 : nRows / 2 - 1;
		do {
			//Selects a pseudorandom index row*
			//------------------------------------------------------------------------------------------
			rowa = state0.m128i_u64[0] & (unsigned int)(nRows - 1);  //(USE THIS IF nRows IS A POWER OF 2)
																	 //rowa = state0 % nRows; //(USE THIS FOR THE "GENERIC" CASE)
																	 //------------------------------------------------------------------------------------------

																	 //Performs a reduced-round duplexing operation over M[row*] XOR M[prev], updating both M[row*] and M[row]
			ptrWordIn = memMatrix[prev]; //In Lyra2: pointer to prev
			__m128i* ptrWordInOut = memMatrix[rowa]; //In Lyra2: pointer to row*
			ptrWordOut = memMatrix[row]; //In Lyra2: pointer to row

			for (i = 0; i < nCols; i++) {

				//Absorbing "M[prev] [+] M[row*]"
				state0 = _mm_xor_si128(state0, _mm_add_epi64(ptrWordIn[0], ptrWordInOut[0]));
				state1 = _mm_xor_si128(state1, _mm_add_epi64(ptrWordIn[1], ptrWordInOut[1]));
				state2 = _mm_xor_si128(state2, _mm_add_epi64(ptrWordIn[2], ptrWordInOut[2]));
				state3 = _mm_xor_si128(state3, _mm_add_epi64(ptrWordIn[3], ptrWordInOut[3]));
				state4 = _mm_xor_si128(state4, _mm_add_epi64(ptrWordIn[4], ptrWordInOut[4]));
				state5 = _mm_xor_si128(state5, _mm_add_epi64(ptrWordIn[5], ptrWordInOut[5]));

				//Applies the reduced-round transformation f to the sponge's state
				reducedBlake2bLyra_SSSE3(state);

				//M[rowOut][col] = M[rowOut][col] XOR rand
				ptrWordOut[0] = _mm_xor_si128(ptrWordOut[0], state0);
				ptrWordOut[1] = _mm_xor_si128(ptrWordOut[1], state1);
				ptrWordOut[2] = _mm_xor_si128(ptrWordOut[2], state2);
				ptrWordOut[3] = _mm_xor_si128(ptrWordOut[3], state3);
				ptrWordOut[4] = _mm_xor_si128(ptrWordOut[4], state4);
				ptrWordOut[5] = _mm_xor_si128(ptrWordOut[5], state5);

				//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
				ptrWordInOut[0] = _mm_xor_si128(ptrWordInOut[0], _mm_alignr_epi8(state0, state5, 8));
				ptrWordInOut[1] = _mm_xor_si128(ptrWordInOut[1], _mm_alignr_epi8(state1, state0, 8));
				ptrWordInOut[2] = _mm_xor_si128(ptrWordInOut[2], _mm_alignr_epi8(state2, state1, 8));
				ptrWordInOut[3] = _mm_xor_si128(ptrWordInOut[3], _mm_alignr_epi8(state3, state2, 8));
				ptrWordInOut[4] = _mm_xor_si128(ptrWordInOut[4], _mm_alignr_epi8(state4, state3, 8));
				ptrWordInOut[5] = _mm_xor_si128(ptrWordInOut[5], _mm_alignr_epi8(state5, state4, 8));

				//Goes to next block
				ptrWordOut += BLOCK_LEN_XMM;
				ptrWordInOut += BLOCK_LEN_XMM;
				ptrWordIn += BLOCK_LEN_XMM;
			}
			//update prev: it now points to the last row ever computed
			prev = row;

			//updates row: goes to the next row to be computed
			//------------------------------------------------------------------------------------------
			row = (row + step) & (unsigned int)(nRows - 1); //(USE THIS IF nRows IS A POWER OF 2)
															//row = (row + step) % nRows; //(USE THIS FOR THE "GENERIC" CASE)
															//------------------------------------------------------------------------------------------

		} while (row != 0);
	}


	//============================ Wrap-up Phase ===============================//
	//XORs the first BLOCK_LEN_INT64 words of "in" with the current state
	state0 = _mm_xor_si128(state0, memMatrix[rowa][0]);
	state1 = _mm_xor_si128(state1, memMatrix[rowa][1]);
	state2 = _mm_xor_si128(state2, memMatrix[rowa][2]);
	state3 = _mm_xor_si128(state3, memMatrix[rowa][3]);
	state4 = _mm_xor_si128(state4, memMatrix[rowa][4]);
	state5 = _mm_xor_si128(state5, memMatrix[rowa][5]);

	//Applies the transformation f to the sponge's state
	blake2bLyra_SSSE3(state);


	//Squeezes the key
	int64_t fullBlocks = kLen / BLOCK_LEN_BYTES;
	__m128i *ptr = (__m128i*)K;
	//Squeezes full blocks
	for (i = 0; i < fullBlocks; i++) {
		_mm_storeu_si128(ptr + 0, state0);
		_mm_storeu_si128(ptr + 1, state1);
		_mm_storeu_si128(ptr + 2, state2);
		_mm_storeu_si128(ptr + 3, state3);
		_mm_storeu_si128(ptr + 4, state4);
		_mm_storeu_si128(ptr + 5, state5);
		blake2bLyra_SSSE3(state);
		ptr += BLOCK_LEN_XMM;
	}

	//Squeezes remaining bytes
	int remain = kLen % BLOCK_LEN_BYTES;
	if (remain > 0) _mm_storeu_si128(ptr + 0, state0);
	if (remain > 16) _mm_storeu_si128(ptr + 1, state1);
	if (remain > 32) _mm_storeu_si128(ptr + 2, state2);
	if (remain > 48) _mm_storeu_si128(ptr + 3, state3);
	if (remain > 64) _mm_storeu_si128(ptr + 4, state4);
	if (remain > 80) _mm_storeu_si128(ptr + 5, state5);

	//========================= Freeing the memory =============================//
	free(memMatrix);

	return 0;
}
#else

int LYRA2_SSE2(void *K, int64_t kLen, const void *pwd, int32_t pwdlen, const void *salt, int32_t saltlen, int64_t timeCost, const int16_t nRows, const int16_t nCols, __m128i *wholeMatrix)
{
	//============================= Basic variables ============================//
	int64_t row = 2; //index of row to be processed
	int64_t prev = 1; //index of prev (last row ever computed/modified)
	int64_t rowa = 0; //index of row* (a previous row, deterministically picked during Setup and randomly picked while Wandering)
	int64_t tau; //Time Loop iterator
	int64_t step = 1; //Visitation step (used during Setup and Wandering phases)
	int64_t window = 2; //Visitation window (used to define which rows can be revisited during Setup)
	int64_t gap = 1; //Modifier to the step, assuming the values 1 or -1
	int64_t i; //auxiliary iteration counter
	int64_t v64; // 64bit var for memcpy
	//==========================================================================/

	//========== Initializing the Memory Matrix and pointers to it =============//
	//Tries to allocate enough space for the whole memory matrix

	const int64_t ROW_LEN_XMM = BLOCK_LEN_XMM * nCols;
	const int64_t ROW_LEN_BYTES = ROW_LEN_XMM * 16;
	// for Lyra2REv2, nCols = 4, v1 was using 8
	const int64_t BLOCK_LEN = (nCols == 4) ? BLOCK_LEN_BLAKE2_SAFE_INT64 : BLOCK_LEN_BLAKE2_SAFE_BYTES;

	i = (int64_t)ROW_LEN_BYTES * nRows;

	//Allocates pointers to each row of the matrix
	__m128i **memMatrix = malloc(sizeof(__m128i*) * nRows);
	if (memMatrix == NULL) {
		return -1;
	}
	//Places the pointers in the correct positions
	__m128i *ptrWord = wholeMatrix;
	for (i = 0; i < nRows; i++) {
		memMatrix[i] = ptrWord;
		ptrWord += ROW_LEN_XMM;
	}
	//==========================================================================/

	//============= Getting the password + salt + basil padded with 10*1 ===============//
	//OBS.:The memory matrix will temporarily hold the password: not for saving memory,
	//but this ensures that the password copied locally will be overwritten as soon as possible

	//First, we clean enough blocks for the password, salt, basil and padding
	int64_t nBlocksInput = ((saltlen + pwdlen + 6 * sizeof(uint64_t)) / BLOCK_LEN_BLAKE2_SAFE_BYTES) + 1;

	byte *ptrByte = (byte*)wholeMatrix;

	//Prepends the password
	memcpy(ptrByte, pwd, pwdlen);
	ptrByte += pwdlen;

	//Concatenates the salt
	memcpy(ptrByte, salt, saltlen);
	ptrByte += saltlen;

	memset(ptrByte, 0, nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - (saltlen + pwdlen));
	memset((byte*)wholeMatrix + BLOCK_LEN * 8, 0, 64);

	//Concatenates the basil: every integer passed as parameter, in the order they are provided by the interface
	memcpy(ptrByte, &kLen, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = pwdlen;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = saltlen;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = timeCost;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = nRows;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);
	v64 = nCols;
	memcpy(ptrByte, &v64, sizeof(int64_t));
	ptrByte += sizeof(uint64_t);

	//Now comes the padding
	*ptrByte = 0x80; //first byte of padding: right after the password
	ptrByte = (byte*)wholeMatrix; //resets the pointer to the start of the memory matrix
	ptrByte += nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - 1; //sets the pointer to the correct position: end of incomplete block
	*ptrByte ^= 0x01; //last byte of padding: at the end of the last incomplete block
	//==========================================================================/

	//======================= Initializing the Sponge State ====================//
	//Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)
	__m128i state0, state1, state2, state3, state4, state5, state6, state7;
	//First 512 bis are zeros
	state0 = state1 = state2 = state3 = _mm_setzero_si128();
	//Remainder BLOCK_LEN_BLAKE2_SAFE_BYTES are reserved to the IV
	state4 = _mm_setr_epi32(0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85);
	state5 = _mm_setr_epi32(0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a);
	state6 = _mm_setr_epi32(0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c);
	state7 = _mm_setr_epi32(0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19);
	//==========================================================================/

	//================================ Setup Phase =============================//
	//Absorbing salt, password and basil: this is the only place in which the block length is hard-coded to 512 bits
	ptrWord = wholeMatrix;
	for (i = 0; i < nBlocksInput; i++) {
		//XORs the first BLOCK_LEN_BLAKE2_SAFE_INT64 words of "in" with the current state
		state0 = _mm_xor_si128(state0, ptrWord[0]);
		state1 = _mm_xor_si128(state1, ptrWord[1]);
		state2 = _mm_xor_si128(state2, ptrWord[2]);
		state3 = _mm_xor_si128(state3, ptrWord[3]);
	
		//Applies the transformation f to the sponge's state
		blake2bLyra_SSE2(state);

		ptrWord += BLOCK_LEN >> 1; //goes to next block of pad(pwd || salt || basil)
	}

	//Initializes M[0] and M[1]
	ptrWord = memMatrix[0] + (nCols - 1)*BLOCK_LEN_XMM; //In Lyra2: pointer to M[0][C-1]
														//M[row][C-1-col] = H.reduced_squeeze()
	for (i = 0; i < nCols; i++) {
		ptrWord[0] = state0;
		ptrWord[1] = state1;
		ptrWord[2] = state2;
		ptrWord[3] = state3;
		ptrWord[4] = state4;
		ptrWord[5] = state5;

		//Goes to next block (column) that will receive the squeezed data
		ptrWord -= BLOCK_LEN_XMM;

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSE2(state);
	}

	__m128i* ptrWordIn = memMatrix[0];				//In Lyra2: pointer to prev
	__m128i* ptrWordOut = memMatrix[1] + (nCols - 1)*BLOCK_LEN_XMM; //In Lyra2: pointer to row

	for (i = 0; i < nCols; i++) {

		//Absorbing "M[prev][col]"
		state0 = _mm_xor_si128(state0, ptrWordIn[0]);
		state1 = _mm_xor_si128(state1, ptrWordIn[1]);
		state2 = _mm_xor_si128(state2, ptrWordIn[2]);
		state3 = _mm_xor_si128(state3, ptrWordIn[3]);
		state4 = _mm_xor_si128(state4, ptrWordIn[4]);
		state5 = _mm_xor_si128(state5, ptrWordIn[5]);

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSE2(state);

		//M[row][C-1-col] = M[prev][col] XOR rand
		ptrWordOut[0] = _mm_xor_si128(ptrWordIn[0], state0);
		ptrWordOut[1] = _mm_xor_si128(ptrWordIn[1], state1);
		ptrWordOut[2] = _mm_xor_si128(ptrWordIn[2], state2);
		ptrWordOut[3] = _mm_xor_si128(ptrWordIn[3], state3);
		ptrWordOut[4] = _mm_xor_si128(ptrWordIn[4], state4);
		ptrWordOut[5] = _mm_xor_si128(ptrWordIn[5], state5);

		//Input: next column (i.e., next block in sequence)
		ptrWordIn += BLOCK_LEN_XMM;
		//Output: goes to previous column
		ptrWordOut -= BLOCK_LEN_XMM;
	}

	do {
		//M[row] = rand; //M[row*] = M[row*] XOR rotW(rand)
		ptrWordIn = memMatrix[prev];				//In Lyra2: pointer to prev
		__m128i* ptrWordInOut = memMatrix[rowa];				//In Lyra2: pointer to row*
		ptrWordOut = memMatrix[row] + (nCols - 1)*BLOCK_LEN_XMM; //In Lyra2: pointer to row

		for (i = 0; i < nCols; i++) {

			//Absorbing "M[prev] [+] M[row*]"
			state0 = _mm_xor_si128(state0, _mm_add_epi64(ptrWordIn[0], ptrWordInOut[0]));
			state1 = _mm_xor_si128(state1, _mm_add_epi64(ptrWordIn[1], ptrWordInOut[1]));
			state2 = _mm_xor_si128(state2, _mm_add_epi64(ptrWordIn[2], ptrWordInOut[2]));
			state3 = _mm_xor_si128(state3, _mm_add_epi64(ptrWordIn[3], ptrWordInOut[3]));
			state4 = _mm_xor_si128(state4, _mm_add_epi64(ptrWordIn[4], ptrWordInOut[4]));
			state5 = _mm_xor_si128(state5, _mm_add_epi64(ptrWordIn[5], ptrWordInOut[5]));

			//Applies the reduced-round transformation f to the sponge's state
			reducedBlake2bLyra_SSE2(state);

			//M[row][col] = M[prev][col] XOR rand
			ptrWordOut[0] = _mm_xor_si128(ptrWordIn[0], state0);
			ptrWordOut[1] = _mm_xor_si128(ptrWordIn[1], state1);
			ptrWordOut[2] = _mm_xor_si128(ptrWordIn[2], state2);
			ptrWordOut[3] = _mm_xor_si128(ptrWordIn[3], state3);
			ptrWordOut[4] = _mm_xor_si128(ptrWordIn[4], state4);
			ptrWordOut[5] = _mm_xor_si128(ptrWordIn[5], state5);

			//M[row*][col] = M[row*][col] XOR rotW(rand)
			ptrWordInOut[0] = _mm_xor_si128(ptrWordInOut[0], _mm_or_si128(_mm_slli_si128(state0, 8), _mm_srli_si128(state5, 8)));
			ptrWordInOut[1] = _mm_xor_si128(ptrWordInOut[1], _mm_or_si128(_mm_slli_si128(state1, 8), _mm_srli_si128(state0, 8)));
			ptrWordInOut[2] = _mm_xor_si128(ptrWordInOut[2], _mm_or_si128(_mm_slli_si128(state2, 8), _mm_srli_si128(state1, 8)));
			ptrWordInOut[3] = _mm_xor_si128(ptrWordInOut[3], _mm_or_si128(_mm_slli_si128(state3, 8), _mm_srli_si128(state2, 8)));
			ptrWordInOut[4] = _mm_xor_si128(ptrWordInOut[4], _mm_or_si128(_mm_slli_si128(state4, 8), _mm_srli_si128(state3, 8)));
			ptrWordInOut[5] = _mm_xor_si128(ptrWordInOut[5], _mm_or_si128(_mm_slli_si128(state5, 8), _mm_srli_si128(state4, 8)));

			//Inputs: next column (i.e., next block in sequence)
			ptrWordInOut += BLOCK_LEN_XMM;
			ptrWordIn += BLOCK_LEN_XMM;
			//Output: goes to previous column
			ptrWordOut -= BLOCK_LEN_XMM;
		}

		//updates the value of row* (deterministically picked during Setup))
		rowa = (rowa + step) & (window - 1);
		//update prev: it now points to the last row ever computed
		prev = row;
		//updates row: goes to the next row to be computed
		row++;

		//Checks if all rows in the window where visited.
		if (rowa == 0) {
			step = window + gap; //changes the step: approximately doubles its value
			window *= 2; //doubles the size of the re-visitation window
			gap = -gap; //inverts the modifier to the step
		}

	} while (row < nRows);
	//==========================================================================/

	//============================ Wandering Phase =============================//
	row = 0; //Resets the visitation to the first row of the memory matrix
	for (tau = 1; tau <= timeCost; tau++) {
		//Step is approximately half the number of all rows of the memory matrix for an odd tau; otherwise, it is -1
		step = (tau % 2 == 0) ? -1 : nRows / 2 - 1;
		do {
			//Selects a pseudorandom index row*
			//------------------------------------------------------------------------------------------
			rowa = state0.m128i_u64[0] & (unsigned int)(nRows - 1);  //(USE THIS IF nRows IS A POWER OF 2)
																	 //rowa = state0 % nRows; //(USE THIS FOR THE "GENERIC" CASE)
			//------------------------------------------------------------------------------------------

			//Performs a reduced-round duplexing operation over M[row*] XOR M[prev], updating both M[row*] and M[row]
			ptrWordIn = memMatrix[prev]; //In Lyra2: pointer to prev
			__m128i* ptrWordInOut = memMatrix[rowa]; //In Lyra2: pointer to row*
			ptrWordOut = memMatrix[row]; //In Lyra2: pointer to row

			for (i = 0; i < nCols; i++) {

				//Absorbing "M[prev] [+] M[row*]"
				state0 = _mm_xor_si128(state0, _mm_add_epi64(ptrWordIn[0], ptrWordInOut[0]));
				state1 = _mm_xor_si128(state1, _mm_add_epi64(ptrWordIn[1], ptrWordInOut[1]));
				state2 = _mm_xor_si128(state2, _mm_add_epi64(ptrWordIn[2], ptrWordInOut[2]));
				state3 = _mm_xor_si128(state3, _mm_add_epi64(ptrWordIn[3], ptrWordInOut[3]));
				state4 = _mm_xor_si128(state4, _mm_add_epi64(ptrWordIn[4], ptrWordInOut[4]));
				state5 = _mm_xor_si128(state5, _mm_add_epi64(ptrWordIn[5], ptrWordInOut[5]));

				//Applies the reduced-round transformation f to the sponge's state
				reducedBlake2bLyra_SSE2(state);

				//M[rowOut][col] = M[rowOut][col] XOR rand
				ptrWordOut[0] = _mm_xor_si128(ptrWordOut[0], state0);
				ptrWordOut[1] = _mm_xor_si128(ptrWordOut[1], state1);
				ptrWordOut[2] = _mm_xor_si128(ptrWordOut[2], state2);
				ptrWordOut[3] = _mm_xor_si128(ptrWordOut[3], state3);
				ptrWordOut[4] = _mm_xor_si128(ptrWordOut[4], state4);
				ptrWordOut[5] = _mm_xor_si128(ptrWordOut[5], state5);

				//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
				ptrWordInOut[0] = _mm_xor_si128(ptrWordInOut[0], _mm_or_si128(_mm_slli_si128(state0, 8), _mm_srli_si128(state5, 8)));
				ptrWordInOut[1] = _mm_xor_si128(ptrWordInOut[1], _mm_or_si128(_mm_slli_si128(state1, 8), _mm_srli_si128(state0, 8)));
				ptrWordInOut[2] = _mm_xor_si128(ptrWordInOut[2], _mm_or_si128(_mm_slli_si128(state2, 8), _mm_srli_si128(state1, 8)));
				ptrWordInOut[3] = _mm_xor_si128(ptrWordInOut[3], _mm_or_si128(_mm_slli_si128(state3, 8), _mm_srli_si128(state2, 8)));
				ptrWordInOut[4] = _mm_xor_si128(ptrWordInOut[4], _mm_or_si128(_mm_slli_si128(state4, 8), _mm_srli_si128(state3, 8)));
				ptrWordInOut[5] = _mm_xor_si128(ptrWordInOut[5], _mm_or_si128(_mm_slli_si128(state5, 8), _mm_srli_si128(state4, 8)));

				//Goes to next block
				ptrWordOut += BLOCK_LEN_XMM;
				ptrWordInOut += BLOCK_LEN_XMM;
				ptrWordIn += BLOCK_LEN_XMM;
			}
			//update prev: it now points to the last row ever computed
			prev = row;

			//updates row: goes to the next row to be computed
			//------------------------------------------------------------------------------------------
			row = (row + step) & (unsigned int)(nRows - 1); //(USE THIS IF nRows IS A POWER OF 2)
															//row = (row + step) % nRows; //(USE THIS FOR THE "GENERIC" CASE)
			//------------------------------------------------------------------------------------------

		} while (row != 0);
	}


	//============================ Wrap-up Phase ===============================//
	//XORs the first BLOCK_LEN_INT64 words of "in" with the current state
	state0 = _mm_xor_si128(state0, memMatrix[rowa][0]);
	state1 = _mm_xor_si128(state1, memMatrix[rowa][1]);
	state2 = _mm_xor_si128(state2, memMatrix[rowa][2]);
	state3 = _mm_xor_si128(state3, memMatrix[rowa][3]);
	state4 = _mm_xor_si128(state4, memMatrix[rowa][4]);
	state5 = _mm_xor_si128(state5, memMatrix[rowa][5]);

	//Applies the transformation f to the sponge's state
	blake2bLyra_SSE2(state);


	//Squeezes the key
	int64_t fullBlocks = kLen / BLOCK_LEN_BYTES;
	__m128i *ptr = (__m128i*)K;
	//Squeezes full blocks
	for (i = 0; i < fullBlocks; i++) {
		_mm_storeu_si128(ptr + 0, state0);
		_mm_storeu_si128(ptr + 1, state1);
		_mm_storeu_si128(ptr + 2, state2);
		_mm_storeu_si128(ptr + 3, state3);
		_mm_storeu_si128(ptr + 4, state4);
		_mm_storeu_si128(ptr + 5, state5);
		blake2bLyra_SSE2(state);
		ptr += BLOCK_LEN_XMM;
	}

	//Squeezes remaining bytes
	int remain = kLen % BLOCK_LEN_BYTES;
	if (remain > 0) _mm_storeu_si128(ptr + 0, state0);
	if (remain > 16) _mm_storeu_si128(ptr + 1, state1);
	if (remain > 32) _mm_storeu_si128(ptr + 2, state2);
	if (remain > 48) _mm_storeu_si128(ptr + 3, state3);
	if (remain > 64) _mm_storeu_si128(ptr + 4, state4);
	if (remain > 80) _mm_storeu_si128(ptr + 5, state5);

	//========================= Freeing the memory =============================//
	free(memMatrix);

	return 0;
}
#endif

#endif

/**
* Executes Lyra2 based on the G function from Blake2b. This version supports salts and passwords
* whose combined length is smaller than the size of the memory matrix, (i.e., (nRows x nCols x b) bits,
* where "b" is the underlying sponge's bitrate). In this implementation, the "basil" is composed by all
* integer parameters (treated as type "unsigned int") in the order they are provided, plus the value
* of nCols, (i.e., basil = kLen || pwdlen || saltlen || timeCost || nRows || nCols).
*
* @param K The derived key to be output by the algorithm
* @param kLen Desired key length
* @param pwd User password
* @param pwdlen Password length
* @param salt Salt
* @param saltlen Salt length
* @param timeCost Parameter to determine the processing time (T)
* @param nRows Number or rows of the memory matrix (R)
* @param nCols Number of columns of the memory matrix (C)
*
* @return 0 if the key is generated correctly; -1 if there is an error (usually due to lack of memory for allocation)
*/
#ifndef SSE
int LYRA2v2(void *K, const void *pwd, __m256i *wholeMatrix)
{
	//============================= Basic variables ============================//
	int64_t rowa = 0; //index of row* (a previous row, deterministically picked during Setup and randomly picked while Wandering)
	int64_t i; //auxiliary iteration counter
	//==========================================================================/
	
	//========== Initializing the Memory Matrix and pointers to it =============//
	//Allocates pointers to each row of the matrix
	__m256i* memMatrix[4];

	//Places the pointers in the correct positions
	memMatrix[0] = wholeMatrix + 0;
	memMatrix[1] = wholeMatrix + 12;
	memMatrix[2] = wholeMatrix + 24;
	memMatrix[3] = wholeMatrix + 36;
	//==========================================================================/

	//======================= Initializing the Sponge State ====================//
	//Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)
	register __m256i state0, state1, state2, state3;
	//Prepends the password
	//Concatenates the salt
	state0 = state1 = _mm256_lddqu_si256((__m256i*)pwd);
	//Remainder BLOCK_LEN_BLAKE2_SAFE_BYTES are reserved to the IV
	state2 = _mm256_setr_epi64x(0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL);
	state3 = _mm256_setr_epi64x(0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL);

	//Applies the transformation f to the sponge's state
	blake2bLyra(state);

	state0 = _mm256_xor_si256(state0, _mm256_setr_epi64x(0x20ULL, 0x20ULL, 0x20ULL, 1ULL));
	state1 = _mm256_xor_si256(state1, _mm256_setr_epi64x(0x04ULL, 0x04ULL, 0x80ULL, 0x0100000000000000ULL));

	//Applies the transformation f to the sponge's state
	blake2bLyra(state);

	//==========================================================================/

	//================================ Setup Phase =============================//
	//Initializes M[0] and M[1]
	for (i = 9; i >= 0; i -= 3) {
		memMatrix[0][i + 0] = state0;
		memMatrix[0][i + 1] = state1;
		memMatrix[0][i + 2] = state2;

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra(state);
	}

	int64_t j;
	for (i = 0, j = 9; i < 12; i += 3, j -= 3) {

		//Absorbing "M[prev][col]"
		state0 = _mm256_xor_si256(state0, memMatrix[0][i + 0]);
		state1 = _mm256_xor_si256(state1, memMatrix[0][i + 1]);
		state2 = _mm256_xor_si256(state2, memMatrix[0][i + 2]);

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra(state);

		//M[row][C-1-col] = M[prev][col] XOR rand
		memMatrix[1][j + 0] = _mm256_xor_si256(memMatrix[0][i + 0], state0);
		memMatrix[1][j + 1] = _mm256_xor_si256(memMatrix[0][i + 1], state1);
		memMatrix[1][j + 2] = _mm256_xor_si256(memMatrix[0][i + 2], state2);
	}

	for (i = 0, j = 9; i < 12; i += 3, j -= 3) {

		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm256_xor_si256(state0, _mm256_add_epi64(memMatrix[1][i + 0], memMatrix[0][i + 0]));
		state1 = _mm256_xor_si256(state1, _mm256_add_epi64(memMatrix[1][i + 1], memMatrix[0][i + 1]));
		state2 = _mm256_xor_si256(state2, _mm256_add_epi64(memMatrix[1][i + 2], memMatrix[0][i + 2]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra(state);

		//M[row][col] = M[prev][col] XOR rand
		memMatrix[2][j + 0] = _mm256_xor_si256(memMatrix[1][i + 0], state0);
		memMatrix[2][j + 1] = _mm256_xor_si256(memMatrix[1][i + 1], state1);
		memMatrix[2][j + 2] = _mm256_xor_si256(memMatrix[1][i + 2], state2);

		//M[row*][col] = M[row*][col] XOR rotW(rand)
		memMatrix[0][i + 0] = _mm256_xor_si256(memMatrix[0][i + 0], _mm256_alignr_epi8(state0, _mm256_permute2x128_si256(state0, state2, 0x03), 8));
		memMatrix[0][i + 1] = _mm256_xor_si256(memMatrix[0][i + 1], _mm256_alignr_epi8(state1, _mm256_permute2x128_si256(state1, state0, 0x03), 8));
		memMatrix[0][i + 2] = _mm256_xor_si256(memMatrix[0][i + 2], _mm256_alignr_epi8(state2, _mm256_permute2x128_si256(state2, state1, 0x03), 8));
	}

	for (i = 0, j = 9; i < 12; i += 3, j -= 3) {

		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm256_xor_si256(state0, _mm256_add_epi64(memMatrix[2][i + 0], memMatrix[1][i + 0]));
		state1 = _mm256_xor_si256(state1, _mm256_add_epi64(memMatrix[2][i + 1], memMatrix[1][i + 1]));
		state2 = _mm256_xor_si256(state2, _mm256_add_epi64(memMatrix[2][i + 2], memMatrix[1][i + 2]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra(state);

		//M[row][col] = M[prev][col] XOR rand
		memMatrix[3][j + 0] = _mm256_xor_si256(memMatrix[2][i + 0], state0);
		memMatrix[3][j + 1] = _mm256_xor_si256(memMatrix[2][i + 1], state1);
		memMatrix[3][j + 2] = _mm256_xor_si256(memMatrix[2][i + 2], state2);

		//M[row*][col] = M[row*][col] XOR rotW(rand)
		memMatrix[1][i + 0] = _mm256_xor_si256(memMatrix[1][i + 0], _mm256_alignr_epi8(state0, _mm256_permute2x128_si256(state0, state2, 0x03), 8));
		memMatrix[1][i + 1] = _mm256_xor_si256(memMatrix[1][i + 1], _mm256_alignr_epi8(state1, _mm256_permute2x128_si256(state1, state0, 0x03), 8));
		memMatrix[1][i + 2] = _mm256_xor_si256(memMatrix[1][i + 2], _mm256_alignr_epi8(state2, _mm256_permute2x128_si256(state2, state1, 0x03), 8));
	}

	//============================ Wandering Phase =============================//
	rowa = state0.m256i_u64[0] & 3;  //(USE THIS IF nRows IS A POWER OF 2)
	for (i = 0; i < 12; i += 3) {
		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm256_xor_si256(state0, _mm256_add_epi64(memMatrix[3][i + 0], memMatrix[rowa][i + 0]));
		state1 = _mm256_xor_si256(state1, _mm256_add_epi64(memMatrix[3][i + 1], memMatrix[rowa][i + 1]));
		state2 = _mm256_xor_si256(state2, _mm256_add_epi64(memMatrix[3][i + 2], memMatrix[rowa][i + 2]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra(state);

		//M[rowOut][col] = M[rowOut][col] XOR rand
		memMatrix[0][i + 0] = _mm256_xor_si256(memMatrix[0][i + 0], state0);
		memMatrix[0][i + 1] = _mm256_xor_si256(memMatrix[0][i + 1], state1);
		memMatrix[0][i + 2] = _mm256_xor_si256(memMatrix[0][i + 2], state2);

		//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
		memMatrix[rowa][i + 0] = _mm256_xor_si256(memMatrix[rowa][i + 0], _mm256_alignr_epi8(state0, _mm256_permute2x128_si256(state0, state2, 0x03), 8));
		memMatrix[rowa][i + 1] = _mm256_xor_si256(memMatrix[rowa][i + 1], _mm256_alignr_epi8(state1, _mm256_permute2x128_si256(state1, state0, 0x03), 8));
		memMatrix[rowa][i + 2] = _mm256_xor_si256(memMatrix[rowa][i + 2], _mm256_alignr_epi8(state2, _mm256_permute2x128_si256(state2, state1, 0x03), 8));
	}

	rowa = state0.m256i_u64[0] & 3;  //(USE THIS IF nRows IS A POWER OF 2)
	for (i = 0; i < 12; i += 3) {
		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm256_xor_si256(state0, _mm256_add_epi64(memMatrix[0][i + 0], memMatrix[rowa][i + 0]));
		state1 = _mm256_xor_si256(state1, _mm256_add_epi64(memMatrix[0][i + 1], memMatrix[rowa][i + 1]));
		state2 = _mm256_xor_si256(state2, _mm256_add_epi64(memMatrix[0][i + 2], memMatrix[rowa][i + 2]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra(state);

		//M[rowOut][col] = M[rowOut][col] XOR rand
		memMatrix[1][i + 0] = _mm256_xor_si256(memMatrix[1][i + 0], state0);
		memMatrix[1][i + 1] = _mm256_xor_si256(memMatrix[1][i + 1], state1);
		memMatrix[1][i + 2] = _mm256_xor_si256(memMatrix[1][i + 2], state2);

		//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
		memMatrix[rowa][i + 0] = _mm256_xor_si256(memMatrix[rowa][i + 0], _mm256_alignr_epi8(state0, _mm256_permute2x128_si256(state0, state2, 0x03), 8));
		memMatrix[rowa][i + 1] = _mm256_xor_si256(memMatrix[rowa][i + 1], _mm256_alignr_epi8(state1, _mm256_permute2x128_si256(state1, state0, 0x03), 8));
		memMatrix[rowa][i + 2] = _mm256_xor_si256(memMatrix[rowa][i + 2], _mm256_alignr_epi8(state2, _mm256_permute2x128_si256(state2, state1, 0x03), 8));
	}

	rowa = state0.m256i_u64[0] & 3;  //(USE THIS IF nRows IS A POWER OF 2)
	for (i = 0; i < 12; i += 3) {
		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm256_xor_si256(state0, _mm256_add_epi64(memMatrix[1][i + 0], memMatrix[rowa][i + 0]));
		state1 = _mm256_xor_si256(state1, _mm256_add_epi64(memMatrix[1][i + 1], memMatrix[rowa][i + 1]));
		state2 = _mm256_xor_si256(state2, _mm256_add_epi64(memMatrix[1][i + 2], memMatrix[rowa][i + 2]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra(state);

		//M[rowOut][col] = M[rowOut][col] XOR rand
		memMatrix[2][i + 0] = _mm256_xor_si256(memMatrix[2][i + 0], state0);
		memMatrix[2][i + 1] = _mm256_xor_si256(memMatrix[2][i + 1], state1);
		memMatrix[2][i + 2] = _mm256_xor_si256(memMatrix[2][i + 2], state2);

		//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
		memMatrix[rowa][i + 0] = _mm256_xor_si256(memMatrix[rowa][i + 0], _mm256_alignr_epi8(state0, _mm256_permute2x128_si256(state0, state2, 0x03), 8));
		memMatrix[rowa][i + 1] = _mm256_xor_si256(memMatrix[rowa][i + 1], _mm256_alignr_epi8(state1, _mm256_permute2x128_si256(state1, state0, 0x03), 8));
		memMatrix[rowa][i + 2] = _mm256_xor_si256(memMatrix[rowa][i + 2], _mm256_alignr_epi8(state2, _mm256_permute2x128_si256(state2, state1, 0x03), 8));
	}

	rowa = state0.m256i_u64[0] & 3;  //(USE THIS IF nRows IS A POWER OF 2)

	register __m256i buf0, buf1, buf2;
	buf0 = memMatrix[rowa][0];
	buf1 = memMatrix[rowa][1];
	buf2 = memMatrix[rowa][2];

	//Absorbing "M[prev] [+] M[row*]"
	state0 = _mm256_xor_si256(state0, _mm256_add_epi64(memMatrix[2][0], buf0));
	state1 = _mm256_xor_si256(state1, _mm256_add_epi64(memMatrix[2][1], buf1));
	state2 = _mm256_xor_si256(state2, _mm256_add_epi64(memMatrix[2][2], buf2));

	//Applies the reduced-round transformation f to the sponge's state
	reducedBlake2bLyra(state);

	//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
	buf0 = _mm256_xor_si256(buf0, _mm256_alignr_epi8(state0, _mm256_permute2x128_si256(state0, state2, 0x03), 8));
	buf1 = _mm256_xor_si256(buf1, _mm256_alignr_epi8(state1, _mm256_permute2x128_si256(state1, state0, 0x03), 8));
	buf2 = _mm256_xor_si256(buf2, _mm256_alignr_epi8(state2, _mm256_permute2x128_si256(state2, state1, 0x03), 8));

	if (rowa == 3)
	{
		//M[rowOut][col] = M[rowOut][col] XOR rand
		buf0 = _mm256_xor_si256(buf0, state0);
		buf1 = _mm256_xor_si256(buf1, state1);
		buf2 = _mm256_xor_si256(buf2, state2);
	}

	for (i = 3; i < 12; i += 3) {
		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm256_xor_si256(state0, _mm256_add_epi64(memMatrix[2][i + 0], memMatrix[rowa][i + 0]));
		state1 = _mm256_xor_si256(state1, _mm256_add_epi64(memMatrix[2][i + 1], memMatrix[rowa][i + 1]));
		state2 = _mm256_xor_si256(state2, _mm256_add_epi64(memMatrix[2][i + 2], memMatrix[rowa][i + 2]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra(state);
	}

	//============================ Wrap-up Phase ===============================//
	//XORs the first BLOCK_LEN_INT64 words of "in" with the current state
	state0 = _mm256_xor_si256(state0, buf0);
	state1 = _mm256_xor_si256(state1, buf1);
	state2 = _mm256_xor_si256(state2, buf2);

	//Applies the transformation f to the sponge's state
	blake2bLyra(state);

	//Squeezes the key
	_mm256_storeu_si256((__m256i*)K, state0);

	//========================= Freeing the memory =============================//
	_mm256_zeroupper();

	return 0;
}
#else
#ifdef SSE3
int LYRA2v2_SSSE3(void *K, const void *pwd, __m128i *wholeMatrix)
{
	//============================= Basic variables ============================//
	int64_t rowa = 0; //index of row* (a previous row, deterministically picked during Setup and randomly picked while Wandering)
	int64_t i; //auxiliary iteration counter
	//==========================================================================/

	//========== Initializing the Memory Matrix and pointers to it =============//
	//Allocates pointers to each row of the matrix
	__m128i* memMatrix[4];

	//Places the pointers in the correct positions
	memMatrix[0] = wholeMatrix + 0;
	memMatrix[1] = wholeMatrix + 24;
	memMatrix[2] = wholeMatrix + 48;
	memMatrix[3] = wholeMatrix + 72;
	//==========================================================================/

	//======================= Initializing the Sponge State ====================//
	//Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)
	__m128i state0, state1, state2, state3, state4, state5, state6, state7;
	//Prepends the password
	//Concatenates the salt
	state0 = state2 = _mm_loadu_si128((__m128i*)pwd + 0);
	state1 = state3 = _mm_loadu_si128((__m128i*)pwd + 1);
	//Remainder BLOCK_LEN_BLAKE2_SAFE_BYTES are reserved to the IV
	state4 = _mm_setr_epi32(0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85);
	state5 = _mm_setr_epi32(0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a);
	state6 = _mm_setr_epi32(0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c);
	state7 = _mm_setr_epi32(0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19);

	//Applies the transformation f to the sponge's state
	blake2bLyra_SSSE3(state);

	state0 = _mm_xor_si128(state0, _mm_setr_epi32(0x20, 0x00, 0x20, 0x00));
	state1 = _mm_xor_si128(state1, _mm_setr_epi32(0x20, 0x00, 0x01, 0x00));
	state2 = _mm_xor_si128(state2, _mm_setr_epi32(0x04, 0x00, 0x04, 0x00));
	state3 = _mm_xor_si128(state3, _mm_setr_epi32(0x80, 0x00, 0x00, 0x01000000));

	//Applies the transformation f to the sponge's state
	blake2bLyra_SSSE3(state);

	//==========================================================================/

	//================================ Setup Phase =============================//
	//Initializes M[0] and M[1]
	for (i = 18; i >= 0; i -= 6) {
		memMatrix[0][i + 0] = state0;
		memMatrix[0][i + 1] = state1;
		memMatrix[0][i + 2] = state2;
		memMatrix[0][i + 3] = state3;
		memMatrix[0][i + 4] = state4;
		memMatrix[0][i + 5] = state5;

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSSE3(state);
	}

	int64_t j;
	for (i = 0, j = 18; i < 24; i += 6, j -= 6) {

		//Absorbing "M[prev][col]"
		state0 = _mm_xor_si128(state0, memMatrix[0][i + 0]);
		state1 = _mm_xor_si128(state1, memMatrix[0][i + 1]);
		state2 = _mm_xor_si128(state2, memMatrix[0][i + 2]);
		state3 = _mm_xor_si128(state3, memMatrix[0][i + 3]);
		state4 = _mm_xor_si128(state4, memMatrix[0][i + 4]);
		state5 = _mm_xor_si128(state5, memMatrix[0][i + 5]);

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSSE3(state);

		//M[row][C-1-col] = M[prev][col] XOR rand
		memMatrix[1][j + 0] = _mm_xor_si128(memMatrix[0][i + 0], state0);
		memMatrix[1][j + 1] = _mm_xor_si128(memMatrix[0][i + 1], state1);
		memMatrix[1][j + 2] = _mm_xor_si128(memMatrix[0][i + 2], state2);
		memMatrix[1][j + 3] = _mm_xor_si128(memMatrix[0][i + 3], state3);
		memMatrix[1][j + 4] = _mm_xor_si128(memMatrix[0][i + 4], state4);
		memMatrix[1][j + 5] = _mm_xor_si128(memMatrix[0][i + 5], state5);
	}

	for (i = 0, j = 18; i < 24; i += 6, j -= 6) {

		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm_xor_si128(state0, _mm_add_epi64(memMatrix[1][i + 0], memMatrix[0][i + 0]));
		state1 = _mm_xor_si128(state1, _mm_add_epi64(memMatrix[1][i + 1], memMatrix[0][i + 1]));
		state2 = _mm_xor_si128(state2, _mm_add_epi64(memMatrix[1][i + 2], memMatrix[0][i + 2]));
		state3 = _mm_xor_si128(state3, _mm_add_epi64(memMatrix[1][i + 3], memMatrix[0][i + 3]));
		state4 = _mm_xor_si128(state4, _mm_add_epi64(memMatrix[1][i + 4], memMatrix[0][i + 4]));
		state5 = _mm_xor_si128(state5, _mm_add_epi64(memMatrix[1][i + 5], memMatrix[0][i + 5]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSSE3(state);

		//M[row][col] = M[prev][col] XOR rand
		memMatrix[2][j + 0] = _mm_xor_si128(memMatrix[1][i + 0], state0);
		memMatrix[2][j + 1] = _mm_xor_si128(memMatrix[1][i + 1], state1);
		memMatrix[2][j + 2] = _mm_xor_si128(memMatrix[1][i + 2], state2);
		memMatrix[2][j + 3] = _mm_xor_si128(memMatrix[1][i + 3], state3);
		memMatrix[2][j + 4] = _mm_xor_si128(memMatrix[1][i + 4], state4);
		memMatrix[2][j + 5] = _mm_xor_si128(memMatrix[1][i + 5], state5);

		//M[row*][col] = M[row*][col] XOR rotW(rand)
		memMatrix[0][i + 0] = _mm_xor_si128(memMatrix[0][i + 0], _mm_alignr_epi8(state0, state5, 8));
		memMatrix[0][i + 1] = _mm_xor_si128(memMatrix[0][i + 1], _mm_alignr_epi8(state1, state0, 8));
		memMatrix[0][i + 2] = _mm_xor_si128(memMatrix[0][i + 2], _mm_alignr_epi8(state2, state1, 8));
		memMatrix[0][i + 3] = _mm_xor_si128(memMatrix[0][i + 3], _mm_alignr_epi8(state3, state2, 8));
		memMatrix[0][i + 4] = _mm_xor_si128(memMatrix[0][i + 4], _mm_alignr_epi8(state4, state3, 8));
		memMatrix[0][i + 5] = _mm_xor_si128(memMatrix[0][i + 5], _mm_alignr_epi8(state5, state4, 8));
	}

	for (i = 0, j = 18; i < 24; i += 6, j -= 6) {

		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm_xor_si128(state0, _mm_add_epi64(memMatrix[2][i + 0], memMatrix[1][i + 0]));
		state1 = _mm_xor_si128(state1, _mm_add_epi64(memMatrix[2][i + 1], memMatrix[1][i + 1]));
		state2 = _mm_xor_si128(state2, _mm_add_epi64(memMatrix[2][i + 2], memMatrix[1][i + 2]));
		state3 = _mm_xor_si128(state3, _mm_add_epi64(memMatrix[2][i + 3], memMatrix[1][i + 3]));
		state4 = _mm_xor_si128(state4, _mm_add_epi64(memMatrix[2][i + 4], memMatrix[1][i + 4]));
		state5 = _mm_xor_si128(state5, _mm_add_epi64(memMatrix[2][i + 5], memMatrix[1][i + 5]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSSE3(state);

		//M[row][col] = M[prev][col] XOR rand
		memMatrix[3][j + 0] = _mm_xor_si128(memMatrix[2][i + 0], state0);
		memMatrix[3][j + 1] = _mm_xor_si128(memMatrix[2][i + 1], state1);
		memMatrix[3][j + 2] = _mm_xor_si128(memMatrix[2][i + 2], state2);
		memMatrix[3][j + 3] = _mm_xor_si128(memMatrix[2][i + 3], state3);
		memMatrix[3][j + 4] = _mm_xor_si128(memMatrix[2][i + 4], state4);
		memMatrix[3][j + 5] = _mm_xor_si128(memMatrix[2][i + 5], state5);

		//M[row*][col] = M[row*][col] XOR rotW(rand)
		memMatrix[1][i + 0] = _mm_xor_si128(memMatrix[1][i + 0], _mm_alignr_epi8(state0, state5, 8));
		memMatrix[1][i + 1] = _mm_xor_si128(memMatrix[1][i + 1], _mm_alignr_epi8(state1, state0, 8));
		memMatrix[1][i + 2] = _mm_xor_si128(memMatrix[1][i + 2], _mm_alignr_epi8(state2, state1, 8));
		memMatrix[1][i + 3] = _mm_xor_si128(memMatrix[1][i + 3], _mm_alignr_epi8(state3, state2, 8));
		memMatrix[1][i + 4] = _mm_xor_si128(memMatrix[1][i + 4], _mm_alignr_epi8(state4, state3, 8));
		memMatrix[1][i + 5] = _mm_xor_si128(memMatrix[1][i + 5], _mm_alignr_epi8(state5, state4, 8));
	}

	//============================ Wandering Phase =============================//
	rowa = state0.m128i_u64[0] & 3;  //(USE THIS IF nRows IS A POWER OF 2)
	for (i = 0; i < 24; i += 6) {
		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm_xor_si128(state0, _mm_add_epi64(memMatrix[3][i + 0], memMatrix[rowa][i + 0]));
		state1 = _mm_xor_si128(state1, _mm_add_epi64(memMatrix[3][i + 1], memMatrix[rowa][i + 1]));
		state2 = _mm_xor_si128(state2, _mm_add_epi64(memMatrix[3][i + 2], memMatrix[rowa][i + 2]));
		state3 = _mm_xor_si128(state3, _mm_add_epi64(memMatrix[3][i + 3], memMatrix[rowa][i + 3]));
		state4 = _mm_xor_si128(state4, _mm_add_epi64(memMatrix[3][i + 4], memMatrix[rowa][i + 4]));
		state5 = _mm_xor_si128(state5, _mm_add_epi64(memMatrix[3][i + 5], memMatrix[rowa][i + 5]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSSE3(state);

		//M[rowOut][col] = M[rowOut][col] XOR rand
		memMatrix[0][i + 0] = _mm_xor_si128(memMatrix[0][i + 0], state0);
		memMatrix[0][i + 1] = _mm_xor_si128(memMatrix[0][i + 1], state1);
		memMatrix[0][i + 2] = _mm_xor_si128(memMatrix[0][i + 2], state2);
		memMatrix[0][i + 3] = _mm_xor_si128(memMatrix[0][i + 3], state3);
		memMatrix[0][i + 4] = _mm_xor_si128(memMatrix[0][i + 4], state4);
		memMatrix[0][i + 5] = _mm_xor_si128(memMatrix[0][i + 5], state5);

		//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
		memMatrix[rowa][i + 0] = _mm_xor_si128(memMatrix[rowa][i + 0], _mm_alignr_epi8(state0, state5, 8));
		memMatrix[rowa][i + 1] = _mm_xor_si128(memMatrix[rowa][i + 1], _mm_alignr_epi8(state1, state0, 8));
		memMatrix[rowa][i + 2] = _mm_xor_si128(memMatrix[rowa][i + 2], _mm_alignr_epi8(state2, state1, 8));
		memMatrix[rowa][i + 3] = _mm_xor_si128(memMatrix[rowa][i + 3], _mm_alignr_epi8(state3, state2, 8));
		memMatrix[rowa][i + 4] = _mm_xor_si128(memMatrix[rowa][i + 4], _mm_alignr_epi8(state4, state3, 8));
		memMatrix[rowa][i + 5] = _mm_xor_si128(memMatrix[rowa][i + 5], _mm_alignr_epi8(state5, state4, 8));
	}

	rowa = state0.m128i_u64[0] & 3;  //(USE THIS IF nRows IS A POWER OF 2)
	for (i = 0; i < 24; i += 6) {
		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm_xor_si128(state0, _mm_add_epi64(memMatrix[0][i + 0], memMatrix[rowa][i + 0]));
		state1 = _mm_xor_si128(state1, _mm_add_epi64(memMatrix[0][i + 1], memMatrix[rowa][i + 1]));
		state2 = _mm_xor_si128(state2, _mm_add_epi64(memMatrix[0][i + 2], memMatrix[rowa][i + 2]));
		state3 = _mm_xor_si128(state3, _mm_add_epi64(memMatrix[0][i + 3], memMatrix[rowa][i + 3]));
		state4 = _mm_xor_si128(state4, _mm_add_epi64(memMatrix[0][i + 4], memMatrix[rowa][i + 4]));
		state5 = _mm_xor_si128(state5, _mm_add_epi64(memMatrix[0][i + 5], memMatrix[rowa][i + 5]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSSE3(state);

		//M[rowOut][col] = M[rowOut][col] XOR rand
		memMatrix[1][i + 0] = _mm_xor_si128(memMatrix[1][i + 0], state0);
		memMatrix[1][i + 1] = _mm_xor_si128(memMatrix[1][i + 1], state1);
		memMatrix[1][i + 2] = _mm_xor_si128(memMatrix[1][i + 2], state2);
		memMatrix[1][i + 3] = _mm_xor_si128(memMatrix[1][i + 3], state3);
		memMatrix[1][i + 4] = _mm_xor_si128(memMatrix[1][i + 4], state4);
		memMatrix[1][i + 5] = _mm_xor_si128(memMatrix[1][i + 5], state5);

		//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
		memMatrix[rowa][i + 0] = _mm_xor_si128(memMatrix[rowa][i + 0], _mm_alignr_epi8(state0, state5, 8));
		memMatrix[rowa][i + 1] = _mm_xor_si128(memMatrix[rowa][i + 1], _mm_alignr_epi8(state1, state0, 8));
		memMatrix[rowa][i + 2] = _mm_xor_si128(memMatrix[rowa][i + 2], _mm_alignr_epi8(state2, state1, 8));
		memMatrix[rowa][i + 3] = _mm_xor_si128(memMatrix[rowa][i + 3], _mm_alignr_epi8(state3, state2, 8));
		memMatrix[rowa][i + 4] = _mm_xor_si128(memMatrix[rowa][i + 4], _mm_alignr_epi8(state4, state3, 8));
		memMatrix[rowa][i + 5] = _mm_xor_si128(memMatrix[rowa][i + 5], _mm_alignr_epi8(state5, state4, 8));
	}

	rowa = state0.m128i_u64[0] & 3;  //(USE THIS IF nRows IS A POWER OF 2)
	for (i = 0; i < 24; i += 6) {
		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm_xor_si128(state0, _mm_add_epi64(memMatrix[1][i + 0], memMatrix[rowa][i + 0]));
		state1 = _mm_xor_si128(state1, _mm_add_epi64(memMatrix[1][i + 1], memMatrix[rowa][i + 1]));
		state2 = _mm_xor_si128(state2, _mm_add_epi64(memMatrix[1][i + 2], memMatrix[rowa][i + 2]));
		state3 = _mm_xor_si128(state3, _mm_add_epi64(memMatrix[1][i + 3], memMatrix[rowa][i + 3]));
		state4 = _mm_xor_si128(state4, _mm_add_epi64(memMatrix[1][i + 4], memMatrix[rowa][i + 4]));
		state5 = _mm_xor_si128(state5, _mm_add_epi64(memMatrix[1][i + 5], memMatrix[rowa][i + 5]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSSE3(state);

		//M[rowOut][col] = M[rowOut][col] XOR rand
		memMatrix[2][i + 0] = _mm_xor_si128(memMatrix[2][i + 0], state0);
		memMatrix[2][i + 1] = _mm_xor_si128(memMatrix[2][i + 1], state1);
		memMatrix[2][i + 2] = _mm_xor_si128(memMatrix[2][i + 2], state2);
		memMatrix[2][i + 3] = _mm_xor_si128(memMatrix[2][i + 3], state3);
		memMatrix[2][i + 4] = _mm_xor_si128(memMatrix[2][i + 4], state4);
		memMatrix[2][i + 5] = _mm_xor_si128(memMatrix[2][i + 5], state5);

		//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
		memMatrix[rowa][i + 0] = _mm_xor_si128(memMatrix[rowa][i + 0], _mm_alignr_epi8(state0, state5, 8));
		memMatrix[rowa][i + 1] = _mm_xor_si128(memMatrix[rowa][i + 1], _mm_alignr_epi8(state1, state0, 8));
		memMatrix[rowa][i + 2] = _mm_xor_si128(memMatrix[rowa][i + 2], _mm_alignr_epi8(state2, state1, 8));
		memMatrix[rowa][i + 3] = _mm_xor_si128(memMatrix[rowa][i + 3], _mm_alignr_epi8(state3, state2, 8));
		memMatrix[rowa][i + 4] = _mm_xor_si128(memMatrix[rowa][i + 4], _mm_alignr_epi8(state4, state3, 8));
		memMatrix[rowa][i + 5] = _mm_xor_si128(memMatrix[rowa][i + 5], _mm_alignr_epi8(state5, state4, 8));
	}

	rowa = state0.m128i_u64[0] & 3;  //(USE THIS IF nRows IS A POWER OF 2)

	__m128i buf0, buf1, buf2, buf3, buf4, buf5;
	buf0 = memMatrix[rowa][0];
	buf1 = memMatrix[rowa][1];
	buf2 = memMatrix[rowa][2];
	buf3 = memMatrix[rowa][3];
	buf4 = memMatrix[rowa][4];
	buf5 = memMatrix[rowa][5];

	//Absorbing "M[prev] [+] M[row*]"
	state0 = _mm_xor_si128(state0, _mm_add_epi64(memMatrix[2][0], buf0));
	state1 = _mm_xor_si128(state1, _mm_add_epi64(memMatrix[2][1], buf1));
	state2 = _mm_xor_si128(state2, _mm_add_epi64(memMatrix[2][2], buf2));
	state3 = _mm_xor_si128(state3, _mm_add_epi64(memMatrix[2][3], buf3));
	state4 = _mm_xor_si128(state4, _mm_add_epi64(memMatrix[2][4], buf4));
	state5 = _mm_xor_si128(state5, _mm_add_epi64(memMatrix[2][5], buf5));

	//Applies the reduced-round transformation f to the sponge's state
	reducedBlake2bLyra_SSSE3(state);

	//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
	buf0 = _mm_xor_si128(buf0, _mm_alignr_epi8(state0, state5, 8));
	buf1 = _mm_xor_si128(buf1, _mm_alignr_epi8(state1, state0, 8));
	buf2 = _mm_xor_si128(buf2, _mm_alignr_epi8(state2, state1, 8));
	buf3 = _mm_xor_si128(buf3, _mm_alignr_epi8(state3, state2, 8));
	buf4 = _mm_xor_si128(buf4, _mm_alignr_epi8(state4, state3, 8));
	buf5 = _mm_xor_si128(buf5, _mm_alignr_epi8(state5, state4, 8));

	if (rowa == 3)
	{
		//M[rowOut][col] = M[rowOut][col] XOR rand
		buf0 = _mm_xor_si128(buf0, state0);
		buf1 = _mm_xor_si128(buf1, state1);
		buf2 = _mm_xor_si128(buf2, state2);
		buf3 = _mm_xor_si128(buf3, state3);
		buf4 = _mm_xor_si128(buf4, state4);
		buf5 = _mm_xor_si128(buf5, state5);
	}

	for (i = 6; i < 24; i += 6) {
		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm_xor_si128(state0, _mm_add_epi64(memMatrix[2][i + 0], memMatrix[rowa][i + 0]));
		state1 = _mm_xor_si128(state1, _mm_add_epi64(memMatrix[2][i + 1], memMatrix[rowa][i + 1]));
		state2 = _mm_xor_si128(state2, _mm_add_epi64(memMatrix[2][i + 2], memMatrix[rowa][i + 2]));
		state3 = _mm_xor_si128(state3, _mm_add_epi64(memMatrix[2][i + 3], memMatrix[rowa][i + 3]));
		state4 = _mm_xor_si128(state4, _mm_add_epi64(memMatrix[2][i + 4], memMatrix[rowa][i + 4]));
		state5 = _mm_xor_si128(state5, _mm_add_epi64(memMatrix[2][i + 5], memMatrix[rowa][i + 5]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSSE3(state);
	}

	//============================ Wrap-up Phase ===============================//
	//XORs the first BLOCK_LEN_INT64 words of "in" with the current state
	state0 = _mm_xor_si128(state0, buf0);
	state1 = _mm_xor_si128(state1, buf1);
	state2 = _mm_xor_si128(state2, buf2);
	state3 = _mm_xor_si128(state3, buf3);
	state4 = _mm_xor_si128(state4, buf4);
	state5 = _mm_xor_si128(state5, buf5);

	//Applies the transformation f to the sponge's state
	blake2bLyra_SSSE3(state);

	//Squeezes the key
	_mm_storeu_si128((__m128i*)K + 0, state0);
	_mm_storeu_si128((__m128i*)K + 1, state1);

	//========================= Freeing the memory =============================//

	return 0;
}
#else
int LYRA2v2_SSE2(void *K, const void *pwd, __m128i *wholeMatrix)
{
	//============================= Basic variables ============================//
	int64_t rowa = 0; //index of row* (a previous row, deterministically picked during Setup and randomly picked while Wandering)
	int64_t i; //auxiliary iteration counter
			   //==========================================================================/

			   //========== Initializing the Memory Matrix and pointers to it =============//
			   //Allocates pointers to each row of the matrix
	__m128i* memMatrix[4];

	//Places the pointers in the correct positions
	memMatrix[0] = wholeMatrix + 0;
	memMatrix[1] = wholeMatrix + 24;
	memMatrix[2] = wholeMatrix + 48;
	memMatrix[3] = wholeMatrix + 72;
	//==========================================================================/

	//======================= Initializing the Sponge State ====================//
	//Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)
	__m128i state0, state1, state2, state3, state4, state5, state6, state7;
	//Prepends the password
	//Concatenates the salt
	state0 = state2 = _mm_loadu_si128((__m128i*)pwd + 0);
	state1 = state3 = _mm_loadu_si128((__m128i*)pwd + 1);
	//Remainder BLOCK_LEN_BLAKE2_SAFE_BYTES are reserved to the IV
	state4 = _mm_setr_epi32(0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85);
	state5 = _mm_setr_epi32(0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a);
	state6 = _mm_setr_epi32(0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c);
	state7 = _mm_setr_epi32(0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19);

	//Applies the transformation f to the sponge's state
	blake2bLyra_SSE2(state);

	state0 = _mm_xor_si128(state0, _mm_setr_epi32(0x20, 0x00, 0x20, 0x00));
	state1 = _mm_xor_si128(state1, _mm_setr_epi32(0x20, 0x00, 0x01, 0x00));
	state2 = _mm_xor_si128(state2, _mm_setr_epi32(0x04, 0x00, 0x04, 0x00));
	state3 = _mm_xor_si128(state3, _mm_setr_epi32(0x80, 0x00, 0x00, 0x01000000));

	//Applies the transformation f to the sponge's state
	blake2bLyra_SSE2(state);

	//==========================================================================/

	//================================ Setup Phase =============================//
	//Initializes M[0] and M[1]
	for (i = 18; i >= 0; i -= 6) {
		memMatrix[0][i + 0] = state0;
		memMatrix[0][i + 1] = state1;
		memMatrix[0][i + 2] = state2;
		memMatrix[0][i + 3] = state3;
		memMatrix[0][i + 4] = state4;
		memMatrix[0][i + 5] = state5;

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSE2(state);
	}

	int64_t j;
	for (i = 0, j = 18; i < 24; i += 6, j -= 6) {

		//Absorbing "M[prev][col]"
		state0 = _mm_xor_si128(state0, memMatrix[0][i + 0]);
		state1 = _mm_xor_si128(state1, memMatrix[0][i + 1]);
		state2 = _mm_xor_si128(state2, memMatrix[0][i + 2]);
		state3 = _mm_xor_si128(state3, memMatrix[0][i + 3]);
		state4 = _mm_xor_si128(state4, memMatrix[0][i + 4]);
		state5 = _mm_xor_si128(state5, memMatrix[0][i + 5]);

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSE2(state);

		//M[row][C-1-col] = M[prev][col] XOR rand
		memMatrix[1][j + 0] = _mm_xor_si128(memMatrix[0][i + 0], state0);
		memMatrix[1][j + 1] = _mm_xor_si128(memMatrix[0][i + 1], state1);
		memMatrix[1][j + 2] = _mm_xor_si128(memMatrix[0][i + 2], state2);
		memMatrix[1][j + 3] = _mm_xor_si128(memMatrix[0][i + 3], state3);
		memMatrix[1][j + 4] = _mm_xor_si128(memMatrix[0][i + 4], state4);
		memMatrix[1][j + 5] = _mm_xor_si128(memMatrix[0][i + 5], state5);
	}

	for (i = 0, j = 18; i < 24; i += 6, j -= 6) {

		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm_xor_si128(state0, _mm_add_epi64(memMatrix[1][i + 0], memMatrix[0][i + 0]));
		state1 = _mm_xor_si128(state1, _mm_add_epi64(memMatrix[1][i + 1], memMatrix[0][i + 1]));
		state2 = _mm_xor_si128(state2, _mm_add_epi64(memMatrix[1][i + 2], memMatrix[0][i + 2]));
		state3 = _mm_xor_si128(state3, _mm_add_epi64(memMatrix[1][i + 3], memMatrix[0][i + 3]));
		state4 = _mm_xor_si128(state4, _mm_add_epi64(memMatrix[1][i + 4], memMatrix[0][i + 4]));
		state5 = _mm_xor_si128(state5, _mm_add_epi64(memMatrix[1][i + 5], memMatrix[0][i + 5]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSE2(state);

		//M[row][col] = M[prev][col] XOR rand
		memMatrix[2][j + 0] = _mm_xor_si128(memMatrix[1][i + 0], state0);
		memMatrix[2][j + 1] = _mm_xor_si128(memMatrix[1][i + 1], state1);
		memMatrix[2][j + 2] = _mm_xor_si128(memMatrix[1][i + 2], state2);
		memMatrix[2][j + 3] = _mm_xor_si128(memMatrix[1][i + 3], state3);
		memMatrix[2][j + 4] = _mm_xor_si128(memMatrix[1][i + 4], state4);
		memMatrix[2][j + 5] = _mm_xor_si128(memMatrix[1][i + 5], state5);

		//M[row*][col] = M[row*][col] XOR rotW(rand)
		memMatrix[0][i + 0] = _mm_xor_si128(memMatrix[0][i + 0], _mm_or_si128(_mm_slli_si128(state0, 8), _mm_srli_si128(state5, 8)));
		memMatrix[0][i + 1] = _mm_xor_si128(memMatrix[0][i + 1], _mm_or_si128(_mm_slli_si128(state1, 8), _mm_srli_si128(state0, 8)));
		memMatrix[0][i + 2] = _mm_xor_si128(memMatrix[0][i + 2], _mm_or_si128(_mm_slli_si128(state2, 8), _mm_srli_si128(state1, 8)));
		memMatrix[0][i + 3] = _mm_xor_si128(memMatrix[0][i + 3], _mm_or_si128(_mm_slli_si128(state3, 8), _mm_srli_si128(state2, 8)));
		memMatrix[0][i + 4] = _mm_xor_si128(memMatrix[0][i + 4], _mm_or_si128(_mm_slli_si128(state4, 8), _mm_srli_si128(state3, 8)));
		memMatrix[0][i + 5] = _mm_xor_si128(memMatrix[0][i + 5], _mm_or_si128(_mm_slli_si128(state5, 8), _mm_srli_si128(state4, 8)));
	}

	for (i = 0, j = 18; i < 24; i += 6, j -= 6) {

		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm_xor_si128(state0, _mm_add_epi64(memMatrix[2][i + 0], memMatrix[1][i + 0]));
		state1 = _mm_xor_si128(state1, _mm_add_epi64(memMatrix[2][i + 1], memMatrix[1][i + 1]));
		state2 = _mm_xor_si128(state2, _mm_add_epi64(memMatrix[2][i + 2], memMatrix[1][i + 2]));
		state3 = _mm_xor_si128(state3, _mm_add_epi64(memMatrix[2][i + 3], memMatrix[1][i + 3]));
		state4 = _mm_xor_si128(state4, _mm_add_epi64(memMatrix[2][i + 4], memMatrix[1][i + 4]));
		state5 = _mm_xor_si128(state5, _mm_add_epi64(memMatrix[2][i + 5], memMatrix[1][i + 5]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSE2(state);

		//M[row][col] = M[prev][col] XOR rand
		memMatrix[3][j + 0] = _mm_xor_si128(memMatrix[2][i + 0], state0);
		memMatrix[3][j + 1] = _mm_xor_si128(memMatrix[2][i + 1], state1);
		memMatrix[3][j + 2] = _mm_xor_si128(memMatrix[2][i + 2], state2);
		memMatrix[3][j + 3] = _mm_xor_si128(memMatrix[2][i + 3], state3);
		memMatrix[3][j + 4] = _mm_xor_si128(memMatrix[2][i + 4], state4);
		memMatrix[3][j + 5] = _mm_xor_si128(memMatrix[2][i + 5], state5);

		//M[row*][col] = M[row*][col] XOR rotW(rand)
		memMatrix[1][i + 0] = _mm_xor_si128(memMatrix[1][i + 0], _mm_or_si128(_mm_slli_si128(state0, 8), _mm_srli_si128(state5, 8)));
		memMatrix[1][i + 1] = _mm_xor_si128(memMatrix[1][i + 1], _mm_or_si128(_mm_slli_si128(state1, 8), _mm_srli_si128(state0, 8)));
		memMatrix[1][i + 2] = _mm_xor_si128(memMatrix[1][i + 2], _mm_or_si128(_mm_slli_si128(state2, 8), _mm_srli_si128(state1, 8)));
		memMatrix[1][i + 3] = _mm_xor_si128(memMatrix[1][i + 3], _mm_or_si128(_mm_slli_si128(state3, 8), _mm_srli_si128(state2, 8)));
		memMatrix[1][i + 4] = _mm_xor_si128(memMatrix[1][i + 4], _mm_or_si128(_mm_slli_si128(state4, 8), _mm_srli_si128(state3, 8)));
		memMatrix[1][i + 5] = _mm_xor_si128(memMatrix[1][i + 5], _mm_or_si128(_mm_slli_si128(state5, 8), _mm_srli_si128(state4, 8)));
	}

	//============================ Wandering Phase =============================//
	rowa = state0.m128i_u64[0] & 3;  //(USE THIS IF nRows IS A POWER OF 2)
	for (i = 0; i < 24; i += 6) {
		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm_xor_si128(state0, _mm_add_epi64(memMatrix[3][i + 0], memMatrix[rowa][i + 0]));
		state1 = _mm_xor_si128(state1, _mm_add_epi64(memMatrix[3][i + 1], memMatrix[rowa][i + 1]));
		state2 = _mm_xor_si128(state2, _mm_add_epi64(memMatrix[3][i + 2], memMatrix[rowa][i + 2]));
		state3 = _mm_xor_si128(state3, _mm_add_epi64(memMatrix[3][i + 3], memMatrix[rowa][i + 3]));
		state4 = _mm_xor_si128(state4, _mm_add_epi64(memMatrix[3][i + 4], memMatrix[rowa][i + 4]));
		state5 = _mm_xor_si128(state5, _mm_add_epi64(memMatrix[3][i + 5], memMatrix[rowa][i + 5]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSE2(state);

		//M[rowOut][col] = M[rowOut][col] XOR rand
		memMatrix[0][i + 0] = _mm_xor_si128(memMatrix[0][i + 0], state0);
		memMatrix[0][i + 1] = _mm_xor_si128(memMatrix[0][i + 1], state1);
		memMatrix[0][i + 2] = _mm_xor_si128(memMatrix[0][i + 2], state2);
		memMatrix[0][i + 3] = _mm_xor_si128(memMatrix[0][i + 3], state3);
		memMatrix[0][i + 4] = _mm_xor_si128(memMatrix[0][i + 4], state4);
		memMatrix[0][i + 5] = _mm_xor_si128(memMatrix[0][i + 5], state5);

		//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
		memMatrix[rowa][i + 0] = _mm_xor_si128(memMatrix[rowa][i + 0], _mm_or_si128(_mm_slli_si128(state0, 8), _mm_srli_si128(state5, 8)));
		memMatrix[rowa][i + 1] = _mm_xor_si128(memMatrix[rowa][i + 1], _mm_or_si128(_mm_slli_si128(state1, 8), _mm_srli_si128(state0, 8)));
		memMatrix[rowa][i + 2] = _mm_xor_si128(memMatrix[rowa][i + 2], _mm_or_si128(_mm_slli_si128(state2, 8), _mm_srli_si128(state1, 8)));
		memMatrix[rowa][i + 3] = _mm_xor_si128(memMatrix[rowa][i + 3], _mm_or_si128(_mm_slli_si128(state3, 8), _mm_srli_si128(state2, 8)));
		memMatrix[rowa][i + 4] = _mm_xor_si128(memMatrix[rowa][i + 4], _mm_or_si128(_mm_slli_si128(state4, 8), _mm_srli_si128(state3, 8)));
		memMatrix[rowa][i + 5] = _mm_xor_si128(memMatrix[rowa][i + 5], _mm_or_si128(_mm_slli_si128(state5, 8), _mm_srli_si128(state4, 8)));
	}

	rowa = state0.m128i_u64[0] & 3;  //(USE THIS IF nRows IS A POWER OF 2)
	for (i = 0; i < 24; i += 6) {
		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm_xor_si128(state0, _mm_add_epi64(memMatrix[0][i + 0], memMatrix[rowa][i + 0]));
		state1 = _mm_xor_si128(state1, _mm_add_epi64(memMatrix[0][i + 1], memMatrix[rowa][i + 1]));
		state2 = _mm_xor_si128(state2, _mm_add_epi64(memMatrix[0][i + 2], memMatrix[rowa][i + 2]));
		state3 = _mm_xor_si128(state3, _mm_add_epi64(memMatrix[0][i + 3], memMatrix[rowa][i + 3]));
		state4 = _mm_xor_si128(state4, _mm_add_epi64(memMatrix[0][i + 4], memMatrix[rowa][i + 4]));
		state5 = _mm_xor_si128(state5, _mm_add_epi64(memMatrix[0][i + 5], memMatrix[rowa][i + 5]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSE2(state);

		//M[rowOut][col] = M[rowOut][col] XOR rand
		memMatrix[1][i + 0] = _mm_xor_si128(memMatrix[1][i + 0], state0);
		memMatrix[1][i + 1] = _mm_xor_si128(memMatrix[1][i + 1], state1);
		memMatrix[1][i + 2] = _mm_xor_si128(memMatrix[1][i + 2], state2);
		memMatrix[1][i + 3] = _mm_xor_si128(memMatrix[1][i + 3], state3);
		memMatrix[1][i + 4] = _mm_xor_si128(memMatrix[1][i + 4], state4);
		memMatrix[1][i + 5] = _mm_xor_si128(memMatrix[1][i + 5], state5);

		//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
		memMatrix[rowa][i + 0] = _mm_xor_si128(memMatrix[rowa][i + 0], _mm_or_si128(_mm_slli_si128(state0, 8), _mm_srli_si128(state5, 8)));
		memMatrix[rowa][i + 1] = _mm_xor_si128(memMatrix[rowa][i + 1], _mm_or_si128(_mm_slli_si128(state1, 8), _mm_srli_si128(state0, 8)));
		memMatrix[rowa][i + 2] = _mm_xor_si128(memMatrix[rowa][i + 2], _mm_or_si128(_mm_slli_si128(state2, 8), _mm_srli_si128(state1, 8)));
		memMatrix[rowa][i + 3] = _mm_xor_si128(memMatrix[rowa][i + 3], _mm_or_si128(_mm_slli_si128(state3, 8), _mm_srli_si128(state2, 8)));
		memMatrix[rowa][i + 4] = _mm_xor_si128(memMatrix[rowa][i + 4], _mm_or_si128(_mm_slli_si128(state4, 8), _mm_srli_si128(state3, 8)));
		memMatrix[rowa][i + 5] = _mm_xor_si128(memMatrix[rowa][i + 5], _mm_or_si128(_mm_slli_si128(state5, 8), _mm_srli_si128(state4, 8)));
	}

	rowa = state0.m128i_u64[0] & 3;  //(USE THIS IF nRows IS A POWER OF 2)
	for (i = 0; i < 24; i += 6) {
		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm_xor_si128(state0, _mm_add_epi64(memMatrix[1][i + 0], memMatrix[rowa][i + 0]));
		state1 = _mm_xor_si128(state1, _mm_add_epi64(memMatrix[1][i + 1], memMatrix[rowa][i + 1]));
		state2 = _mm_xor_si128(state2, _mm_add_epi64(memMatrix[1][i + 2], memMatrix[rowa][i + 2]));
		state3 = _mm_xor_si128(state3, _mm_add_epi64(memMatrix[1][i + 3], memMatrix[rowa][i + 3]));
		state4 = _mm_xor_si128(state4, _mm_add_epi64(memMatrix[1][i + 4], memMatrix[rowa][i + 4]));
		state5 = _mm_xor_si128(state5, _mm_add_epi64(memMatrix[1][i + 5], memMatrix[rowa][i + 5]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSE2(state);

		//M[rowOut][col] = M[rowOut][col] XOR rand
		memMatrix[2][i + 0] = _mm_xor_si128(memMatrix[2][i + 0], state0);
		memMatrix[2][i + 1] = _mm_xor_si128(memMatrix[2][i + 1], state1);
		memMatrix[2][i + 2] = _mm_xor_si128(memMatrix[2][i + 2], state2);
		memMatrix[2][i + 3] = _mm_xor_si128(memMatrix[2][i + 3], state3);
		memMatrix[2][i + 4] = _mm_xor_si128(memMatrix[2][i + 4], state4);
		memMatrix[2][i + 5] = _mm_xor_si128(memMatrix[2][i + 5], state5);

		//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
		memMatrix[rowa][i + 0] = _mm_xor_si128(memMatrix[rowa][i + 0], _mm_or_si128(_mm_slli_si128(state0, 8), _mm_srli_si128(state5, 8)));
		memMatrix[rowa][i + 1] = _mm_xor_si128(memMatrix[rowa][i + 1], _mm_or_si128(_mm_slli_si128(state1, 8), _mm_srli_si128(state0, 8)));
		memMatrix[rowa][i + 2] = _mm_xor_si128(memMatrix[rowa][i + 2], _mm_or_si128(_mm_slli_si128(state2, 8), _mm_srli_si128(state1, 8)));
		memMatrix[rowa][i + 3] = _mm_xor_si128(memMatrix[rowa][i + 3], _mm_or_si128(_mm_slli_si128(state3, 8), _mm_srli_si128(state2, 8)));
		memMatrix[rowa][i + 4] = _mm_xor_si128(memMatrix[rowa][i + 4], _mm_or_si128(_mm_slli_si128(state4, 8), _mm_srli_si128(state3, 8)));
		memMatrix[rowa][i + 5] = _mm_xor_si128(memMatrix[rowa][i + 5], _mm_or_si128(_mm_slli_si128(state5, 8), _mm_srli_si128(state4, 8)));
	}

	rowa = state0.m128i_u64[0] & 3;  //(USE THIS IF nRows IS A POWER OF 2)

	__m128i buf0, buf1, buf2, buf3, buf4, buf5;
	buf0 = memMatrix[rowa][0];
	buf1 = memMatrix[rowa][1];
	buf2 = memMatrix[rowa][2];
	buf3 = memMatrix[rowa][3];
	buf4 = memMatrix[rowa][4];
	buf5 = memMatrix[rowa][5];

	//Absorbing "M[prev] [+] M[row*]"
	state0 = _mm_xor_si128(state0, _mm_add_epi64(memMatrix[2][0], buf0));
	state1 = _mm_xor_si128(state1, _mm_add_epi64(memMatrix[2][1], buf1));
	state2 = _mm_xor_si128(state2, _mm_add_epi64(memMatrix[2][2], buf2));
	state3 = _mm_xor_si128(state3, _mm_add_epi64(memMatrix[2][3], buf3));
	state4 = _mm_xor_si128(state4, _mm_add_epi64(memMatrix[2][4], buf4));
	state5 = _mm_xor_si128(state5, _mm_add_epi64(memMatrix[2][5], buf5));

	//Applies the reduced-round transformation f to the sponge's state
	reducedBlake2bLyra_SSE2(state);

	//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
	buf0 = _mm_xor_si128(buf0, _mm_or_si128(_mm_slli_si128(state0, 8), _mm_srli_si128(state5, 8)));
	buf1 = _mm_xor_si128(buf1, _mm_or_si128(_mm_slli_si128(state1, 8), _mm_srli_si128(state0, 8)));
	buf2 = _mm_xor_si128(buf2, _mm_or_si128(_mm_slli_si128(state2, 8), _mm_srli_si128(state1, 8)));
	buf3 = _mm_xor_si128(buf3, _mm_or_si128(_mm_slli_si128(state3, 8), _mm_srli_si128(state2, 8)));
	buf4 = _mm_xor_si128(buf4, _mm_or_si128(_mm_slli_si128(state4, 8), _mm_srli_si128(state3, 8)));
	buf5 = _mm_xor_si128(buf5, _mm_or_si128(_mm_slli_si128(state5, 8), _mm_srli_si128(state4, 8)));

	if (rowa == 3)
	{
		//M[rowOut][col] = M[rowOut][col] XOR rand
		buf0 = _mm_xor_si128(buf0, state0);
		buf1 = _mm_xor_si128(buf1, state1);
		buf2 = _mm_xor_si128(buf2, state2);
		buf3 = _mm_xor_si128(buf3, state3);
		buf4 = _mm_xor_si128(buf4, state4);
		buf5 = _mm_xor_si128(buf5, state5);
	}

	for (i = 6; i < 24; i += 6) {
		//Absorbing "M[prev] [+] M[row*]"
		state0 = _mm_xor_si128(state0, _mm_add_epi64(memMatrix[2][i + 0], memMatrix[rowa][i + 0]));
		state1 = _mm_xor_si128(state1, _mm_add_epi64(memMatrix[2][i + 1], memMatrix[rowa][i + 1]));
		state2 = _mm_xor_si128(state2, _mm_add_epi64(memMatrix[2][i + 2], memMatrix[rowa][i + 2]));
		state3 = _mm_xor_si128(state3, _mm_add_epi64(memMatrix[2][i + 3], memMatrix[rowa][i + 3]));
		state4 = _mm_xor_si128(state4, _mm_add_epi64(memMatrix[2][i + 4], memMatrix[rowa][i + 4]));
		state5 = _mm_xor_si128(state5, _mm_add_epi64(memMatrix[2][i + 5], memMatrix[rowa][i + 5]));

		//Applies the reduced-round transformation f to the sponge's state
		reducedBlake2bLyra_SSE2(state);
	}

	//============================ Wrap-up Phase ===============================//
	//XORs the first BLOCK_LEN_INT64 words of "in" with the current state
	state0 = _mm_xor_si128(state0, buf0);
	state1 = _mm_xor_si128(state1, buf1);
	state2 = _mm_xor_si128(state2, buf2);
	state3 = _mm_xor_si128(state3, buf3);
	state4 = _mm_xor_si128(state4, buf4);
	state5 = _mm_xor_si128(state5, buf5);

	//Applies the transformation f to the sponge's state
	blake2bLyra_SSE2(state);

	//Squeezes the key
	_mm_storeu_si128((__m128i*)K + 0, state0);
	_mm_storeu_si128((__m128i*)K + 1, state1);

	//========================= Freeing the memory =============================//

	return 0;
}
#endif
#endif