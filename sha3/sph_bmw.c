/* $Id: bmw.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * BMW implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#include <stddef.h>
#include <string.h>
#include <limits.h>

#ifdef __cplusplus
extern "C"{
#endif

#include "sph_bmw.h"

#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_BMW
#define SPH_SMALL_FOOTPRINT_BMW   1
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

static const sph_u32 IV224[] = {
	SPH_C32(0x00010203), SPH_C32(0x04050607),
	SPH_C32(0x08090A0B), SPH_C32(0x0C0D0E0F),
	SPH_C32(0x10111213), SPH_C32(0x14151617),
	SPH_C32(0x18191A1B), SPH_C32(0x1C1D1E1F),
	SPH_C32(0x20212223), SPH_C32(0x24252627),
	SPH_C32(0x28292A2B), SPH_C32(0x2C2D2E2F),
	SPH_C32(0x30313233), SPH_C32(0x34353637),
	SPH_C32(0x38393A3B), SPH_C32(0x3C3D3E3F)
};

static const sph_u32 IV256[] = {
	SPH_C32(0x40414243), SPH_C32(0x44454647),
	SPH_C32(0x48494A4B), SPH_C32(0x4C4D4E4F),
	SPH_C32(0x50515253), SPH_C32(0x54555657),
	SPH_C32(0x58595A5B), SPH_C32(0x5C5D5E5F),
	SPH_C32(0x60616263), SPH_C32(0x64656667),
	SPH_C32(0x68696A6B), SPH_C32(0x6C6D6E6F),
	SPH_C32(0x70717273), SPH_C32(0x74757677),
	SPH_C32(0x78797A7B), SPH_C32(0x7C7D7E7F)
};

#if SPH_64

static const sph_u64 IV384[] = {
	SPH_C64(0x0001020304050607), SPH_C64(0x08090A0B0C0D0E0F),
	SPH_C64(0x1011121314151617), SPH_C64(0x18191A1B1C1D1E1F),
	SPH_C64(0x2021222324252627), SPH_C64(0x28292A2B2C2D2E2F),
	SPH_C64(0x3031323334353637), SPH_C64(0x38393A3B3C3D3E3F),
	SPH_C64(0x4041424344454647), SPH_C64(0x48494A4B4C4D4E4F),
	SPH_C64(0x5051525354555657), SPH_C64(0x58595A5B5C5D5E5F),
	SPH_C64(0x6061626364656667), SPH_C64(0x68696A6B6C6D6E6F),
	SPH_C64(0x7071727374757677), SPH_C64(0x78797A7B7C7D7E7F)
};

static const sph_u64 IV512[] = {
	SPH_C64(0x8081828384858687), SPH_C64(0x88898A8B8C8D8E8F),
	SPH_C64(0x9091929394959697), SPH_C64(0x98999A9B9C9D9E9F),
	SPH_C64(0xA0A1A2A3A4A5A6A7), SPH_C64(0xA8A9AAABACADAEAF),
	SPH_C64(0xB0B1B2B3B4B5B6B7), SPH_C64(0xB8B9BABBBCBDBEBF),
	SPH_C64(0xC0C1C2C3C4C5C6C7), SPH_C64(0xC8C9CACBCCCDCECF),
	SPH_C64(0xD0D1D2D3D4D5D6D7), SPH_C64(0xD8D9DADBDCDDDEDF),
	SPH_C64(0xE0E1E2E3E4E5E6E7), SPH_C64(0xE8E9EAEBECEDEEEF),
	SPH_C64(0xF0F1F2F3F4F5F6F7), SPH_C64(0xF8F9FAFBFCFDFEFF)
};

#endif

#define XCAT(x, y)    XCAT_(x, y)
#define XCAT_(x, y)   x ## y

#define LPAR   (

#define I16_16    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15
#define I16_17    1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16
#define I16_18    2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17
#define I16_19    3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18
#define I16_20    4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19
#define I16_21    5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20
#define I16_22    6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21
#define I16_23    7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22
#define I16_24    8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23
#define I16_25    9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24
#define I16_26   10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25
#define I16_27   11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26
#define I16_28   12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27
#define I16_29   13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28
#define I16_30   14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29
#define I16_31   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30

#define M16_16    0,  1,  3,  4,  7, 10, 11
#define M16_17    1,  2,  4,  5,  8, 11, 12
#define M16_18    2,  3,  5,  6,  9, 12, 13
#define M16_19    3,  4,  6,  7, 10, 13, 14
#define M16_20    4,  5,  7,  8, 11, 14, 15
#define M16_21    5,  6,  8,  9, 12, 15, 16
#define M16_22    6,  7,  9, 10, 13,  0,  1
#define M16_23    7,  8, 10, 11, 14,  1,  2
#define M16_24    8,  9, 11, 12, 15,  2,  3
#define M16_25    9, 10, 12, 13,  0,  3,  4
#define M16_26   10, 11, 13, 14,  1,  4,  5
#define M16_27   11, 12, 14, 15,  2,  5,  6
#define M16_28   12, 13, 15, 16,  3,  6,  7
#define M16_29   13, 14,  0,  1,  4,  7,  8
#define M16_30   14, 15,  1,  2,  5,  8,  9
#define M16_31   15, 16,  2,  3,  6,  9, 10

#define ss0(x)    (((x) >> 1) ^ SPH_T32((x) << 3) \
                  ^ SPH_ROTL32(x,  4) ^ SPH_ROTL32(x, 19))
#define ss1(x)    (((x) >> 1) ^ SPH_T32((x) << 2) \
                  ^ SPH_ROTL32(x,  8) ^ SPH_ROTL32(x, 23))
#define ss2(x)    (((x) >> 2) ^ SPH_T32((x) << 1) \
                  ^ SPH_ROTL32(x, 12) ^ SPH_ROTL32(x, 25))
#define ss3(x)    (((x) >> 2) ^ SPH_T32((x) << 2) \
                  ^ SPH_ROTL32(x, 15) ^ SPH_ROTL32(x, 29))
#define ss4(x)    (((x) >> 1) ^ (x))
#define ss5(x)    (((x) >> 2) ^ (x))
#define rs1(x)    SPH_ROTL32(x,  3)
#define rs2(x)    SPH_ROTL32(x,  7)
#define rs3(x)    SPH_ROTL32(x, 13)
#define rs4(x)    SPH_ROTL32(x, 16)
#define rs5(x)    SPH_ROTL32(x, 19)
#define rs6(x)    SPH_ROTL32(x, 23)
#define rs7(x)    SPH_ROTL32(x, 27)

#define Ks(j)   SPH_T32((sph_u32)(j) * SPH_C32(0x05555555))

#define add_elt_s(mf, hf, j0m, j1m, j3m, j4m, j7m, j10m, j11m, j16) \
	(SPH_T32(SPH_ROTL32(mf(j0m), j1m) + SPH_ROTL32(mf(j3m), j4m) \
		- SPH_ROTL32(mf(j10m), j11m) + Ks(j16)) ^ hf(j7m))

#define expand1s_inner(qf, mf, hf, i16, \
		i0, i1, i2, i3, i4, i5, i6, i7, i8, \
		i9, i10, i11, i12, i13, i14, i15, \
		i0m, i1m, i3m, i4m, i7m, i10m, i11m) \
	SPH_T32(ss1(qf(i0)) + ss2(qf(i1)) + ss3(qf(i2)) + ss0(qf(i3)) \
		+ ss1(qf(i4)) + ss2(qf(i5)) + ss3(qf(i6)) + ss0(qf(i7)) \
		+ ss1(qf(i8)) + ss2(qf(i9)) + ss3(qf(i10)) + ss0(qf(i11)) \
		+ ss1(qf(i12)) + ss2(qf(i13)) + ss3(qf(i14)) + ss0(qf(i15)) \
		+ add_elt_s(mf, hf, i0m, i1m, i3m, i4m, i7m, i10m, i11m, i16))

#define expand1s(qf, mf, hf, i16) \
	expand1s_(qf, mf, hf, i16, I16_ ## i16, M16_ ## i16)
#define expand1s_(qf, mf, hf, i16, ix, iy) \
	expand1s_inner LPAR qf, mf, hf, i16, ix, iy)

#define expand2s_inner(qf, mf, hf, i16, \
		i0, i1, i2, i3, i4, i5, i6, i7, i8, \
		i9, i10, i11, i12, i13, i14, i15, \
		i0m, i1m, i3m, i4m, i7m, i10m, i11m) \
	SPH_T32(qf(i0) + rs1(qf(i1)) + qf(i2) + rs2(qf(i3)) \
		+ qf(i4) + rs3(qf(i5)) + qf(i6) + rs4(qf(i7)) \
		+ qf(i8) + rs5(qf(i9)) + qf(i10) + rs6(qf(i11)) \
		+ qf(i12) + rs7(qf(i13)) + ss4(qf(i14)) + ss5(qf(i15)) \
		+ add_elt_s(mf, hf, i0m, i1m, i3m, i4m, i7m, i10m, i11m, i16))

#define expand2s(qf, mf, hf, i16) \
	expand2s_(qf, mf, hf, i16, I16_ ## i16, M16_ ## i16)
#define expand2s_(qf, mf, hf, i16, ix, iy) \
	expand2s_inner LPAR qf, mf, hf, i16, ix, iy)

#if SPH_64

#define sb0(x)    (((x) >> 1) ^ SPH_T64((x) << 3) \
                  ^ SPH_ROTL64(x,  4) ^ SPH_ROTL64(x, 37))
#define sb1(x)    (((x) >> 1) ^ SPH_T64((x) << 2) \
                  ^ SPH_ROTL64(x, 13) ^ SPH_ROTL64(x, 43))
#define sb2(x)    (((x) >> 2) ^ SPH_T64((x) << 1) \
                  ^ SPH_ROTL64(x, 19) ^ SPH_ROTL64(x, 53))
#define sb3(x)    (((x) >> 2) ^ SPH_T64((x) << 2) \
                  ^ SPH_ROTL64(x, 28) ^ SPH_ROTL64(x, 59))
#define sb4(x)    (((x) >> 1) ^ (x))
#define sb5(x)    (((x) >> 2) ^ (x))
#define rb1(x)    SPH_ROTL64(x,  5)
#define rb2(x)    SPH_ROTL64(x, 11)
#define rb3(x)    SPH_ROTL64(x, 27)
#define rb4(x)    SPH_ROTL64(x, 32)
#define rb5(x)    SPH_ROTL64(x, 37)
#define rb6(x)    SPH_ROTL64(x, 43)
#define rb7(x)    SPH_ROTL64(x, 53)

#define Kb(j)   SPH_T64((sph_u64)(j) * SPH_C64(0x0555555555555555))

#if SPH_SMALL_FOOTPRINT_BMW

static const sph_u64 Kb_tab[] = {
	Kb(16), Kb(17), Kb(18), Kb(19), Kb(20), Kb(21), Kb(22), Kb(23),
	Kb(24), Kb(25), Kb(26), Kb(27), Kb(28), Kb(29), Kb(30), Kb(31)
};

#define rol_off(mf, j, off) \
	SPH_ROTL64(mf(((j) + (off)) & 15), (((j) + (off)) & 15) + 1)

#define add_elt_b(mf, hf, j) \
	(SPH_T64(rol_off(mf, j, 0) + rol_off(mf, j, 3) \
		- rol_off(mf, j, 10) + Kb_tab[j]) ^ hf(((j) + 7) & 15))

#define expand1b(qf, mf, hf, i) \
	SPH_T64(sb1(qf((i) - 16)) + sb2(qf((i) - 15)) \
		+ sb3(qf((i) - 14)) + sb0(qf((i) - 13)) \
		+ sb1(qf((i) - 12)) + sb2(qf((i) - 11)) \
		+ sb3(qf((i) - 10)) + sb0(qf((i) - 9)) \
		+ sb1(qf((i) - 8)) + sb2(qf((i) - 7)) \
		+ sb3(qf((i) - 6)) + sb0(qf((i) - 5)) \
		+ sb1(qf((i) - 4)) + sb2(qf((i) - 3)) \
		+ sb3(qf((i) - 2)) + sb0(qf((i) - 1)) \
		+ add_elt_b(mf, hf, (i) - 16))

#define expand2b(qf, mf, hf, i) \
	SPH_T64(qf((i) - 16) + rb1(qf((i) - 15)) \
		+ qf((i) - 14) + rb2(qf((i) - 13)) \
		+ qf((i) - 12) + rb3(qf((i) - 11)) \
		+ qf((i) - 10) + rb4(qf((i) - 9)) \
		+ qf((i) - 8) + rb5(qf((i) - 7)) \
		+ qf((i) - 6) + rb6(qf((i) - 5)) \
		+ qf((i) - 4) + rb7(qf((i) - 3)) \
		+ sb4(qf((i) - 2)) + sb5(qf((i) - 1)) \
		+ add_elt_b(mf, hf, (i) - 16))

#else

#define add_elt_b(mf, hf, j0m, j1m, j3m, j4m, j7m, j10m, j11m, j16) \
	(SPH_T64(SPH_ROTL64(mf(j0m), j1m) + SPH_ROTL64(mf(j3m), j4m) \
		- SPH_ROTL64(mf(j10m), j11m) + Kb(j16)) ^ hf(j7m))

#define expand1b_inner(qf, mf, hf, i16, \
		i0, i1, i2, i3, i4, i5, i6, i7, i8, \
		i9, i10, i11, i12, i13, i14, i15, \
		i0m, i1m, i3m, i4m, i7m, i10m, i11m) \
	SPH_T64(sb1(qf(i0)) + sb2(qf(i1)) + sb3(qf(i2)) + sb0(qf(i3)) \
		+ sb1(qf(i4)) + sb2(qf(i5)) + sb3(qf(i6)) + sb0(qf(i7)) \
		+ sb1(qf(i8)) + sb2(qf(i9)) + sb3(qf(i10)) + sb0(qf(i11)) \
		+ sb1(qf(i12)) + sb2(qf(i13)) + sb3(qf(i14)) + sb0(qf(i15)) \
		+ add_elt_b(mf, hf, i0m, i1m, i3m, i4m, i7m, i10m, i11m, i16))

#define expand1b(qf, mf, hf, i16) \
	expand1b_(qf, mf, hf, i16, I16_ ## i16, M16_ ## i16)
#define expand1b_(qf, mf, hf, i16, ix, iy) \
	expand1b_inner LPAR qf, mf, hf, i16, ix, iy)

#define expand2b_inner(qf, mf, hf, i16, \
		i0, i1, i2, i3, i4, i5, i6, i7, i8, \
		i9, i10, i11, i12, i13, i14, i15, \
		i0m, i1m, i3m, i4m, i7m, i10m, i11m) \
	SPH_T64(qf(i0) + rb1(qf(i1)) + qf(i2) + rb2(qf(i3)) \
		+ qf(i4) + rb3(qf(i5)) + qf(i6) + rb4(qf(i7)) \
		+ qf(i8) + rb5(qf(i9)) + qf(i10) + rb6(qf(i11)) \
		+ qf(i12) + rb7(qf(i13)) + sb4(qf(i14)) + sb5(qf(i15)) \
		+ add_elt_b(mf, hf, i0m, i1m, i3m, i4m, i7m, i10m, i11m, i16))

#define expand2b(qf, mf, hf, i16) \
	expand2b_(qf, mf, hf, i16, I16_ ## i16, M16_ ## i16)
#define expand2b_(qf, mf, hf, i16, ix, iy) \
	expand2b_inner LPAR qf, mf, hf, i16, ix, iy)

#endif

#endif

#define MAKE_W(tt, i0, op01, i1, op12, i2, op23, i3, op34, i4) \
	tt((M(i0) ^ H(i0)) op01 (M(i1) ^ H(i1)) op12 (M(i2) ^ H(i2)) \
	op23 (M(i3) ^ H(i3)) op34 (M(i4) ^ H(i4)))

#define Ws0    MAKE_W(SPH_T32,  5, -,  7, +, 10, +, 13, +, 14)
#define Ws1    MAKE_W(SPH_T32,  6, -,  8, +, 11, +, 14, -, 15)
#define Ws2    MAKE_W(SPH_T32,  0, +,  7, +,  9, -, 12, +, 15)
#define Ws3    MAKE_W(SPH_T32,  0, -,  1, +,  8, -, 10, +, 13)
#define Ws4    MAKE_W(SPH_T32,  1, +,  2, +,  9, -, 11, -, 14)
#define Ws5    MAKE_W(SPH_T32,  3, -,  2, +, 10, -, 12, +, 15)
#define Ws6    MAKE_W(SPH_T32,  4, -,  0, -,  3, -, 11, +, 13)
#define Ws7    MAKE_W(SPH_T32,  1, -,  4, -,  5, -, 12, -, 14)
#define Ws8    MAKE_W(SPH_T32,  2, -,  5, -,  6, +, 13, -, 15)
#define Ws9    MAKE_W(SPH_T32,  0, -,  3, +,  6, -,  7, +, 14)
#define Ws10   MAKE_W(SPH_T32,  8, -,  1, -,  4, -,  7, +, 15)
#define Ws11   MAKE_W(SPH_T32,  8, -,  0, -,  2, -,  5, +,  9)
#define Ws12   MAKE_W(SPH_T32,  1, +,  3, -,  6, -,  9, +, 10)
#define Ws13   MAKE_W(SPH_T32,  2, +,  4, +,  7, +, 10, +, 11)
#define Ws14   MAKE_W(SPH_T32,  3, -,  5, +,  8, -, 11, -, 12)
#define Ws15   MAKE_W(SPH_T32, 12, -,  4, -,  6, -,  9, +, 13)

#if SPH_SMALL_FOOTPRINT_BMW

#define MAKE_Qas   do { \
		unsigned u; \
		sph_u32 Ws[16]; \
		Ws[ 0] = Ws0; \
		Ws[ 1] = Ws1; \
		Ws[ 2] = Ws2; \
		Ws[ 3] = Ws3; \
		Ws[ 4] = Ws4; \
		Ws[ 5] = Ws5; \
		Ws[ 6] = Ws6; \
		Ws[ 7] = Ws7; \
		Ws[ 8] = Ws8; \
		Ws[ 9] = Ws9; \
		Ws[10] = Ws10; \
		Ws[11] = Ws11; \
		Ws[12] = Ws12; \
		Ws[13] = Ws13; \
		Ws[14] = Ws14; \
		Ws[15] = Ws15; \
		for (u = 0; u < 15; u += 5) { \
			qt[u + 0] = SPH_T32(ss0(Ws[u + 0]) + H(u + 1)); \
			qt[u + 1] = SPH_T32(ss1(Ws[u + 1]) + H(u + 2)); \
			qt[u + 2] = SPH_T32(ss2(Ws[u + 2]) + H(u + 3)); \
			qt[u + 3] = SPH_T32(ss3(Ws[u + 3]) + H(u + 4)); \
			qt[u + 4] = SPH_T32(ss4(Ws[u + 4]) + H(u + 5)); \
		} \
		qt[15] = SPH_T32(ss0(Ws[15]) + H(0)); \
	} while (0)

#define MAKE_Qbs   do { \
		qt[16] = expand1s(Qs, M, H, 16); \
		qt[17] = expand1s(Qs, M, H, 17); \
		qt[18] = expand2s(Qs, M, H, 18); \
		qt[19] = expand2s(Qs, M, H, 19); \
		qt[20] = expand2s(Qs, M, H, 20); \
		qt[21] = expand2s(Qs, M, H, 21); \
		qt[22] = expand2s(Qs, M, H, 22); \
		qt[23] = expand2s(Qs, M, H, 23); \
		qt[24] = expand2s(Qs, M, H, 24); \
		qt[25] = expand2s(Qs, M, H, 25); \
		qt[26] = expand2s(Qs, M, H, 26); \
		qt[27] = expand2s(Qs, M, H, 27); \
		qt[28] = expand2s(Qs, M, H, 28); \
		qt[29] = expand2s(Qs, M, H, 29); \
		qt[30] = expand2s(Qs, M, H, 30); \
		qt[31] = expand2s(Qs, M, H, 31); \
	} while (0)

#else

#define MAKE_Qas   do { \
		qt[ 0] = SPH_T32(ss0(Ws0 ) + H( 1)); \
		qt[ 1] = SPH_T32(ss1(Ws1 ) + H( 2)); \
		qt[ 2] = SPH_T32(ss2(Ws2 ) + H( 3)); \
		qt[ 3] = SPH_T32(ss3(Ws3 ) + H( 4)); \
		qt[ 4] = SPH_T32(ss4(Ws4 ) + H( 5)); \
		qt[ 5] = SPH_T32(ss0(Ws5 ) + H( 6)); \
		qt[ 6] = SPH_T32(ss1(Ws6 ) + H( 7)); \
		qt[ 7] = SPH_T32(ss2(Ws7 ) + H( 8)); \
		qt[ 8] = SPH_T32(ss3(Ws8 ) + H( 9)); \
		qt[ 9] = SPH_T32(ss4(Ws9 ) + H(10)); \
		qt[10] = SPH_T32(ss0(Ws10) + H(11)); \
		qt[11] = SPH_T32(ss1(Ws11) + H(12)); \
		qt[12] = SPH_T32(ss2(Ws12) + H(13)); \
		qt[13] = SPH_T32(ss3(Ws13) + H(14)); \
		qt[14] = SPH_T32(ss4(Ws14) + H(15)); \
		qt[15] = SPH_T32(ss0(Ws15) + H( 0)); \
	} while (0)

#define MAKE_Qbs   do { \
		qt[16] = expand1s(Qs, M, H, 16); \
		qt[17] = expand1s(Qs, M, H, 17); \
		qt[18] = expand2s(Qs, M, H, 18); \
		qt[19] = expand2s(Qs, M, H, 19); \
		qt[20] = expand2s(Qs, M, H, 20); \
		qt[21] = expand2s(Qs, M, H, 21); \
		qt[22] = expand2s(Qs, M, H, 22); \
		qt[23] = expand2s(Qs, M, H, 23); \
		qt[24] = expand2s(Qs, M, H, 24); \
		qt[25] = expand2s(Qs, M, H, 25); \
		qt[26] = expand2s(Qs, M, H, 26); \
		qt[27] = expand2s(Qs, M, H, 27); \
		qt[28] = expand2s(Qs, M, H, 28); \
		qt[29] = expand2s(Qs, M, H, 29); \
		qt[30] = expand2s(Qs, M, H, 30); \
		qt[31] = expand2s(Qs, M, H, 31); \
	} while (0)

#endif

#define MAKE_Qs   do { \
		MAKE_Qas; \
		MAKE_Qbs; \
	} while (0)

#define Qs(j)   (qt[j])

#if SPH_64

#define Wb0    MAKE_W(SPH_T64,  5, -,  7, +, 10, +, 13, +, 14)
#define Wb1    MAKE_W(SPH_T64,  6, -,  8, +, 11, +, 14, -, 15)
#define Wb2    MAKE_W(SPH_T64,  0, +,  7, +,  9, -, 12, +, 15)
#define Wb3    MAKE_W(SPH_T64,  0, -,  1, +,  8, -, 10, +, 13)
#define Wb4    MAKE_W(SPH_T64,  1, +,  2, +,  9, -, 11, -, 14)
#define Wb5    MAKE_W(SPH_T64,  3, -,  2, +, 10, -, 12, +, 15)
#define Wb6    MAKE_W(SPH_T64,  4, -,  0, -,  3, -, 11, +, 13)
#define Wb7    MAKE_W(SPH_T64,  1, -,  4, -,  5, -, 12, -, 14)
#define Wb8    MAKE_W(SPH_T64,  2, -,  5, -,  6, +, 13, -, 15)
#define Wb9    MAKE_W(SPH_T64,  0, -,  3, +,  6, -,  7, +, 14)
#define Wb10   MAKE_W(SPH_T64,  8, -,  1, -,  4, -,  7, +, 15)
#define Wb11   MAKE_W(SPH_T64,  8, -,  0, -,  2, -,  5, +,  9)
#define Wb12   MAKE_W(SPH_T64,  1, +,  3, -,  6, -,  9, +, 10)
#define Wb13   MAKE_W(SPH_T64,  2, +,  4, +,  7, +, 10, +, 11)
#define Wb14   MAKE_W(SPH_T64,  3, -,  5, +,  8, -, 11, -, 12)
#define Wb15   MAKE_W(SPH_T64, 12, -,  4, -,  6, -,  9, +, 13)

#if SPH_SMALL_FOOTPRINT_BMW

#define MAKE_Qab   do { \
		unsigned u; \
		sph_u64 Wb[16]; \
		Wb[ 0] = Wb0; \
		Wb[ 1] = Wb1; \
		Wb[ 2] = Wb2; \
		Wb[ 3] = Wb3; \
		Wb[ 4] = Wb4; \
		Wb[ 5] = Wb5; \
		Wb[ 6] = Wb6; \
		Wb[ 7] = Wb7; \
		Wb[ 8] = Wb8; \
		Wb[ 9] = Wb9; \
		Wb[10] = Wb10; \
		Wb[11] = Wb11; \
		Wb[12] = Wb12; \
		Wb[13] = Wb13; \
		Wb[14] = Wb14; \
		Wb[15] = Wb15; \
		for (u = 0; u < 15; u += 5) { \
			qt[u + 0] = SPH_T64(sb0(Wb[u + 0]) + H(u + 1)); \
			qt[u + 1] = SPH_T64(sb1(Wb[u + 1]) + H(u + 2)); \
			qt[u + 2] = SPH_T64(sb2(Wb[u + 2]) + H(u + 3)); \
			qt[u + 3] = SPH_T64(sb3(Wb[u + 3]) + H(u + 4)); \
			qt[u + 4] = SPH_T64(sb4(Wb[u + 4]) + H(u + 5)); \
		} \
		qt[15] = SPH_T64(sb0(Wb[15]) + H(0)); \
	} while (0)

#define MAKE_Qbb   do { \
		unsigned u; \
		for (u = 16; u < 18; u ++) \
			qt[u] = expand1b(Qb, M, H, u); \
		for (u = 18; u < 32; u ++) \
			qt[u] = expand2b(Qb, M, H, u); \
	} while (0)

#else

#define MAKE_Qab   do { \
		qt[ 0] = SPH_T64(sb0(Wb0 ) + H( 1)); \
		qt[ 1] = SPH_T64(sb1(Wb1 ) + H( 2)); \
		qt[ 2] = SPH_T64(sb2(Wb2 ) + H( 3)); \
		qt[ 3] = SPH_T64(sb3(Wb3 ) + H( 4)); \
		qt[ 4] = SPH_T64(sb4(Wb4 ) + H( 5)); \
		qt[ 5] = SPH_T64(sb0(Wb5 ) + H( 6)); \
		qt[ 6] = SPH_T64(sb1(Wb6 ) + H( 7)); \
		qt[ 7] = SPH_T64(sb2(Wb7 ) + H( 8)); \
		qt[ 8] = SPH_T64(sb3(Wb8 ) + H( 9)); \
		qt[ 9] = SPH_T64(sb4(Wb9 ) + H(10)); \
		qt[10] = SPH_T64(sb0(Wb10) + H(11)); \
		qt[11] = SPH_T64(sb1(Wb11) + H(12)); \
		qt[12] = SPH_T64(sb2(Wb12) + H(13)); \
		qt[13] = SPH_T64(sb3(Wb13) + H(14)); \
		qt[14] = SPH_T64(sb4(Wb14) + H(15)); \
		qt[15] = SPH_T64(sb0(Wb15) + H( 0)); \
	} while (0)

#define MAKE_Qbb   do { \
		qt[16] = expand1b(Qb, M, H, 16); \
		qt[17] = expand1b(Qb, M, H, 17); \
		qt[18] = expand2b(Qb, M, H, 18); \
		qt[19] = expand2b(Qb, M, H, 19); \
		qt[20] = expand2b(Qb, M, H, 20); \
		qt[21] = expand2b(Qb, M, H, 21); \
		qt[22] = expand2b(Qb, M, H, 22); \
		qt[23] = expand2b(Qb, M, H, 23); \
		qt[24] = expand2b(Qb, M, H, 24); \
		qt[25] = expand2b(Qb, M, H, 25); \
		qt[26] = expand2b(Qb, M, H, 26); \
		qt[27] = expand2b(Qb, M, H, 27); \
		qt[28] = expand2b(Qb, M, H, 28); \
		qt[29] = expand2b(Qb, M, H, 29); \
		qt[30] = expand2b(Qb, M, H, 30); \
		qt[31] = expand2b(Qb, M, H, 31); \
	} while (0)

#endif

#define MAKE_Qb   do { \
		MAKE_Qab; \
		MAKE_Qbb; \
	} while (0)

#define Qb(j)   (qt[j])

#endif

#define FOLD(type, mkQ, tt, rol, mf, qf, dhf)   do { \
		type qt[32], xl, xh; \
		mkQ; \
		xl = qf(16) ^ qf(17) ^ qf(18) ^ qf(19) \
			^ qf(20) ^ qf(21) ^ qf(22) ^ qf(23); \
		xh = xl ^ qf(24) ^ qf(25) ^ qf(26) ^ qf(27) \
			^ qf(28) ^ qf(29) ^ qf(30) ^ qf(31); \
		dhf( 0) = tt(((xh <<  5) ^ (qf(16) >>  5) ^ mf( 0)) \
			+ (xl ^ qf(24) ^ qf( 0))); \
		dhf( 1) = tt(((xh >>  7) ^ (qf(17) <<  8) ^ mf( 1)) \
			+ (xl ^ qf(25) ^ qf( 1))); \
		dhf( 2) = tt(((xh >>  5) ^ (qf(18) <<  5) ^ mf( 2)) \
			+ (xl ^ qf(26) ^ qf( 2))); \
		dhf( 3) = tt(((xh >>  1) ^ (qf(19) <<  5) ^ mf( 3)) \
			+ (xl ^ qf(27) ^ qf( 3))); \
		dhf( 4) = tt(((xh >>  3) ^ (qf(20) <<  0) ^ mf( 4)) \
			+ (xl ^ qf(28) ^ qf( 4))); \
		dhf( 5) = tt(((xh <<  6) ^ (qf(21) >>  6) ^ mf( 5)) \
			+ (xl ^ qf(29) ^ qf( 5))); \
		dhf( 6) = tt(((xh >>  4) ^ (qf(22) <<  6) ^ mf( 6)) \
			+ (xl ^ qf(30) ^ qf( 6))); \
		dhf( 7) = tt(((xh >> 11) ^ (qf(23) <<  2) ^ mf( 7)) \
			+ (xl ^ qf(31) ^ qf( 7))); \
		dhf( 8) = tt(rol(dhf(4),  9) + (xh ^ qf(24) ^ mf( 8)) \
			+ ((xl << 8) ^ qf(23) ^ qf( 8))); \
		dhf( 9) = tt(rol(dhf(5), 10) + (xh ^ qf(25) ^ mf( 9)) \
			+ ((xl >> 6) ^ qf(16) ^ qf( 9))); \
		dhf(10) = tt(rol(dhf(6), 11) + (xh ^ qf(26) ^ mf(10)) \
			+ ((xl << 6) ^ qf(17) ^ qf(10))); \
		dhf(11) = tt(rol(dhf(7), 12) + (xh ^ qf(27) ^ mf(11)) \
			+ ((xl << 4) ^ qf(18) ^ qf(11))); \
		dhf(12) = tt(rol(dhf(0), 13) + (xh ^ qf(28) ^ mf(12)) \
			+ ((xl >> 3) ^ qf(19) ^ qf(12))); \
		dhf(13) = tt(rol(dhf(1), 14) + (xh ^ qf(29) ^ mf(13)) \
			+ ((xl >> 4) ^ qf(20) ^ qf(13))); \
		dhf(14) = tt(rol(dhf(2), 15) + (xh ^ qf(30) ^ mf(14)) \
			+ ((xl >> 7) ^ qf(21) ^ qf(14))); \
		dhf(15) = tt(rol(dhf(3), 16) + (xh ^ qf(31) ^ mf(15)) \
			+ ((xl >> 2) ^ qf(22) ^ qf(15))); \
	} while (0)

#define FOLDs   FOLD(sph_u32, MAKE_Qs, SPH_T32, SPH_ROTL32, M, Qs, dH)

#if SPH_64

#define FOLDb   FOLD(sph_u64, MAKE_Qb, SPH_T64, SPH_ROTL64, M, Qb, dH)

#endif

static void
compress_small(const unsigned char *data, const sph_u32 h[16], sph_u32 dh[16])
{
#if SPH_LITTLE_FAST
#define M(x)    sph_dec32le_aligned(data + 4 * (x))
#else
	sph_u32 mv[16];

	mv[ 0] = sph_dec32le_aligned(data +  0);
	mv[ 1] = sph_dec32le_aligned(data +  4);
	mv[ 2] = sph_dec32le_aligned(data +  8);
	mv[ 3] = sph_dec32le_aligned(data + 12);
	mv[ 4] = sph_dec32le_aligned(data + 16);
	mv[ 5] = sph_dec32le_aligned(data + 20);
	mv[ 6] = sph_dec32le_aligned(data + 24);
	mv[ 7] = sph_dec32le_aligned(data + 28);
	mv[ 8] = sph_dec32le_aligned(data + 32);
	mv[ 9] = sph_dec32le_aligned(data + 36);
	mv[10] = sph_dec32le_aligned(data + 40);
	mv[11] = sph_dec32le_aligned(data + 44);
	mv[12] = sph_dec32le_aligned(data + 48);
	mv[13] = sph_dec32le_aligned(data + 52);
	mv[14] = sph_dec32le_aligned(data + 56);
	mv[15] = sph_dec32le_aligned(data + 60);
#define M(x)    (mv[x])
#endif
#define H(x)    (h[x])
#define dH(x)   (dh[x])

	FOLDs;

#undef M
#undef H
#undef dH
}

static const sph_u32 final_s[16] = {
	SPH_C32(0xaaaaaaa0), SPH_C32(0xaaaaaaa1), SPH_C32(0xaaaaaaa2),
	SPH_C32(0xaaaaaaa3), SPH_C32(0xaaaaaaa4), SPH_C32(0xaaaaaaa5),
	SPH_C32(0xaaaaaaa6), SPH_C32(0xaaaaaaa7), SPH_C32(0xaaaaaaa8),
	SPH_C32(0xaaaaaaa9), SPH_C32(0xaaaaaaaa), SPH_C32(0xaaaaaaab),
	SPH_C32(0xaaaaaaac), SPH_C32(0xaaaaaaad), SPH_C32(0xaaaaaaae),
	SPH_C32(0xaaaaaaaf)
};

static void
bmw32_init(sph_bmw_small_context *sc, const sph_u32 *iv)
{
	memcpy(sc->H, iv, sizeof sc->H);
	sc->ptr = 0;
#if SPH_64
	sc->bit_count = 0;
#else
	sc->bit_count_high = 0;
	sc->bit_count_low = 0;
#endif
}

static void
bmw32(sph_bmw_small_context *sc, const void *data, size_t len)
{
	unsigned char *buf;
	size_t ptr;
	sph_u32 htmp[16];
	sph_u32 *h1, *h2;
#if !SPH_64
	sph_u32 tmp;
#endif

#if SPH_64
	sc->bit_count += (sph_u64)len << 3;
#else
	tmp = sc->bit_count_low;
	sc->bit_count_low = SPH_T32(tmp + ((sph_u32)len << 3));
	if (sc->bit_count_low < tmp)
		sc->bit_count_high ++;
	sc->bit_count_high += len >> 29;
#endif
	buf = sc->buf;
	ptr = sc->ptr;
	h1 = sc->H;
	h2 = htmp;
	while (len > 0) {
		size_t clen;

		clen = (sizeof sc->buf) - ptr;
		if (clen > len)
			clen = len;
		memcpy(buf + ptr, data, clen);
		data = (const unsigned char *)data + clen;
		len -= clen;
		ptr += clen;
		if (ptr == sizeof sc->buf) {
			sph_u32 *ht;

			compress_small(buf, h1, h2);
			ht = h1;
			h1 = h2;
			h2 = ht;
			ptr = 0;
		}
	}
	sc->ptr = ptr;
	if (h1 != sc->H)
		memcpy(sc->H, h1, sizeof sc->H);
}

static void
bmw32_close(sph_bmw_small_context *sc, unsigned ub, unsigned n,
	void *dst, size_t out_size_w32)
{
	unsigned char *buf, *out;
	size_t ptr, u, v;
	unsigned z;
	sph_u32 h1[16], h2[16], *h;

	buf = sc->buf;
	ptr = sc->ptr;
	z = 0x80 >> n;
	buf[ptr ++] = ((ub & -z) | z) & 0xFF;
	h = sc->H;
	if (ptr > (sizeof sc->buf) - 8) {
		memset(buf + ptr, 0, (sizeof sc->buf) - ptr);
		compress_small(buf, h, h1);
		ptr = 0;
		h = h1;
	}
	memset(buf + ptr, 0, (sizeof sc->buf) - 8 - ptr);
#if SPH_64
	sph_enc64le_aligned(buf + (sizeof sc->buf) - 8,
		SPH_T64(sc->bit_count + n));
#else
	sph_enc32le_aligned(buf + (sizeof sc->buf) - 8,
		sc->bit_count_low + n);
	sph_enc32le_aligned(buf + (sizeof sc->buf) - 4,
		SPH_T32(sc->bit_count_high));
#endif
	compress_small(buf, h, h2);
	for (u = 0; u < 16; u ++)
		sph_enc32le_aligned(buf + 4 * u, h2[u]);
	compress_small(buf, final_s, h1);
	out = dst;
	for (u = 0, v = 16 - out_size_w32; u < out_size_w32; u ++, v ++)
		sph_enc32le(out + 4 * u, h1[v]);
}

#if SPH_64

static void
compress_big(const unsigned char *data, const sph_u64 h[16], sph_u64 dh[16])
{
#if SPH_LITTLE_FAST
#define M(x)    sph_dec64le_aligned(data + 8 * (x))
#else
	sph_u64 mv[16];

	mv[ 0] = sph_dec64le_aligned(data +   0);
	mv[ 1] = sph_dec64le_aligned(data +   8);
	mv[ 2] = sph_dec64le_aligned(data +  16);
	mv[ 3] = sph_dec64le_aligned(data +  24);
	mv[ 4] = sph_dec64le_aligned(data +  32);
	mv[ 5] = sph_dec64le_aligned(data +  40);
	mv[ 6] = sph_dec64le_aligned(data +  48);
	mv[ 7] = sph_dec64le_aligned(data +  56);
	mv[ 8] = sph_dec64le_aligned(data +  64);
	mv[ 9] = sph_dec64le_aligned(data +  72);
	mv[10] = sph_dec64le_aligned(data +  80);
	mv[11] = sph_dec64le_aligned(data +  88);
	mv[12] = sph_dec64le_aligned(data +  96);
	mv[13] = sph_dec64le_aligned(data + 104);
	mv[14] = sph_dec64le_aligned(data + 112);
	mv[15] = sph_dec64le_aligned(data + 120);
#define M(x)    (mv[x])
#endif
#define H(x)    (h[x])
#define dH(x)   (dh[x])

	FOLDb;

#undef M
#undef H
#undef dH
}

static const sph_u64 final_b[16] = {
	SPH_C64(0xaaaaaaaaaaaaaaa0), SPH_C64(0xaaaaaaaaaaaaaaa1),
	SPH_C64(0xaaaaaaaaaaaaaaa2), SPH_C64(0xaaaaaaaaaaaaaaa3),
	SPH_C64(0xaaaaaaaaaaaaaaa4), SPH_C64(0xaaaaaaaaaaaaaaa5),
	SPH_C64(0xaaaaaaaaaaaaaaa6), SPH_C64(0xaaaaaaaaaaaaaaa7),
	SPH_C64(0xaaaaaaaaaaaaaaa8), SPH_C64(0xaaaaaaaaaaaaaaa9),
	SPH_C64(0xaaaaaaaaaaaaaaaa), SPH_C64(0xaaaaaaaaaaaaaaab),
	SPH_C64(0xaaaaaaaaaaaaaaac), SPH_C64(0xaaaaaaaaaaaaaaad),
	SPH_C64(0xaaaaaaaaaaaaaaae), SPH_C64(0xaaaaaaaaaaaaaaaf)
};

static void
bmw64_init(sph_bmw_big_context *sc, const sph_u64 *iv)
{
	memcpy(sc->H, iv, sizeof sc->H);
	sc->ptr = 0;
	sc->bit_count = 0;
}

static void
bmw64(sph_bmw_big_context *sc, const void *data, size_t len)
{
	unsigned char *buf;
	size_t ptr;
	sph_u64 htmp[16];
	sph_u64 *h1, *h2;

	sc->bit_count += (sph_u64)len << 3;
	buf = sc->buf;
	ptr = sc->ptr;
	h1 = sc->H;
	h2 = htmp;
	while (len > 0) {
		size_t clen;

		clen = (sizeof sc->buf) - ptr;
		if (clen > len)
			clen = len;
		memcpy(buf + ptr, data, clen);
		data = (const unsigned char *)data + clen;
		len -= clen;
		ptr += clen;
		if (ptr == sizeof sc->buf) {
			sph_u64 *ht;

			compress_big(buf, h1, h2);
			ht = h1;
			h1 = h2;
			h2 = ht;
			ptr = 0;
		}
	}
	sc->ptr = ptr;
	if (h1 != sc->H)
		memcpy(sc->H, h1, sizeof sc->H);
}

static void
bmw64_close(sph_bmw_big_context *sc, unsigned ub, unsigned n,
	void *dst, size_t out_size_w64)
{
	unsigned char *buf, *out;
	size_t ptr, u, v;
	unsigned z;
	sph_u64 h1[16], h2[16], *h;

	buf = sc->buf;
	ptr = sc->ptr;
	z = 0x80 >> n;
	buf[ptr ++] = ((ub & -z) | z) & 0xFF;
	h = sc->H;
	if (ptr > (sizeof sc->buf) - 8) {
		memset(buf + ptr, 0, (sizeof sc->buf) - ptr);
		compress_big(buf, h, h1);
		ptr = 0;
		h = h1;
	}
	memset(buf + ptr, 0, (sizeof sc->buf) - 8 - ptr);
	sph_enc64le_aligned(buf + (sizeof sc->buf) - 8,
		SPH_T64(sc->bit_count + n));
	compress_big(buf, h, h2);
	for (u = 0; u < 16; u ++)
		sph_enc64le_aligned(buf + 8 * u, h2[u]);
	compress_big(buf, final_b, h1);
	out = dst;
	for (u = 0, v = 16 - out_size_w64; u < out_size_w64; u ++, v ++)
		sph_enc64le(out + 8 * u, h1[v]);
}

#endif

/* see sph_bmw.h */
void
sph_bmw224_init(void *cc)
{
	bmw32_init(cc, IV224);
}

/* see sph_bmw.h */
void
sph_bmw224(void *cc, const void *data, size_t len)
{
	bmw32(cc, data, len);
}

/* see sph_bmw.h */
void
sph_bmw224_close(void *cc, void *dst)
{
	sph_bmw224_addbits_and_close(cc, 0, 0, dst);
}

/* see sph_bmw.h */
void
sph_bmw224_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	bmw32_close(cc, ub, n, dst, 7);
	sph_bmw224_init(cc);
}

/* see sph_bmw.h */
void
sph_bmw256_init(void *cc)
{
	bmw32_init(cc, IV256);
}

/* see sph_bmw.h */
void
sph_bmw256(void *cc, const void *data, size_t len)
{
	bmw32(cc, data, len);
}

#ifndef SSE
#define XOR(a,b) _mm256_xor_si256((a), (b))
#define ADD(a,b) _mm256_add_epi32((a), (b))
#define SUB(a,b) _mm256_sub_epi32((a), (b))
#define ROTL32_AVX(a,b) _mm256_or_si256(_mm256_slli_epi32((a),(b)),_mm256_srli_epi32((a),32-(b)))
#define ROTL32v_AVX_1(a) _mm256_or_si256(_mm256_sll_epi32((a),(r0)),_mm256_srl_epi32((a),(r3)))
#define ROTL32v_AVX_2(a) _mm256_or_si256(_mm256_sll_epi32((a),(r1)),_mm256_srl_epi32((a),(r4)))
#define ROTL32v_AVX_3(a) _mm256_or_si256(_mm256_sll_epi32((a),(r2)),_mm256_srl_epi32((a),(r5)))
#define ss0_AVX(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32((x), 1), _mm256_slli_epi32((x), 3)), ROTL32_AVX((x), 4)), ROTL32_AVX((x), 19))
#define ss1_AVX(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32((x), 1), _mm256_slli_epi32((x), 2)), ROTL32_AVX((x), 8)), ROTL32_AVX((x), 23))
#define ss2_AVX(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32((x), 2), _mm256_slli_epi32((x), 1)), ROTL32_AVX((x), 12)), ROTL32_AVX((x), 25))
#define ss3_AVX(x) _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_srli_epi32((x), 2), _mm256_slli_epi32((x), 2)), ROTL32_AVX((x), 15)), ROTL32_AVX((x), 29))
#define ss4_AVX(x) _mm256_xor_si256(_mm256_srli_epi32((x), 1), (x))
#define ss5_AVX(x) _mm256_xor_si256(_mm256_srli_epi32((x), 2), (x))
#define rs1_AVX(x) ROTL32_AVX((x),  3)
#define rs2_AVX(x) ROTL32_AVX((x),  7)
#define rs3_AVX(x) ROTL32_AVX((x), 13)
#define rs4_AVX(x) ROTL32_AVX((x), 16)
#define rs5_AVX(x) ROTL32_AVX((x), 19)
#define rs6_AVX(x) ROTL32_AVX((x), 23)
#define rs7_AVX(x) ROTL32_AVX((x), 27)
#define bswap32_AVX(x) 	_mm256_or_si256(_mm256_or_si256(_mm256_and_si256(_mm256_slli_epi32(x, 24), _mm256_set1_epi32(0xff000000u)), _mm256_and_si256(_mm256_slli_epi32(x, 8), _mm256_set1_epi32(0x00ff0000u))),\
	_mm256_or_si256(_mm256_and_si256(_mm256_srli_epi32(x, 8), _mm256_set1_epi32(0x0000ff00u)), _mm256_and_si256(_mm256_srli_epi32(x, 24), _mm256_set1_epi32(0x000000ffu))))

void
sph_bmw256_AVX(void *cc, const void *data, size_t len)
{
	__m256i M32[16];
	M32[0] = ((__m256i*)data)[0];
	M32[1] = ((__m256i*)data)[1];
	M32[2] = ((__m256i*)data)[2];
	M32[3] = ((__m256i*)data)[3];
	M32[4] = ((__m256i*)data)[4];
	M32[5] = ((__m256i*)data)[5];
	M32[6] = ((__m256i*)data)[6];
	M32[7] = ((__m256i*)data)[7];

	M32[8] = _mm256_set1_epi32(0x80);
	M32[14] = _mm256_set1_epi32(0x100ULL);
	M32[9] = M32[10] = M32[11] = M32[12] = M32[13] = M32[15] = _mm256_setzero_si256();

	__m256i Q[32], XL32, XH32;
	__m256i H[16];
	H[0] = _mm256_set1_epi32(0x40414243);
	H[1] = _mm256_set1_epi32(0x44454647);
	H[2] = _mm256_set1_epi32(0x48494A4B);
	H[3] = _mm256_set1_epi32(0x4C4D4E4F);
	H[4] = _mm256_set1_epi32(0x50515253);
	H[5] = _mm256_set1_epi32(0x54555657);
	H[6] = _mm256_set1_epi32(0x58595A5B);
	H[7] = _mm256_set1_epi32(0x5C5D5E5F);
	H[8] = _mm256_set1_epi32(0x60616263);
	H[9] = _mm256_set1_epi32(0x64656667);
	H[10] = _mm256_set1_epi32(0x68696A6B);
	H[11] = _mm256_set1_epi32(0x6C6D6E6F);
	H[12] = _mm256_set1_epi32(0x70717273);
	H[13] = _mm256_set1_epi32(0x74757677);
	H[14] = _mm256_set1_epi32(0x78797A7B);
	H[15] = _mm256_set1_epi32(0x7C7D7E7F);

	Q[0] = ADD(ADD(ADD(SUB(XOR(M32[5], H[5]), XOR(M32[7], H[7])), XOR(M32[10], H[10])), XOR(M32[13], H[13])), XOR(M32[14], H[14]));
	Q[1] = SUB(ADD(ADD(SUB(XOR(M32[6], H[6]), XOR(M32[8], H[8])), XOR(M32[11], H[11])), XOR(M32[14], H[14])), XOR(M32[15], H[15]));
	Q[2] = ADD(SUB(ADD(ADD(XOR(M32[0], H[0]), XOR(M32[7], H[7])), XOR(M32[9], H[9])), XOR(M32[12], H[12])), XOR(M32[15], H[15]));
	Q[3] = ADD(SUB(ADD(SUB(XOR(M32[0], H[0]), XOR(M32[1], H[1])), XOR(M32[8], H[8])), XOR(M32[10], H[10])), XOR(M32[13], H[13]));
	Q[4] = SUB(SUB(ADD(ADD(XOR(M32[1], H[1]), XOR(M32[2], H[2])), XOR(M32[9], H[9])), XOR(M32[11], H[11])), XOR(M32[14], H[14]));
	Q[5] = ADD(SUB(ADD(SUB(XOR(M32[3], H[3]), XOR(M32[2], H[2])), XOR(M32[10], H[10])), XOR(M32[12], H[12])), XOR(M32[15], H[15]));
	Q[6] = ADD(SUB(SUB(SUB(XOR(M32[4], H[4]), XOR(M32[0], H[0])), XOR(M32[3], H[3])), XOR(M32[11], H[11])), XOR(M32[13], H[13]));
	Q[7] = SUB(SUB(SUB(SUB(XOR(M32[1], H[1]), XOR(M32[4], H[4])), XOR(M32[5], H[5])), XOR(M32[12], H[12])), XOR(M32[14], H[14]));
	Q[8] = SUB(ADD(SUB(SUB(XOR(M32[2], H[2]), XOR(M32[5], H[5])), XOR(M32[6], H[6])), XOR(M32[13], H[13])), XOR(M32[15], H[15]));
	Q[9] = ADD(SUB(ADD(SUB(XOR(M32[0], H[0]), XOR(M32[3], H[3])), XOR(M32[6], H[6])), XOR(M32[7], H[7])), XOR(M32[14], H[14]));
	Q[10] = ADD(SUB(SUB(SUB(XOR(M32[8], H[8]), XOR(M32[1], H[1])), XOR(M32[4], H[4])), XOR(M32[7], H[7])), XOR(M32[15], H[15]));
	Q[11] = ADD(SUB(SUB(SUB(XOR(M32[8], H[8]), XOR(M32[0], H[0])), XOR(M32[2], H[2])), XOR(M32[5], H[5])), XOR(M32[9], H[9]));
	Q[12] = ADD(SUB(SUB(ADD(XOR(M32[1], H[1]), XOR(M32[3], H[3])), XOR(M32[6], H[6])), XOR(M32[9], H[9])), XOR(M32[10], H[10]));
	Q[13] = ADD(ADD(ADD(ADD(XOR(M32[2], H[2]), XOR(M32[4], H[4])), XOR(M32[7], H[7])), XOR(M32[10], H[10])), XOR(M32[11], H[11]));
	Q[14] = SUB(SUB(ADD(SUB(XOR(M32[3], H[3]), XOR(M32[5], H[5])), XOR(M32[8], H[8])), XOR(M32[11], H[11])), XOR(M32[12], H[12]));
	Q[15] = ADD(SUB(SUB(SUB(XOR(M32[12], H[12]), XOR(M32[4], H[4])), XOR(M32[6], H[6])), XOR(M32[9], H[9])), XOR(M32[13], H[13]));

	/*  Diffuse the differences in every word in a bijective manner with ssi, and then add the values of the previous double pipe. */
	Q[0] = _mm256_add_epi32(ss0_AVX(Q[0]), H[1]);
	Q[1] = _mm256_add_epi32(ss1_AVX(Q[1]), H[2]);
	Q[2] = _mm256_add_epi32(ss2_AVX(Q[2]), H[3]);
	Q[3] = _mm256_add_epi32(ss3_AVX(Q[3]), H[4]);
	Q[4] = _mm256_add_epi32(ss4_AVX(Q[4]), H[5]);
	Q[5] = _mm256_add_epi32(ss0_AVX(Q[5]), H[6]);
	Q[6] = _mm256_add_epi32(ss1_AVX(Q[6]), H[7]);
	Q[7] = _mm256_add_epi32(ss2_AVX(Q[7]), H[8]);
	Q[8] = _mm256_add_epi32(ss3_AVX(Q[8]), H[9]);
	Q[9] = _mm256_add_epi32(ss4_AVX(Q[9]), H[10]);
	Q[10] = _mm256_add_epi32(ss0_AVX(Q[10]), H[11]);
	Q[11] = _mm256_add_epi32(ss1_AVX(Q[11]), H[12]);
	Q[12] = _mm256_add_epi32(ss2_AVX(Q[12]), H[13]);
	Q[13] = _mm256_add_epi32(ss3_AVX(Q[13]), H[14]);
	Q[14] = _mm256_add_epi32(ss4_AVX(Q[14]), H[15]);
	Q[15] = _mm256_add_epi32(ss0_AVX(Q[15]), H[0]);

	/* This is the Message expansion or f_1 in the documentation.       */
	/* It has 16 rounds.                                                */
	/* Blue Midnight Wish has two tunable security parameters.          */
	/* The parameters are named EXPAND_1_ROUNDS and EXPAND_2_ROUNDS.    */
	/* The following relation for these parameters should is satisfied: */
	/* EXPAND_1_ROUNDS + EXPAND_2_ROUNDS = 16                           */

	for (int i = 16; i < 18; i++)
	{
		__m128i r0 = _mm_setr_epi32(((i - 16) & 15) + 1,0,0,0);
		__m128i r1 = _mm_setr_epi32(((i - 13) & 15) + 1, 0, 0, 0);
		__m128i r2 = _mm_setr_epi32(((i - 6) & 15) + 1, 0, 0, 0);
		__m128i r3 = _mm_setr_epi32(32 - (((i - 16) & 15) + 1), 0, 0, 0);
		__m128i r4 = _mm_setr_epi32(32 - (((i - 13) & 15) + 1), 0, 0, 0);
		__m128i r5 = _mm_setr_epi32(32 - (((i - 6) & 15) + 1), 0, 0, 0);

		Q[i] = ADD(ADD(ss1_AVX(Q[i - 16]), ss2_AVX(Q[i - 15])), ADD(ss3_AVX(Q[i - 14]), ss0_AVX(Q[i - 13])));
		Q[i] = ADD(Q[i], ADD(ADD(ss1_AVX(Q[i - 12]), ss2_AVX(Q[i - 11])), ADD(ss3_AVX(Q[i - 10]), ss0_AVX(Q[i - 9]))));
		Q[i] = ADD(Q[i], ADD(ADD(ss1_AVX(Q[i - 8]), ss2_AVX(Q[i - 7])), ADD(ss3_AVX(Q[i - 6]), ss0_AVX(Q[i - 5]))));
		Q[i] = ADD(Q[i], ADD(ADD(ss1_AVX(Q[i - 4]), ss2_AVX(Q[i - 3])), ADD(ss3_AVX(Q[i - 2]), ss0_AVX(Q[i - 1]))));
		Q[i] = ADD(Q[i], XOR(SUB(ADD(ADD(_mm256_set1_epi32(i*(0x05555555ul)), ROTL32v_AVX_1(M32[(i - 16) & 15])), ROTL32v_AVX_2(M32[(i - 13) & 15])), ROTL32v_AVX_3(M32[(i - 6) & 15])), H[(i - 16 + 7) & 15]));
	}
	for (int i = 18; i < 32; i++)
	{
		__m128i r0 = _mm_setr_epi32(((i - 16) & 15) + 1, 0, 0, 0);
		__m128i r1 = _mm_setr_epi32(((i - 13) & 15) + 1, 0, 0, 0);
		__m128i r2 = _mm_setr_epi32(((i - 6) & 15) + 1, 0, 0, 0);
		__m128i r3 = _mm_setr_epi32(32 - (((i - 16) & 15) + 1), 0, 0, 0);
		__m128i r4 = _mm_setr_epi32(32 - (((i - 13) & 15) + 1), 0, 0, 0);
		__m128i r5 = _mm_setr_epi32(32 - (((i - 6) & 15) + 1), 0, 0, 0);

		Q[i] = ADD(ADD(Q[i - 16], rs1_AVX(Q[i - 15])), ADD(Q[i - 14], rs2_AVX(Q[i - 13])));
		Q[i] = ADD(Q[i], ADD(ADD(Q[i - 12], rs3_AVX(Q[i - 11])), ADD(Q[i - 10], rs4_AVX(Q[i - 9]))));
		Q[i] = ADD(Q[i], ADD(ADD(Q[i - 8], rs5_AVX(Q[i - 7])), ADD(Q[i - 6], rs6_AVX(Q[i - 5]))));
		Q[i] = ADD(Q[i], ADD(ADD(Q[i - 4], rs7_AVX(Q[i - 3])), ADD(ss4_AVX(Q[i - 2]), ss5_AVX(Q[i - 1]))));
		Q[i] = ADD(Q[i], XOR(SUB(ADD(ADD(_mm256_set1_epi32(i*(0x05555555ul)), ROTL32v_AVX_1(M32[(i - 16) & 15])), ROTL32v_AVX_2(M32[(i - 13) & 15])), ROTL32v_AVX_3(M32[(i - 6) & 15])), H[(i - 16 + 7) & 15]));
	}

	/* Blue Midnight Wish has two temporary cummulative variables that accumulate via XORing */
	/* 16 new variables that are prooduced in the Message Expansion part.                    */
	XL32 = Q[16];
	for (int i = 17; i < 24; i++)
		XL32 = _mm256_xor_si256(XL32, Q[i]);
	XH32 = XL32;
	for (int i = 24; i < 32; i++)
		XH32 = _mm256_xor_si256(XH32, Q[i]);

	/*  This part is the function f_2 - in the documentation            */

	/*  Compute the double chaining pipe for the next message block.    */
	M32[0] = ADD(XOR(XOR(_mm256_slli_epi32(XH32, 5), _mm256_srli_epi32(Q[16], 5)), M32[0]), XOR(XOR(XL32, Q[24]), Q[0]));
	M32[1] = ADD(XOR(XOR(_mm256_srli_epi32(XH32, 7), _mm256_slli_epi32(Q[17], 8)), M32[1]), XOR(XOR(XL32, Q[25]), Q[1]));
	M32[2] = ADD(XOR(XOR(_mm256_srli_epi32(XH32, 5), _mm256_slli_epi32(Q[18], 5)), M32[2]), XOR(XOR(XL32, Q[26]), Q[2]));
	M32[3] = ADD(XOR(XOR(_mm256_srli_epi32(XH32, 1), _mm256_slli_epi32(Q[19], 5)), M32[3]), XOR(XOR(XL32, Q[27]), Q[3]));
	M32[4] = ADD(XOR(XOR(_mm256_srli_epi32(XH32, 3), Q[20]), M32[4]), XOR(XOR(XL32, Q[28]), Q[4]));
	M32[5] = ADD(XOR(XOR(_mm256_slli_epi32(XH32, 6), _mm256_srli_epi32(Q[21], 6)), M32[5]), XOR(XOR(XL32, Q[29]), Q[5]));
	M32[6] = ADD(XOR(XOR(_mm256_srli_epi32(XH32, 4), _mm256_slli_epi32(Q[22], 6)), M32[6]), XOR(XOR(XL32, Q[30]), Q[6]));
	M32[7] = ADD(XOR(XOR(_mm256_srli_epi32(XH32, 11), _mm256_slli_epi32(Q[23], 2)), M32[7]), XOR(XOR(XL32, Q[31]), Q[7]));
	M32[8] = ADD(ADD(ROTL32_AVX(M32[4], 9), XOR(XOR(XH32, Q[24]), M32[8])), XOR(XOR(_mm256_slli_epi32(XL32, 8), Q[23]), Q[8]));
	M32[9] = ADD(ADD(ROTL32_AVX(M32[5], 10), XOR(XOR(XH32, Q[25]), M32[9])), XOR(XOR(_mm256_srli_epi32(XL32, 6), Q[16]), Q[9]));
	M32[10] = ADD(ADD(ROTL32_AVX(M32[6], 11), XOR(XOR(XH32, Q[26]), M32[10])), XOR(XOR(_mm256_slli_epi32(XL32, 6), Q[17]), Q[10]));
	M32[11] = ADD(ADD(ROTL32_AVX(M32[7], 12), XOR(XOR(XH32, Q[27]), M32[11])), XOR(XOR(_mm256_slli_epi32(XL32, 4), Q[18]), Q[11]));
	M32[12] = ADD(ADD(ROTL32_AVX(M32[0], 13), XOR(XOR(XH32, Q[28]), M32[12])), XOR(XOR(_mm256_srli_epi32(XL32, 3), Q[19]), Q[12]));
	M32[13] = ADD(ADD(ROTL32_AVX(M32[1], 14), XOR(XOR(XH32, Q[29]), M32[13])), XOR(XOR(_mm256_srli_epi32(XL32, 4), Q[20]), Q[13]));
	M32[14] = ADD(ADD(ROTL32_AVX(M32[2], 15), XOR(XOR(XH32, Q[30]), M32[14])), XOR(XOR(_mm256_srli_epi32(XL32, 7), Q[21]), Q[14]));
	M32[15] = ADD(ADD(ROTL32_AVX(M32[3], 16), XOR(XOR(XH32, Q[31]), M32[15])), XOR(XOR(_mm256_srli_epi32(XL32, 2), Q[22]), Q[15]));

	H[0] = _mm256_set1_epi32(0xaaaaaaa0);
	H[1] = _mm256_set1_epi32(0xaaaaaaa1);
	H[2] = _mm256_set1_epi32(0xaaaaaaa2);
	H[3] = _mm256_set1_epi32(0xaaaaaaa3);
	H[4] = _mm256_set1_epi32(0xaaaaaaa4);
	H[5] = _mm256_set1_epi32(0xaaaaaaa5);
	H[6] = _mm256_set1_epi32(0xaaaaaaa6);
	H[7] = _mm256_set1_epi32(0xaaaaaaa7);
	H[8] = _mm256_set1_epi32(0xaaaaaaa8);
	H[9] = _mm256_set1_epi32(0xaaaaaaa9);
	H[10] = _mm256_set1_epi32(0xaaaaaaaa);
	H[11] = _mm256_set1_epi32(0xaaaaaaab);
	H[12] = _mm256_set1_epi32(0xaaaaaaac);
	H[13] = _mm256_set1_epi32(0xaaaaaaad);
	H[14] = _mm256_set1_epi32(0xaaaaaaae);
	H[15] = _mm256_set1_epi32(0xaaaaaaaf);

	Q[0] = ADD(ADD(ADD(SUB(XOR(M32[5], H[5]), XOR(M32[7], H[7])), XOR(M32[10], H[10])), XOR(M32[13], H[13])), XOR(M32[14], H[14]));
	Q[1] = SUB(ADD(ADD(SUB(XOR(M32[6], H[6]), XOR(M32[8], H[8])), XOR(M32[11], H[11])), XOR(M32[14], H[14])), XOR(M32[15], H[15]));
	Q[2] = ADD(SUB(ADD(ADD(XOR(M32[0], H[0]), XOR(M32[7], H[7])), XOR(M32[9], H[9])), XOR(M32[12], H[12])), XOR(M32[15], H[15]));
	Q[3] = ADD(SUB(ADD(SUB(XOR(M32[0], H[0]), XOR(M32[1], H[1])), XOR(M32[8], H[8])), XOR(M32[10], H[10])), XOR(M32[13], H[13]));
	Q[4] = SUB(SUB(ADD(ADD(XOR(M32[1], H[1]), XOR(M32[2], H[2])), XOR(M32[9], H[9])), XOR(M32[11], H[11])), XOR(M32[14], H[14]));
	Q[5] = ADD(SUB(ADD(SUB(XOR(M32[3], H[3]), XOR(M32[2], H[2])), XOR(M32[10], H[10])), XOR(M32[12], H[12])), XOR(M32[15], H[15]));
	Q[6] = ADD(SUB(SUB(SUB(XOR(M32[4], H[4]), XOR(M32[0], H[0])), XOR(M32[3], H[3])), XOR(M32[11], H[11])), XOR(M32[13], H[13]));
	Q[7] = SUB(SUB(SUB(SUB(XOR(M32[1], H[1]), XOR(M32[4], H[4])), XOR(M32[5], H[5])), XOR(M32[12], H[12])), XOR(M32[14], H[14]));
	Q[8] = SUB(ADD(SUB(SUB(XOR(M32[2], H[2]), XOR(M32[5], H[5])), XOR(M32[6], H[6])), XOR(M32[13], H[13])), XOR(M32[15], H[15]));
	Q[9] = ADD(SUB(ADD(SUB(XOR(M32[0], H[0]), XOR(M32[3], H[3])), XOR(M32[6], H[6])), XOR(M32[7], H[7])), XOR(M32[14], H[14]));
	Q[10] = ADD(SUB(SUB(SUB(XOR(M32[8], H[8]), XOR(M32[1], H[1])), XOR(M32[4], H[4])), XOR(M32[7], H[7])), XOR(M32[15], H[15]));
	Q[11] = ADD(SUB(SUB(SUB(XOR(M32[8], H[8]), XOR(M32[0], H[0])), XOR(M32[2], H[2])), XOR(M32[5], H[5])), XOR(M32[9], H[9]));
	Q[12] = ADD(SUB(SUB(ADD(XOR(M32[1], H[1]), XOR(M32[3], H[3])), XOR(M32[6], H[6])), XOR(M32[9], H[9])), XOR(M32[10], H[10]));
	Q[13] = ADD(ADD(ADD(ADD(XOR(M32[2], H[2]), XOR(M32[4], H[4])), XOR(M32[7], H[7])), XOR(M32[10], H[10])), XOR(M32[11], H[11]));
	Q[14] = SUB(SUB(ADD(SUB(XOR(M32[3], H[3]), XOR(M32[5], H[5])), XOR(M32[8], H[8])), XOR(M32[11], H[11])), XOR(M32[12], H[12]));
	Q[15] = ADD(SUB(SUB(SUB(XOR(M32[12], H[12]), XOR(M32[4], H[4])), XOR(M32[6], H[6])), XOR(M32[9], H[9])), XOR(M32[13], H[13]));

	/*  Diffuse the differences in every word in a bijective manner with ssi, and then add the values of the previous double pipe.*/
	Q[0] = _mm256_add_epi32(ss0_AVX(Q[0]), H[1]);
	Q[1] = _mm256_add_epi32(ss1_AVX(Q[1]), H[2]);
	Q[2] = _mm256_add_epi32(ss2_AVX(Q[2]), H[3]);
	Q[3] = _mm256_add_epi32(ss3_AVX(Q[3]), H[4]);
	Q[4] = _mm256_add_epi32(ss4_AVX(Q[4]), H[5]);
	Q[5] = _mm256_add_epi32(ss0_AVX(Q[5]), H[6]);
	Q[6] = _mm256_add_epi32(ss1_AVX(Q[6]), H[7]);
	Q[7] = _mm256_add_epi32(ss2_AVX(Q[7]), H[8]);
	Q[8] = _mm256_add_epi32(ss3_AVX(Q[8]), H[9]);
	Q[9] = _mm256_add_epi32(ss4_AVX(Q[9]), H[10]);
	Q[10] = _mm256_add_epi32(ss0_AVX(Q[10]), H[11]);
	Q[11] = _mm256_add_epi32(ss1_AVX(Q[11]), H[12]);
	Q[12] = _mm256_add_epi32(ss2_AVX(Q[12]), H[13]);
	Q[13] = _mm256_add_epi32(ss3_AVX(Q[13]), H[14]);
	Q[14] = _mm256_add_epi32(ss4_AVX(Q[14]), H[15]);
	Q[15] = _mm256_add_epi32(ss0_AVX(Q[15]), H[0]);

	/* This is the Message expansion or f_1 in the documentation.       */
	/* It has 16 rounds.                                                */
	/* Blue Midnight Wish has two tunable security parameters.          */
	/* The parameters are named EXPAND_1_ROUNDS and EXPAND_2_ROUNDS.    */
	/* The following relation for these parameters should is satisfied: */
	/* EXPAND_1_ROUNDS + EXPAND_2_ROUNDS = 16                           */

	for (int i = 16; i < 18; i++)
	{
		__m128i r0 = _mm_setr_epi32(((i - 16) & 15) + 1, 0, 0, 0);
		__m128i r1 = _mm_setr_epi32(((i - 13) & 15) + 1, 0, 0, 0);
		__m128i r2 = _mm_setr_epi32(((i - 6) & 15) + 1, 0, 0, 0);
		__m128i r3 = _mm_setr_epi32(32 - (((i - 16) & 15) + 1), 0, 0, 0);
		__m128i r4 = _mm_setr_epi32(32 - (((i - 13) & 15) + 1), 0, 0, 0);
		__m128i r5 = _mm_setr_epi32(32 - (((i - 6) & 15) + 1), 0, 0, 0);

		Q[i] = ADD(ADD(ss1_AVX(Q[i - 16]), ss2_AVX(Q[i - 15])), ADD(ss3_AVX(Q[i - 14]), ss0_AVX(Q[i - 13])));
		Q[i] = ADD(Q[i], ADD(ADD(ss1_AVX(Q[i - 12]), ss2_AVX(Q[i - 11])), ADD(ss3_AVX(Q[i - 10]), ss0_AVX(Q[i - 9]))));
		Q[i] = ADD(Q[i], ADD(ADD(ss1_AVX(Q[i - 8]), ss2_AVX(Q[i - 7])), ADD(ss3_AVX(Q[i - 6]), ss0_AVX(Q[i - 5]))));
		Q[i] = ADD(Q[i], ADD(ADD(ss1_AVX(Q[i - 4]), ss2_AVX(Q[i - 3])), ADD(ss3_AVX(Q[i - 2]), ss0_AVX(Q[i - 1]))));
		Q[i] = ADD(Q[i], XOR(SUB(ADD(ADD(_mm256_set1_epi32(i*(0x05555555ul)), ROTL32v_AVX_1(M32[(i - 16) & 15])), ROTL32v_AVX_2(M32[(i - 13) & 15])), ROTL32v_AVX_3(M32[(i - 6) & 15])), H[(i - 16 + 7) & 15]));
	}
	for (int i = 18; i < 32; i++)
	{
		__m128i r0 = _mm_setr_epi32(((i - 16) & 15) + 1, 0, 0, 0);
		__m128i r1 = _mm_setr_epi32(((i - 13) & 15) + 1, 0, 0, 0);
		__m128i r2 = _mm_setr_epi32(((i - 6) & 15) + 1, 0, 0, 0);
		__m128i r3 = _mm_setr_epi32(32 - (((i - 16) & 15) + 1), 0, 0, 0);
		__m128i r4 = _mm_setr_epi32(32 - (((i - 13) & 15) + 1), 0, 0, 0);
		__m128i r5 = _mm_setr_epi32(32 - (((i - 6) & 15) + 1), 0, 0, 0);

		Q[i] = ADD(ADD(Q[i - 16], rs1_AVX(Q[i - 15])), ADD(Q[i - 14], rs2_AVX(Q[i - 13])));
		Q[i] = ADD(Q[i], ADD(ADD(Q[i - 12], rs3_AVX(Q[i - 11])), ADD(Q[i - 10], rs4_AVX(Q[i - 9]))));
		Q[i] = ADD(Q[i], ADD(ADD(Q[i - 8], rs5_AVX(Q[i - 7])), ADD(Q[i - 6], rs6_AVX(Q[i - 5]))));
		Q[i] = ADD(Q[i], ADD(ADD(Q[i - 4], rs7_AVX(Q[i - 3])), ADD(ss4_AVX(Q[i - 2]), ss5_AVX(Q[i - 1]))));
		Q[i] = ADD(Q[i], XOR(SUB(ADD(ADD(_mm256_set1_epi32(i*(0x05555555ul)), ROTL32v_AVX_1(M32[(i - 16) & 15])), ROTL32v_AVX_2(M32[(i - 13) & 15])), ROTL32v_AVX_3(M32[(i - 6) & 15])), H[(i - 16 + 7) & 15]));
	}

	/* Blue Midnight Wish has two temporary cummulative variables that accumulate via XORing */
	/* 16 new variables that are prooduced in the Message Expansion part.                    */
	XL32 = Q[16];
	for (int i = 17; i < 24; i++)
		XL32 = _mm256_xor_si256(XL32, Q[i]);
	XH32 = XL32;
	for (int i = 24; i < 32; i++)
		XH32 = _mm256_xor_si256(XH32, Q[i]);

	M32[0] = ADD(XOR(XOR(_mm256_slli_epi32(XH32, 5), _mm256_srli_epi32(Q[16], 5)), M32[0]), XOR(XOR(XL32, Q[24]), Q[0]));
	M32[1] = ADD(XOR(XOR(_mm256_srli_epi32(XH32, 7), _mm256_slli_epi32(Q[17], 8)), M32[1]), XOR(XOR(XL32, Q[25]), Q[1]));
	M32[2] = ADD(XOR(XOR(_mm256_srli_epi32(XH32, 5), _mm256_slli_epi32(Q[18], 5)), M32[2]), XOR(XOR(XL32, Q[26]), Q[2]));
	M32[3] = ADD(XOR(XOR(_mm256_srli_epi32(XH32, 1), _mm256_slli_epi32(Q[19], 5)), M32[3]), XOR(XOR(XL32, Q[27]), Q[3]));
	M32[4] = ADD(XOR(XOR(_mm256_srli_epi32(XH32, 3), Q[20]), M32[4]), XOR(XOR(XL32, Q[28]), Q[4]));
	M32[5] = ADD(XOR(XOR(_mm256_slli_epi32(XH32, 6), _mm256_srli_epi32(Q[21], 6)), M32[5]), XOR(XOR(XL32, Q[29]), Q[5]));
	M32[6] = ADD(XOR(XOR(_mm256_srli_epi32(XH32, 4), _mm256_slli_epi32(Q[22], 6)), M32[6]), XOR(XOR(XL32, Q[30]), Q[6]));
	M32[7] = ADD(XOR(XOR(_mm256_srli_epi32(XH32, 11), _mm256_slli_epi32(Q[23], 2)), M32[7]), XOR(XOR(XL32, Q[31]), Q[7]));
	M32[8] = ADD(ADD(ROTL32_AVX(M32[4], 9), XOR(XOR(XH32, Q[24]), M32[8])), XOR(XOR(_mm256_slli_epi32(XL32, 8), Q[23]), Q[8]));
	M32[9] = ADD(ADD(ROTL32_AVX(M32[5], 10), XOR(XOR(XH32, Q[25]), M32[9])), XOR(XOR(_mm256_srli_epi32(XL32, 6), Q[16]), Q[9]));
	M32[10] = ADD(ADD(ROTL32_AVX(M32[6], 11), XOR(XOR(XH32, Q[26]), M32[10])), XOR(XOR(_mm256_slli_epi32(XL32, 6), Q[17]), Q[10]));
	M32[11] = ADD(ADD(ROTL32_AVX(M32[7], 12), XOR(XOR(XH32, Q[27]), M32[11])), XOR(XOR(_mm256_slli_epi32(XL32, 4), Q[18]), Q[11]));
	M32[12] = ADD(ADD(ROTL32_AVX(M32[0], 13), XOR(XOR(XH32, Q[28]), M32[12])), XOR(XOR(_mm256_srli_epi32(XL32, 3), Q[19]), Q[12]));
	M32[13] = ADD(ADD(ROTL32_AVX(M32[1], 14), XOR(XOR(XH32, Q[29]), M32[13])), XOR(XOR(_mm256_srli_epi32(XL32, 4), Q[20]), Q[13]));
	M32[14] = ADD(ADD(ROTL32_AVX(M32[2], 15), XOR(XOR(XH32, Q[30]), M32[14])), XOR(XOR(_mm256_srli_epi32(XL32, 7), Q[21]), Q[14]));
	M32[15] = ADD(ADD(ROTL32_AVX(M32[3], 16), XOR(XOR(XH32, Q[31]), M32[15])), XOR(XOR(_mm256_srli_epi32(XL32, 2), Q[22]), Q[15]));

	((__m256i*)cc)[0] = (M32[8]);
	((__m256i*)cc)[1] = (M32[9]);
	((__m256i*)cc)[2] = (M32[10]);
	((__m256i*)cc)[3] = (M32[11]);
	((__m256i*)cc)[4] = (M32[12]);
	((__m256i*)cc)[5] = (M32[13]);
	((__m256i*)cc)[6] = (M32[14]);
	((__m256i*)cc)[7] = (M32[15]);

	_mm256_zeroupper();
}
#else
#define XOR_SSE2(a,b) _mm_xor_si128((a), (b))
#define ADD_SSE2(a,b) _mm_add_epi32((a), (b))
#define SUB_SSE2(a,b) _mm_sub_epi32((a), (b))
#define ROTL32_SSE2(a,b) _mm_or_si128(_mm_slli_epi32((a),(b)),_mm_srli_epi32((a),32-(b)))
#define ROTL32v_SSE2_1(a) _mm_or_si128(_mm_sll_epi32((a),(r0)),_mm_srl_epi32((a),(r3)))
#define ROTL32v_SSE2_2(a) _mm_or_si128(_mm_sll_epi32((a),(r1)),_mm_srl_epi32((a),(r4)))
#define ROTL32v_SSE2_3(a) _mm_or_si128(_mm_sll_epi32((a),(r2)),_mm_srl_epi32((a),(r5)))
#define ss0_SSE2(x) _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_srli_epi32((x), 1), _mm_slli_epi32((x), 3)), ROTL32_SSE2((x), 4)), ROTL32_SSE2((x), 19))
#define ss1_SSE2(x) _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_srli_epi32((x), 1), _mm_slli_epi32((x), 2)), ROTL32_SSE2((x), 8)), ROTL32_SSE2((x), 23))
#define ss2_SSE2(x) _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_srli_epi32((x), 2), _mm_slli_epi32((x), 1)), ROTL32_SSE2((x), 12)), ROTL32_SSE2((x), 25))
#define ss3_SSE2(x) _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_srli_epi32((x), 2), _mm_slli_epi32((x), 2)), ROTL32_SSE2((x), 15)), ROTL32_SSE2((x), 29))
#define ss4_SSE2(x) _mm_xor_si128(_mm_srli_epi32((x), 1), (x))
#define ss5_SSE2(x) _mm_xor_si128(_mm_srli_epi32((x), 2), (x))
#define rs1_SSE2(x) ROTL32_SSE2((x),  3)
#define rs2_SSE2(x) ROTL32_SSE2((x),  7)
#define rs3_SSE2(x) ROTL32_SSE2((x), 13)
#define rs4_SSE2(x) ROTL32_SSE2((x), 16)
#define rs5_SSE2(x) ROTL32_SSE2((x), 19)
#define rs6_SSE2(x) ROTL32_SSE2((x), 23)
#define rs7_SSE2(x) ROTL32_SSE2((x), 27)
#define bswap32_SSE2(x) 	_mm_or_si128(_mm_or_si128(_mm_and_si128(_mm_slli_epi32(x, 24), _mm_set1_epi32(0xff000000u)), _mm_and_si128(_mm_slli_epi32(x, 8), _mm_set1_epi32(0x00ff0000u))),\
	_mm_or_si128(_mm_and_si128(_mm_srli_epi32(x, 8), _mm_set1_epi32(0x0000ff00u)), _mm_and_si128(_mm_srli_epi32(x, 24), _mm_set1_epi32(0x000000ffu))))

void
sph_bmw256_SSE2(void *cc, const void *data, size_t len)
{
	__m128i M32[16];
	M32[0] = ((__m128i*)data)[0];
	M32[1] = ((__m128i*)data)[1];
	M32[2] = ((__m128i*)data)[2];
	M32[3] = ((__m128i*)data)[3];
	M32[4] = ((__m128i*)data)[4];
	M32[5] = ((__m128i*)data)[5];
	M32[6] = ((__m128i*)data)[6];
	M32[7] = ((__m128i*)data)[7];

	M32[8] = _mm_set1_epi32(0x80);
	M32[14] = _mm_set1_epi32(0x100ULL);
	M32[9] = M32[10] = M32[11] = M32[12] = M32[13] = M32[15] = _mm_setzero_si128();

	__m128i Q[32], XL32, XH32;
	__m128i H[16];
	H[0] = _mm_set1_epi32(0x40414243);
	H[1] = _mm_set1_epi32(0x44454647);
	H[2] = _mm_set1_epi32(0x48494A4B);
	H[3] = _mm_set1_epi32(0x4C4D4E4F);
	H[4] = _mm_set1_epi32(0x50515253);
	H[5] = _mm_set1_epi32(0x54555657);
	H[6] = _mm_set1_epi32(0x58595A5B);
	H[7] = _mm_set1_epi32(0x5C5D5E5F);
	H[8] = _mm_set1_epi32(0x60616263);
	H[9] = _mm_set1_epi32(0x64656667);
	H[10] = _mm_set1_epi32(0x68696A6B);
	H[11] = _mm_set1_epi32(0x6C6D6E6F);
	H[12] = _mm_set1_epi32(0x70717273);
	H[13] = _mm_set1_epi32(0x74757677);
	H[14] = _mm_set1_epi32(0x78797A7B);
	H[15] = _mm_set1_epi32(0x7C7D7E7F);

	Q[0] = ADD_SSE2(ADD_SSE2(ADD_SSE2(SUB_SSE2(XOR_SSE2(M32[5], H[5]), XOR_SSE2(M32[7], H[7])), XOR_SSE2(M32[10], H[10])), XOR_SSE2(M32[13], H[13])), XOR_SSE2(M32[14], H[14]));
	Q[1] = SUB_SSE2(ADD_SSE2(ADD_SSE2(SUB_SSE2(XOR_SSE2(M32[6], H[6]), XOR_SSE2(M32[8], H[8])), XOR_SSE2(M32[11], H[11])), XOR_SSE2(M32[14], H[14])), XOR_SSE2(M32[15], H[15]));
	Q[2] = ADD_SSE2(SUB_SSE2(ADD_SSE2(ADD_SSE2(XOR_SSE2(M32[0], H[0]), XOR_SSE2(M32[7], H[7])), XOR_SSE2(M32[9], H[9])), XOR_SSE2(M32[12], H[12])), XOR_SSE2(M32[15], H[15]));
	Q[3] = ADD_SSE2(SUB_SSE2(ADD_SSE2(SUB_SSE2(XOR_SSE2(M32[0], H[0]), XOR_SSE2(M32[1], H[1])), XOR_SSE2(M32[8], H[8])), XOR_SSE2(M32[10], H[10])), XOR_SSE2(M32[13], H[13]));
	Q[4] = SUB_SSE2(SUB_SSE2(ADD_SSE2(ADD_SSE2(XOR_SSE2(M32[1], H[1]), XOR_SSE2(M32[2], H[2])), XOR_SSE2(M32[9], H[9])), XOR_SSE2(M32[11], H[11])), XOR_SSE2(M32[14], H[14]));
	Q[5] = ADD_SSE2(SUB_SSE2(ADD_SSE2(SUB_SSE2(XOR_SSE2(M32[3], H[3]), XOR_SSE2(M32[2], H[2])), XOR_SSE2(M32[10], H[10])), XOR_SSE2(M32[12], H[12])), XOR_SSE2(M32[15], H[15]));
	Q[6] = ADD_SSE2(SUB_SSE2(SUB_SSE2(SUB_SSE2(XOR_SSE2(M32[4], H[4]), XOR_SSE2(M32[0], H[0])), XOR_SSE2(M32[3], H[3])), XOR_SSE2(M32[11], H[11])), XOR_SSE2(M32[13], H[13]));
	Q[7] = SUB_SSE2(SUB_SSE2(SUB_SSE2(SUB_SSE2(XOR_SSE2(M32[1], H[1]), XOR_SSE2(M32[4], H[4])), XOR_SSE2(M32[5], H[5])), XOR_SSE2(M32[12], H[12])), XOR_SSE2(M32[14], H[14]));
	Q[8] = SUB_SSE2(ADD_SSE2(SUB_SSE2(SUB_SSE2(XOR_SSE2(M32[2], H[2]), XOR_SSE2(M32[5], H[5])), XOR_SSE2(M32[6], H[6])), XOR_SSE2(M32[13], H[13])), XOR_SSE2(M32[15], H[15]));
	Q[9] = ADD_SSE2(SUB_SSE2(ADD_SSE2(SUB_SSE2(XOR_SSE2(M32[0], H[0]), XOR_SSE2(M32[3], H[3])), XOR_SSE2(M32[6], H[6])), XOR_SSE2(M32[7], H[7])), XOR_SSE2(M32[14], H[14]));
	Q[10] = ADD_SSE2(SUB_SSE2(SUB_SSE2(SUB_SSE2(XOR_SSE2(M32[8], H[8]), XOR_SSE2(M32[1], H[1])), XOR_SSE2(M32[4], H[4])), XOR_SSE2(M32[7], H[7])), XOR_SSE2(M32[15], H[15]));
	Q[11] = ADD_SSE2(SUB_SSE2(SUB_SSE2(SUB_SSE2(XOR_SSE2(M32[8], H[8]), XOR_SSE2(M32[0], H[0])), XOR_SSE2(M32[2], H[2])), XOR_SSE2(M32[5], H[5])), XOR_SSE2(M32[9], H[9]));
	Q[12] = ADD_SSE2(SUB_SSE2(SUB_SSE2(ADD_SSE2(XOR_SSE2(M32[1], H[1]), XOR_SSE2(M32[3], H[3])), XOR_SSE2(M32[6], H[6])), XOR_SSE2(M32[9], H[9])), XOR_SSE2(M32[10], H[10]));
	Q[13] = ADD_SSE2(ADD_SSE2(ADD_SSE2(ADD_SSE2(XOR_SSE2(M32[2], H[2]), XOR_SSE2(M32[4], H[4])), XOR_SSE2(M32[7], H[7])), XOR_SSE2(M32[10], H[10])), XOR_SSE2(M32[11], H[11]));
	Q[14] = SUB_SSE2(SUB_SSE2(ADD_SSE2(SUB_SSE2(XOR_SSE2(M32[3], H[3]), XOR_SSE2(M32[5], H[5])), XOR_SSE2(M32[8], H[8])), XOR_SSE2(M32[11], H[11])), XOR_SSE2(M32[12], H[12]));
	Q[15] = ADD_SSE2(SUB_SSE2(SUB_SSE2(SUB_SSE2(XOR_SSE2(M32[12], H[12]), XOR_SSE2(M32[4], H[4])), XOR_SSE2(M32[6], H[6])), XOR_SSE2(M32[9], H[9])), XOR_SSE2(M32[13], H[13]));

	/*  Diffuse the differences in every word in a bijective manner with ssi, and then add the values of the previous double pipe. */
	Q[0] = _mm_add_epi32(ss0_SSE2(Q[0]), H[1]);
	Q[1] = _mm_add_epi32(ss1_SSE2(Q[1]), H[2]);
	Q[2] = _mm_add_epi32(ss2_SSE2(Q[2]), H[3]);
	Q[3] = _mm_add_epi32(ss3_SSE2(Q[3]), H[4]);
	Q[4] = _mm_add_epi32(ss4_SSE2(Q[4]), H[5]);
	Q[5] = _mm_add_epi32(ss0_SSE2(Q[5]), H[6]);
	Q[6] = _mm_add_epi32(ss1_SSE2(Q[6]), H[7]);
	Q[7] = _mm_add_epi32(ss2_SSE2(Q[7]), H[8]);
	Q[8] = _mm_add_epi32(ss3_SSE2(Q[8]), H[9]);
	Q[9] = _mm_add_epi32(ss4_SSE2(Q[9]), H[10]);
	Q[10] = _mm_add_epi32(ss0_SSE2(Q[10]), H[11]);
	Q[11] = _mm_add_epi32(ss1_SSE2(Q[11]), H[12]);
	Q[12] = _mm_add_epi32(ss2_SSE2(Q[12]), H[13]);
	Q[13] = _mm_add_epi32(ss3_SSE2(Q[13]), H[14]);
	Q[14] = _mm_add_epi32(ss4_SSE2(Q[14]), H[15]);
	Q[15] = _mm_add_epi32(ss0_SSE2(Q[15]), H[0]);

	/* This is the Message expansion or f_1 in the documentation.       */
	/* It has 16 rounds.                                                */
	/* Blue Midnight Wish has two tunable security parameters.          */
	/* The parameters are named EXPAND_1_ROUNDS and EXPAND_2_ROUNDS.    */
	/* The following relation for these parameters should is satisfied: */
	/* EXPAND_1_ROUNDS + EXPAND_2_ROUNDS = 16                           */

	for (int i = 16; i < 18; i++)
	{
		__m128i r0 = _mm_setr_epi32(((i - 16) & 15) + 1, 0, 0, 0);
		__m128i r1 = _mm_setr_epi32(((i - 13) & 15) + 1, 0, 0, 0);
		__m128i r2 = _mm_setr_epi32(((i - 6) & 15) + 1, 0, 0, 0);
		__m128i r3 = _mm_setr_epi32(32 - (((i - 16) & 15) + 1), 0, 0, 0);
		__m128i r4 = _mm_setr_epi32(32 - (((i - 13) & 15) + 1), 0, 0, 0);
		__m128i r5 = _mm_setr_epi32(32 - (((i - 6) & 15) + 1), 0, 0, 0);

		Q[i] = ADD_SSE2(ADD_SSE2(ss1_SSE2(Q[i - 16]), ss2_SSE2(Q[i - 15])), ADD_SSE2(ss3_SSE2(Q[i - 14]), ss0_SSE2(Q[i - 13])));
		Q[i] = ADD_SSE2(Q[i], ADD_SSE2(ADD_SSE2(ss1_SSE2(Q[i - 12]), ss2_SSE2(Q[i - 11])), ADD_SSE2(ss3_SSE2(Q[i - 10]), ss0_SSE2(Q[i - 9]))));
		Q[i] = ADD_SSE2(Q[i], ADD_SSE2(ADD_SSE2(ss1_SSE2(Q[i - 8]), ss2_SSE2(Q[i - 7])), ADD_SSE2(ss3_SSE2(Q[i - 6]), ss0_SSE2(Q[i - 5]))));
		Q[i] = ADD_SSE2(Q[i], ADD_SSE2(ADD_SSE2(ss1_SSE2(Q[i - 4]), ss2_SSE2(Q[i - 3])), ADD_SSE2(ss3_SSE2(Q[i - 2]), ss0_SSE2(Q[i - 1]))));
		Q[i] = ADD_SSE2(Q[i], XOR_SSE2(SUB_SSE2(ADD_SSE2(ADD_SSE2(_mm_set1_epi32(i*(0x05555555ul)), ROTL32v_SSE2_1(M32[(i - 16) & 15])), ROTL32v_SSE2_2(M32[(i - 13) & 15])), ROTL32v_SSE2_3(M32[(i - 6) & 15])), H[(i - 16 + 7) & 15]));
	}
	for (int i = 18; i < 32; i++)
	{
		__m128i r0 = _mm_setr_epi32(((i - 16) & 15) + 1, 0, 0, 0);
		__m128i r1 = _mm_setr_epi32(((i - 13) & 15) + 1, 0, 0, 0);
		__m128i r2 = _mm_setr_epi32(((i - 6) & 15) + 1, 0, 0, 0);
		__m128i r3 = _mm_setr_epi32(32 - (((i - 16) & 15) + 1), 0, 0, 0);
		__m128i r4 = _mm_setr_epi32(32 - (((i - 13) & 15) + 1), 0, 0, 0);
		__m128i r5 = _mm_setr_epi32(32 - (((i - 6) & 15) + 1), 0, 0, 0);

		Q[i] = ADD_SSE2(ADD_SSE2(Q[i - 16], rs1_SSE2(Q[i - 15])), ADD_SSE2(Q[i - 14], rs2_SSE2(Q[i - 13])));
		Q[i] = ADD_SSE2(Q[i], ADD_SSE2(ADD_SSE2(Q[i - 12], rs3_SSE2(Q[i - 11])), ADD_SSE2(Q[i - 10], rs4_SSE2(Q[i - 9]))));
		Q[i] = ADD_SSE2(Q[i], ADD_SSE2(ADD_SSE2(Q[i - 8], rs5_SSE2(Q[i - 7])), ADD_SSE2(Q[i - 6], rs6_SSE2(Q[i - 5]))));
		Q[i] = ADD_SSE2(Q[i], ADD_SSE2(ADD_SSE2(Q[i - 4], rs7_SSE2(Q[i - 3])), ADD_SSE2(ss4_SSE2(Q[i - 2]), ss5_SSE2(Q[i - 1]))));
		Q[i] = ADD_SSE2(Q[i], XOR_SSE2(SUB_SSE2(ADD_SSE2(ADD_SSE2(_mm_set1_epi32(i*(0x05555555ul)), ROTL32v_SSE2_1(M32[(i - 16) & 15])), ROTL32v_SSE2_2(M32[(i - 13) & 15])), ROTL32v_SSE2_3(M32[(i - 6) & 15])), H[(i - 16 + 7) & 15]));
	}

	/* Blue Midnight Wish has two temporary cummulative variables that accumulate via XORing */
	/* 16 new variables that are prooduced in the Message Expansion part.                    */
	XL32 = Q[16];
	for (int i = 17; i < 24; i++)
		XL32 = _mm_xor_si128(XL32, Q[i]);
	XH32 = XL32;
	for (int i = 24; i < 32; i++)
		XH32 = _mm_xor_si128(XH32, Q[i]);

	/*  This part is the function f_2 - in the documentation            */

	/*  Compute the double chaining pipe for the next message block.    */
	M32[0] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_slli_epi32(XH32, 5), _mm_srli_epi32(Q[16], 5)), M32[0]), XOR_SSE2(XOR_SSE2(XL32, Q[24]), Q[0]));
	M32[1] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XH32, 7), _mm_slli_epi32(Q[17], 8)), M32[1]), XOR_SSE2(XOR_SSE2(XL32, Q[25]), Q[1]));
	M32[2] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XH32, 5), _mm_slli_epi32(Q[18], 5)), M32[2]), XOR_SSE2(XOR_SSE2(XL32, Q[26]), Q[2]));
	M32[3] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XH32, 1), _mm_slli_epi32(Q[19], 5)), M32[3]), XOR_SSE2(XOR_SSE2(XL32, Q[27]), Q[3]));
	M32[4] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XH32, 3), Q[20]), M32[4]), XOR_SSE2(XOR_SSE2(XL32, Q[28]), Q[4]));
	M32[5] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_slli_epi32(XH32, 6), _mm_srli_epi32(Q[21], 6)), M32[5]), XOR_SSE2(XOR_SSE2(XL32, Q[29]), Q[5]));
	M32[6] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XH32, 4), _mm_slli_epi32(Q[22], 6)), M32[6]), XOR_SSE2(XOR_SSE2(XL32, Q[30]), Q[6]));
	M32[7] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XH32, 11), _mm_slli_epi32(Q[23], 2)), M32[7]), XOR_SSE2(XOR_SSE2(XL32, Q[31]), Q[7]));
	M32[8] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[4], 9), XOR_SSE2(XOR_SSE2(XH32, Q[24]), M32[8])), XOR_SSE2(XOR_SSE2(_mm_slli_epi32(XL32, 8), Q[23]), Q[8]));
	M32[9] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[5], 10), XOR_SSE2(XOR_SSE2(XH32, Q[25]), M32[9])), XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XL32, 6), Q[16]), Q[9]));
	M32[10] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[6], 11), XOR_SSE2(XOR_SSE2(XH32, Q[26]), M32[10])), XOR_SSE2(XOR_SSE2(_mm_slli_epi32(XL32, 6), Q[17]), Q[10]));
	M32[11] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[7], 12), XOR_SSE2(XOR_SSE2(XH32, Q[27]), M32[11])), XOR_SSE2(XOR_SSE2(_mm_slli_epi32(XL32, 4), Q[18]), Q[11]));
	M32[12] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[0], 13), XOR_SSE2(XOR_SSE2(XH32, Q[28]), M32[12])), XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XL32, 3), Q[19]), Q[12]));
	M32[13] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[1], 14), XOR_SSE2(XOR_SSE2(XH32, Q[29]), M32[13])), XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XL32, 4), Q[20]), Q[13]));
	M32[14] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[2], 15), XOR_SSE2(XOR_SSE2(XH32, Q[30]), M32[14])), XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XL32, 7), Q[21]), Q[14]));
	M32[15] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[3], 16), XOR_SSE2(XOR_SSE2(XH32, Q[31]), M32[15])), XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XL32, 2), Q[22]), Q[15]));

	H[0] = _mm_set1_epi32(0xaaaaaaa0);
	H[1] = _mm_set1_epi32(0xaaaaaaa1);
	H[2] = _mm_set1_epi32(0xaaaaaaa2);
	H[3] = _mm_set1_epi32(0xaaaaaaa3);
	H[4] = _mm_set1_epi32(0xaaaaaaa4);
	H[5] = _mm_set1_epi32(0xaaaaaaa5);
	H[6] = _mm_set1_epi32(0xaaaaaaa6);
	H[7] = _mm_set1_epi32(0xaaaaaaa7);
	H[8] = _mm_set1_epi32(0xaaaaaaa8);
	H[9] = _mm_set1_epi32(0xaaaaaaa9);
	H[10] = _mm_set1_epi32(0xaaaaaaaa);
	H[11] = _mm_set1_epi32(0xaaaaaaab);
	H[12] = _mm_set1_epi32(0xaaaaaaac);
	H[13] = _mm_set1_epi32(0xaaaaaaad);
	H[14] = _mm_set1_epi32(0xaaaaaaae);
	H[15] = _mm_set1_epi32(0xaaaaaaaf);

	Q[0] = ADD_SSE2(ADD_SSE2(ADD_SSE2(SUB_SSE2(XOR_SSE2(M32[5], H[5]), XOR_SSE2(M32[7], H[7])), XOR_SSE2(M32[10], H[10])), XOR_SSE2(M32[13], H[13])), XOR_SSE2(M32[14], H[14]));
	Q[1] = SUB_SSE2(ADD_SSE2(ADD_SSE2(SUB_SSE2(XOR_SSE2(M32[6], H[6]), XOR_SSE2(M32[8], H[8])), XOR_SSE2(M32[11], H[11])), XOR_SSE2(M32[14], H[14])), XOR_SSE2(M32[15], H[15]));
	Q[2] = ADD_SSE2(SUB_SSE2(ADD_SSE2(ADD_SSE2(XOR_SSE2(M32[0], H[0]), XOR_SSE2(M32[7], H[7])), XOR_SSE2(M32[9], H[9])), XOR_SSE2(M32[12], H[12])), XOR_SSE2(M32[15], H[15]));
	Q[3] = ADD_SSE2(SUB_SSE2(ADD_SSE2(SUB_SSE2(XOR_SSE2(M32[0], H[0]), XOR_SSE2(M32[1], H[1])), XOR_SSE2(M32[8], H[8])), XOR_SSE2(M32[10], H[10])), XOR_SSE2(M32[13], H[13]));
	Q[4] = SUB_SSE2(SUB_SSE2(ADD_SSE2(ADD_SSE2(XOR_SSE2(M32[1], H[1]), XOR_SSE2(M32[2], H[2])), XOR_SSE2(M32[9], H[9])), XOR_SSE2(M32[11], H[11])), XOR_SSE2(M32[14], H[14]));
	Q[5] = ADD_SSE2(SUB_SSE2(ADD_SSE2(SUB_SSE2(XOR_SSE2(M32[3], H[3]), XOR_SSE2(M32[2], H[2])), XOR_SSE2(M32[10], H[10])), XOR_SSE2(M32[12], H[12])), XOR_SSE2(M32[15], H[15]));
	Q[6] = ADD_SSE2(SUB_SSE2(SUB_SSE2(SUB_SSE2(XOR_SSE2(M32[4], H[4]), XOR_SSE2(M32[0], H[0])), XOR_SSE2(M32[3], H[3])), XOR_SSE2(M32[11], H[11])), XOR_SSE2(M32[13], H[13]));
	Q[7] = SUB_SSE2(SUB_SSE2(SUB_SSE2(SUB_SSE2(XOR_SSE2(M32[1], H[1]), XOR_SSE2(M32[4], H[4])), XOR_SSE2(M32[5], H[5])), XOR_SSE2(M32[12], H[12])), XOR_SSE2(M32[14], H[14]));
	Q[8] = SUB_SSE2(ADD_SSE2(SUB_SSE2(SUB_SSE2(XOR_SSE2(M32[2], H[2]), XOR_SSE2(M32[5], H[5])), XOR_SSE2(M32[6], H[6])), XOR_SSE2(M32[13], H[13])), XOR_SSE2(M32[15], H[15]));
	Q[9] = ADD_SSE2(SUB_SSE2(ADD_SSE2(SUB_SSE2(XOR_SSE2(M32[0], H[0]), XOR_SSE2(M32[3], H[3])), XOR_SSE2(M32[6], H[6])), XOR_SSE2(M32[7], H[7])), XOR_SSE2(M32[14], H[14]));
	Q[10] = ADD_SSE2(SUB_SSE2(SUB_SSE2(SUB_SSE2(XOR_SSE2(M32[8], H[8]), XOR_SSE2(M32[1], H[1])), XOR_SSE2(M32[4], H[4])), XOR_SSE2(M32[7], H[7])), XOR_SSE2(M32[15], H[15]));
	Q[11] = ADD_SSE2(SUB_SSE2(SUB_SSE2(SUB_SSE2(XOR_SSE2(M32[8], H[8]), XOR_SSE2(M32[0], H[0])), XOR_SSE2(M32[2], H[2])), XOR_SSE2(M32[5], H[5])), XOR_SSE2(M32[9], H[9]));
	Q[12] = ADD_SSE2(SUB_SSE2(SUB_SSE2(ADD_SSE2(XOR_SSE2(M32[1], H[1]), XOR_SSE2(M32[3], H[3])), XOR_SSE2(M32[6], H[6])), XOR_SSE2(M32[9], H[9])), XOR_SSE2(M32[10], H[10]));
	Q[13] = ADD_SSE2(ADD_SSE2(ADD_SSE2(ADD_SSE2(XOR_SSE2(M32[2], H[2]), XOR_SSE2(M32[4], H[4])), XOR_SSE2(M32[7], H[7])), XOR_SSE2(M32[10], H[10])), XOR_SSE2(M32[11], H[11]));
	Q[14] = SUB_SSE2(SUB_SSE2(ADD_SSE2(SUB_SSE2(XOR_SSE2(M32[3], H[3]), XOR_SSE2(M32[5], H[5])), XOR_SSE2(M32[8], H[8])), XOR_SSE2(M32[11], H[11])), XOR_SSE2(M32[12], H[12]));
	Q[15] = ADD_SSE2(SUB_SSE2(SUB_SSE2(SUB_SSE2(XOR_SSE2(M32[12], H[12]), XOR_SSE2(M32[4], H[4])), XOR_SSE2(M32[6], H[6])), XOR_SSE2(M32[9], H[9])), XOR_SSE2(M32[13], H[13]));

	/*  Diffuse the differences in every word in a bijective manner with ssi, and then add the values of the previous double pipe.*/
	Q[0] = _mm_add_epi32(ss0_SSE2(Q[0]), H[1]);
	Q[1] = _mm_add_epi32(ss1_SSE2(Q[1]), H[2]);
	Q[2] = _mm_add_epi32(ss2_SSE2(Q[2]), H[3]);
	Q[3] = _mm_add_epi32(ss3_SSE2(Q[3]), H[4]);
	Q[4] = _mm_add_epi32(ss4_SSE2(Q[4]), H[5]);
	Q[5] = _mm_add_epi32(ss0_SSE2(Q[5]), H[6]);
	Q[6] = _mm_add_epi32(ss1_SSE2(Q[6]), H[7]);
	Q[7] = _mm_add_epi32(ss2_SSE2(Q[7]), H[8]);
	Q[8] = _mm_add_epi32(ss3_SSE2(Q[8]), H[9]);
	Q[9] = _mm_add_epi32(ss4_SSE2(Q[9]), H[10]);
	Q[10] = _mm_add_epi32(ss0_SSE2(Q[10]), H[11]);
	Q[11] = _mm_add_epi32(ss1_SSE2(Q[11]), H[12]);
	Q[12] = _mm_add_epi32(ss2_SSE2(Q[12]), H[13]);
	Q[13] = _mm_add_epi32(ss3_SSE2(Q[13]), H[14]);
	Q[14] = _mm_add_epi32(ss4_SSE2(Q[14]), H[15]);
	Q[15] = _mm_add_epi32(ss0_SSE2(Q[15]), H[0]);

	/* This is the Message expansion or f_1 in the documentation.       */
	/* It has 16 rounds.                                                */
	/* Blue Midnight Wish has two tunable security parameters.          */
	/* The parameters are named EXPAND_1_ROUNDS and EXPAND_2_ROUNDS.    */
	/* The following relation for these parameters should is satisfied: */
	/* EXPAND_1_ROUNDS + EXPAND_2_ROUNDS = 16                           */

	for (int i = 16; i < 18; i++)
	{
		__m128i r0 = _mm_setr_epi32(((i - 16) & 15) + 1, 0, 0, 0);
		__m128i r1 = _mm_setr_epi32(((i - 13) & 15) + 1, 0, 0, 0);
		__m128i r2 = _mm_setr_epi32(((i - 6) & 15) + 1, 0, 0, 0);
		__m128i r3 = _mm_setr_epi32(32 - (((i - 16) & 15) + 1), 0, 0, 0);
		__m128i r4 = _mm_setr_epi32(32 - (((i - 13) & 15) + 1), 0, 0, 0);
		__m128i r5 = _mm_setr_epi32(32 - (((i - 6) & 15) + 1), 0, 0, 0);

		Q[i] = ADD_SSE2(ADD_SSE2(ss1_SSE2(Q[i - 16]), ss2_SSE2(Q[i - 15])), ADD_SSE2(ss3_SSE2(Q[i - 14]), ss0_SSE2(Q[i - 13])));
		Q[i] = ADD_SSE2(Q[i], ADD_SSE2(ADD_SSE2(ss1_SSE2(Q[i - 12]), ss2_SSE2(Q[i - 11])), ADD_SSE2(ss3_SSE2(Q[i - 10]), ss0_SSE2(Q[i - 9]))));
		Q[i] = ADD_SSE2(Q[i], ADD_SSE2(ADD_SSE2(ss1_SSE2(Q[i - 8]), ss2_SSE2(Q[i - 7])), ADD_SSE2(ss3_SSE2(Q[i - 6]), ss0_SSE2(Q[i - 5]))));
		Q[i] = ADD_SSE2(Q[i], ADD_SSE2(ADD_SSE2(ss1_SSE2(Q[i - 4]), ss2_SSE2(Q[i - 3])), ADD_SSE2(ss3_SSE2(Q[i - 2]), ss0_SSE2(Q[i - 1]))));
		Q[i] = ADD_SSE2(Q[i], XOR_SSE2(SUB_SSE2(ADD_SSE2(ADD_SSE2(_mm_set1_epi32(i*(0x05555555ul)), ROTL32v_SSE2_1(M32[(i - 16) & 15])), ROTL32v_SSE2_2(M32[(i - 13) & 15])), ROTL32v_SSE2_3(M32[(i - 6) & 15])), H[(i - 16 + 7) & 15]));
	}
	for (int i = 18; i < 32; i++)
	{
		__m128i r0 = _mm_setr_epi32(((i - 16) & 15) + 1, 0, 0, 0);
		__m128i r1 = _mm_setr_epi32(((i - 13) & 15) + 1, 0, 0, 0);
		__m128i r2 = _mm_setr_epi32(((i - 6) & 15) + 1, 0, 0, 0);
		__m128i r3 = _mm_setr_epi32(32 - (((i - 16) & 15) + 1), 0, 0, 0);
		__m128i r4 = _mm_setr_epi32(32 - (((i - 13) & 15) + 1), 0, 0, 0);
		__m128i r5 = _mm_setr_epi32(32 - (((i - 6) & 15) + 1), 0, 0, 0);

		Q[i] = ADD_SSE2(ADD_SSE2(Q[i - 16], rs1_SSE2(Q[i - 15])), ADD_SSE2(Q[i - 14], rs2_SSE2(Q[i - 13])));
		Q[i] = ADD_SSE2(Q[i], ADD_SSE2(ADD_SSE2(Q[i - 12], rs3_SSE2(Q[i - 11])), ADD_SSE2(Q[i - 10], rs4_SSE2(Q[i - 9]))));
		Q[i] = ADD_SSE2(Q[i], ADD_SSE2(ADD_SSE2(Q[i - 8], rs5_SSE2(Q[i - 7])), ADD_SSE2(Q[i - 6], rs6_SSE2(Q[i - 5]))));
		Q[i] = ADD_SSE2(Q[i], ADD_SSE2(ADD_SSE2(Q[i - 4], rs7_SSE2(Q[i - 3])), ADD_SSE2(ss4_SSE2(Q[i - 2]), ss5_SSE2(Q[i - 1]))));
		Q[i] = ADD_SSE2(Q[i], XOR_SSE2(SUB_SSE2(ADD_SSE2(ADD_SSE2(_mm_set1_epi32(i*(0x05555555ul)), ROTL32v_SSE2_1(M32[(i - 16) & 15])), ROTL32v_SSE2_2(M32[(i - 13) & 15])), ROTL32v_SSE2_3(M32[(i - 6) & 15])), H[(i - 16 + 7) & 15]));
	}

	/* Blue Midnight Wish has two temporary cummulative variables that accumulate via XORing */
	/* 16 new variables that are prooduced in the Message Expansion part.                    */
	XL32 = Q[16];
	for (int i = 17; i < 24; i++)
		XL32 = _mm_xor_si128(XL32, Q[i]);
	XH32 = XL32;
	for (int i = 24; i < 32; i++)
		XH32 = _mm_xor_si128(XH32, Q[i]);

	M32[0] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_slli_epi32(XH32, 5), _mm_srli_epi32(Q[16], 5)), M32[0]), XOR_SSE2(XOR_SSE2(XL32, Q[24]), Q[0]));
	M32[1] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XH32, 7), _mm_slli_epi32(Q[17], 8)), M32[1]), XOR_SSE2(XOR_SSE2(XL32, Q[25]), Q[1]));
	M32[2] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XH32, 5), _mm_slli_epi32(Q[18], 5)), M32[2]), XOR_SSE2(XOR_SSE2(XL32, Q[26]), Q[2]));
	M32[3] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XH32, 1), _mm_slli_epi32(Q[19], 5)), M32[3]), XOR_SSE2(XOR_SSE2(XL32, Q[27]), Q[3]));
	M32[4] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XH32, 3), Q[20]), M32[4]), XOR_SSE2(XOR_SSE2(XL32, Q[28]), Q[4]));
	M32[5] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_slli_epi32(XH32, 6), _mm_srli_epi32(Q[21], 6)), M32[5]), XOR_SSE2(XOR_SSE2(XL32, Q[29]), Q[5]));
	M32[6] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XH32, 4), _mm_slli_epi32(Q[22], 6)), M32[6]), XOR_SSE2(XOR_SSE2(XL32, Q[30]), Q[6]));
	M32[7] = ADD_SSE2(XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XH32, 11), _mm_slli_epi32(Q[23], 2)), M32[7]), XOR_SSE2(XOR_SSE2(XL32, Q[31]), Q[7]));
	M32[8] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[4], 9), XOR_SSE2(XOR_SSE2(XH32, Q[24]), M32[8])), XOR_SSE2(XOR_SSE2(_mm_slli_epi32(XL32, 8), Q[23]), Q[8]));
	M32[9] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[5], 10), XOR_SSE2(XOR_SSE2(XH32, Q[25]), M32[9])), XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XL32, 6), Q[16]), Q[9]));
	M32[10] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[6], 11), XOR_SSE2(XOR_SSE2(XH32, Q[26]), M32[10])), XOR_SSE2(XOR_SSE2(_mm_slli_epi32(XL32, 6), Q[17]), Q[10]));
	M32[11] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[7], 12), XOR_SSE2(XOR_SSE2(XH32, Q[27]), M32[11])), XOR_SSE2(XOR_SSE2(_mm_slli_epi32(XL32, 4), Q[18]), Q[11]));
	M32[12] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[0], 13), XOR_SSE2(XOR_SSE2(XH32, Q[28]), M32[12])), XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XL32, 3), Q[19]), Q[12]));
	M32[13] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[1], 14), XOR_SSE2(XOR_SSE2(XH32, Q[29]), M32[13])), XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XL32, 4), Q[20]), Q[13]));
	M32[14] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[2], 15), XOR_SSE2(XOR_SSE2(XH32, Q[30]), M32[14])), XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XL32, 7), Q[21]), Q[14]));
	M32[15] = ADD_SSE2(ADD_SSE2(ROTL32_SSE2(M32[3], 16), XOR_SSE2(XOR_SSE2(XH32, Q[31]), M32[15])), XOR_SSE2(XOR_SSE2(_mm_srli_epi32(XL32, 2), Q[22]), Q[15]));

	((__m128i*)cc)[0] = (M32[8]);
	((__m128i*)cc)[1] = (M32[9]);
	((__m128i*)cc)[2] = (M32[10]);
	((__m128i*)cc)[3] = (M32[11]);
	((__m128i*)cc)[4] = (M32[12]);
	((__m128i*)cc)[5] = (M32[13]);
	((__m128i*)cc)[6] = (M32[14]);
	((__m128i*)cc)[7] = (M32[15]);
}
#endif
/* see sph_bmw.h */
void
sph_bmw256_close(void *cc, void *dst)
{
	sph_bmw256_addbits_and_close(cc, 0, 0, dst);
}

/* see sph_bmw.h */
void
sph_bmw256_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	bmw32_close(cc, ub, n, dst, 8);
	sph_bmw256_init(cc);
}

#if SPH_64

/* see sph_bmw.h */
void
sph_bmw384_init(void *cc)
{
	bmw64_init(cc, IV384);
}

/* see sph_bmw.h */
void
sph_bmw384(void *cc, const void *data, size_t len)
{
	bmw64(cc, data, len);
}

/* see sph_bmw.h */
void
sph_bmw384_close(void *cc, void *dst)
{
	sph_bmw384_addbits_and_close(cc, 0, 0, dst);
}

/* see sph_bmw.h */
void
sph_bmw384_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	bmw64_close(cc, ub, n, dst, 6);
	sph_bmw384_init(cc);
}

/* see sph_bmw.h */
void
sph_bmw512_init(void *cc)
{
	bmw64_init(cc, IV512);
}

/* see sph_bmw.h */
void
sph_bmw512(void *cc, const void *data, size_t len)
{
	bmw64(cc, data, len);
}

/* see sph_bmw.h */
void
sph_bmw512_close(void *cc, void *dst)
{
	sph_bmw512_addbits_and_close(cc, 0, 0, dst);
}

/* see sph_bmw.h */
void
sph_bmw512_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	bmw64_close(cc, ub, n, dst, 8);
	sph_bmw512_init(cc);
}

#endif

#ifdef __cplusplus
}
#endif
