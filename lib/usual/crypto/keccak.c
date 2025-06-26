/*
 * Keccak implementation for SHA3 parameters.
 *
 * Copyright (c) 2012 Marko Kreen
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Based on public-domain Keccak-inplace.c and Keccak-inplace32BI.c
 * implementations from Keccak reference code:
 *
 *     The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
 *     Michaël Peeters and Gilles Van Assche. For more information, feedback or
 *     questions, please refer to our website: http://keccak.noekeon.org/
 *
 *     Implementation by Ronny Van Keer and the designers,
 *     hereby denoted as "the implementer".
 *
 *     To the extent possible under law, the implementer has waived all copyright
 *     and related or neighboring rights to the source code in this file.
 *     http://creativecommons.org/publicdomain/zero/1.0/
 *
 * 32-bit word interlacing algorithm:
 *
 *     Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
 */

#include <usual/crypto/keccak.h>
#include <usual/bits.h>
#include <usual/endian.h>

#include <limits.h>
#include <string.h>

/* For SHA3 variant of Keccak */
#define KECCAK_ROUNDS 24

/*
 * Enforce minimal code size.  If this is not defined, use
 * faster unrolled implementation.
 */
/* #define KECCAK_SMALL */

#ifdef KECCAK_SMALL
#define KECCAK_64BIT
#endif

/*
 * Decide whether to use 64- or 32-bit implementation.
 */

#if !defined(KECCAK_64BIT) && !defined(KECCAK_32BIT)
#if !defined(LONG_MAX) && !defined(UINTPTR_MAX)
#error "Need LONG_MAX & UINTPTR_MAX"
#endif
/* If neither is defined, try to autodetect */
#if (LONG_MAX > 0xFFFFFFFF) || (UINTPTR_MAX > 0xFFFFFFFF)
/* use 64-bit implementation if 'long' or 'uintptr_t' is 64-bit */
#define KECCAK_64BIT
#else
/* otherwise, use 32-bit implementation */
#define KECCAK_32BIT
#endif
#endif

#ifdef KECCAK_64BIT

/*
 * 64-bit implementation - one lane is one 64-bit word.
 */

/* round constants */
static const uint64_t RoundConstants64[KECCAK_ROUNDS] = {
	UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
	UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
	UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
	UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
	UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088),
	UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
	UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B),
	UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
	UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
	UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
	UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
	UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
};

#ifdef KECCAK_SMALL

/*
 * Minimal code implementation
 */

static const uint8_t RhoRot[24] = {
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const uint8_t PiLane[24] = {
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static void keccak_f(struct KeccakContext *ctx)
{
	int i, j;
	uint64_t *A = ctx->u.state64;
	uint64_t tmpbuf[5 + 2], *tmp = tmpbuf + 1;
	uint64_t d, c1, c2;

	for (j = 0; j < KECCAK_ROUNDS; j++) {
		/* Theta step */
		for (i = 0; i < 5; i++)
			tmp[i] = A[0*5 + i] ^ A[1*5 + i] ^ A[2*5 + i] ^ A[3*5 + i] ^ A[4*5 + i];
		tmpbuf[0] = tmp[4];
		tmpbuf[6] = tmp[0];
		for (i = 0; i < 5; i++) {
			d = tmp[i - 1] ^ rol64(tmp[i + 1], 1);
			A[0 + i] ^= d;
			A[5 + i] ^= d;
			A[10 + i] ^= d;
			A[15 + i] ^= d;
			A[20 + i] ^= d;
		}

		/* Rho + Pi step */
		c1 = A[PiLane[23]];
		for (i = 0; i < 24; i++) {
			c2 = A[PiLane[i]];
			A[PiLane[i]] = rol64(c1, RhoRot[i]);
			c1 = c2;
		}

		/* Chi step */
		for (i = 0; i < 25; ) {
			tmp[0] = A[i + 0];
			tmp[1] = A[i + 1];

			A[i] ^= ~A[i + 1] & A[i + 2]; i++;
			A[i] ^= ~A[i + 1] & A[i + 2]; i++;
			A[i] ^= ~A[i + 1] & A[i + 2]; i++;
			A[i] ^= ~A[i + 1] & tmp[0]; i++;
			A[i] ^= ~tmp[0] & tmp[1]; i++;
		}

		/* Iota step */
		A[0] ^= RoundConstants64[j];
	}
}

#else /* !KECCAK_SMALL - fast 64-bit */

static void keccak_f(struct KeccakContext *ctx)
{
	uint64_t *state = ctx->u.state64;
	uint64_t Ba, Be, Bi, Bo, Bu;
	uint64_t Ca, Ce, Ci, Co, Cu;
	uint64_t Da, De, Di, Do, Du;
	int i;

#define Aba state[0]
#define Abe state[1]
#define Abi state[2]
#define Abo state[3]
#define Abu state[4]
#define Aga state[5]
#define Age state[6]
#define Agi state[7]
#define Ago state[8]
#define Agu state[9]
#define Aka state[10]
#define Ake state[11]
#define Aki state[12]
#define Ako state[13]
#define Aku state[14]
#define Ama state[15]
#define Ame state[16]
#define Ami state[17]
#define Amo state[18]
#define Amu state[19]
#define Asa state[20]
#define Ase state[21]
#define Asi state[22]
#define Aso state[23]
#define Asu state[24]

	for (i = 0; i < KECCAK_ROUNDS; i += 4) {
		/* Code for 4 rounds */
		Ca = Aba^Aga^Aka^Ama^Asa;
		Ce = Abe^Age^Ake^Ame^Ase;
		Ci = Abi^Agi^Aki^Ami^Asi;
		Co = Abo^Ago^Ako^Amo^Aso;
		Cu = Abu^Agu^Aku^Amu^Asu;
		Da = Cu^rol64(Ce, 1);
		De = Ca^rol64(Ci, 1);
		Di = Ce^rol64(Co, 1);
		Do = Ci^rol64(Cu, 1);
		Du = Co^rol64(Ca, 1);

		Ba = (Aba^Da);
		Be = rol64((Age^De), 44);
		Bi = rol64((Aki^Di), 43);
		Bo = rol64((Amo^Do), 21);
		Bu = rol64((Asu^Du), 14);
		Aba = Ba ^((~Be)&  Bi);
		Aba ^= RoundConstants64[i + 0];
		Age = Be ^((~Bi)&  Bo);
		Aki = Bi ^((~Bo)&  Bu);
		Amo = Bo ^((~Bu)&  Ba);
		Asu = Bu ^((~Ba)&  Be);

		Bi = rol64((Aka^Da), 3);
		Bo = rol64((Ame^De), 45);
		Bu = rol64((Asi^Di), 61);
		Ba = rol64((Abo^Do), 28);
		Be = rol64((Agu^Du), 20);
		Aka = Ba ^((~Be)&  Bi);
		Ame = Be ^((~Bi)&  Bo);
		Asi = Bi ^((~Bo)&  Bu);
		Abo = Bo ^((~Bu)&  Ba);
		Agu = Bu ^((~Ba)&  Be);

		Bu = rol64((Asa^Da), 18);
		Ba = rol64((Abe^De), 1);
		Be = rol64((Agi^Di), 6);
		Bi = rol64((Ako^Do), 25);
		Bo = rol64((Amu^Du), 8);
		Asa = Ba ^((~Be)&  Bi);
		Abe = Be ^((~Bi)&  Bo);
		Agi = Bi ^((~Bo)&  Bu);
		Ako = Bo ^((~Bu)&  Ba);
		Amu = Bu ^((~Ba)&  Be);

		Be = rol64((Aga^Da), 36);
		Bi = rol64((Ake^De), 10);
		Bo = rol64((Ami^Di), 15);
		Bu = rol64((Aso^Do), 56);
		Ba = rol64((Abu^Du), 27);
		Aga = Ba ^((~Be)&  Bi);
		Ake = Be ^((~Bi)&  Bo);
		Ami = Bi ^((~Bo)&  Bu);
		Aso = Bo ^((~Bu)&  Ba);
		Abu = Bu ^((~Ba)&  Be);

		Bo = rol64((Ama^Da), 41);
		Bu = rol64((Ase^De), 2);
		Ba = rol64((Abi^Di), 62);
		Be = rol64((Ago^Do), 55);
		Bi = rol64((Aku^Du), 39);
		Ama = Ba ^((~Be)&  Bi);
		Ase = Be ^((~Bi)&  Bo);
		Abi = Bi ^((~Bo)&  Bu);
		Ago = Bo ^((~Bu)&  Ba);
		Aku = Bu ^((~Ba)&  Be);

		Ca = Aba^Aka^Asa^Aga^Ama;
		Ce = Age^Ame^Abe^Ake^Ase;
		Ci = Aki^Asi^Agi^Ami^Abi;
		Co = Amo^Abo^Ako^Aso^Ago;
		Cu = Asu^Agu^Amu^Abu^Aku;
		Da = Cu^rol64(Ce, 1);
		De = Ca^rol64(Ci, 1);
		Di = Ce^rol64(Co, 1);
		Do = Ci^rol64(Cu, 1);
		Du = Co^rol64(Ca, 1);

		Ba = (Aba^Da);
		Be = rol64((Ame^De), 44);
		Bi = rol64((Agi^Di), 43);
		Bo = rol64((Aso^Do), 21);
		Bu = rol64((Aku^Du), 14);
		Aba = Ba ^((~Be)&  Bi);
		Aba ^= RoundConstants64[i + 1];
		Ame = Be ^((~Bi)&  Bo);
		Agi = Bi ^((~Bo)&  Bu);
		Aso = Bo ^((~Bu)&  Ba);
		Aku = Bu ^((~Ba)&  Be);

		Bi = rol64((Asa^Da), 3);
		Bo = rol64((Ake^De), 45);
		Bu = rol64((Abi^Di), 61);
		Ba = rol64((Amo^Do), 28);
		Be = rol64((Agu^Du), 20);
		Asa = Ba ^((~Be)&  Bi);
		Ake = Be ^((~Bi)&  Bo);
		Abi = Bi ^((~Bo)&  Bu);
		Amo = Bo ^((~Bu)&  Ba);
		Agu = Bu ^((~Ba)&  Be);

		Bu = rol64((Ama^Da), 18);
		Ba = rol64((Age^De), 1);
		Be = rol64((Asi^Di), 6);
		Bi = rol64((Ako^Do), 25);
		Bo = rol64((Abu^Du), 8);
		Ama = Ba ^((~Be)&  Bi);
		Age = Be ^((~Bi)&  Bo);
		Asi = Bi ^((~Bo)&  Bu);
		Ako = Bo ^((~Bu)&  Ba);
		Abu = Bu ^((~Ba)&  Be);

		Be = rol64((Aka^Da), 36);
		Bi = rol64((Abe^De), 10);
		Bo = rol64((Ami^Di), 15);
		Bu = rol64((Ago^Do), 56);
		Ba = rol64((Asu^Du), 27);
		Aka = Ba ^((~Be)&  Bi);
		Abe = Be ^((~Bi)&  Bo);
		Ami = Bi ^((~Bo)&  Bu);
		Ago = Bo ^((~Bu)&  Ba);
		Asu = Bu ^((~Ba)&  Be);

		Bo = rol64((Aga^Da), 41);
		Bu = rol64((Ase^De), 2);
		Ba = rol64((Aki^Di), 62);
		Be = rol64((Abo^Do), 55);
		Bi = rol64((Amu^Du), 39);
		Aga = Ba ^((~Be)&  Bi);
		Ase = Be ^((~Bi)&  Bo);
		Aki = Bi ^((~Bo)&  Bu);
		Abo = Bo ^((~Bu)&  Ba);
		Amu = Bu ^((~Ba)&  Be);

		Ca = Aba^Asa^Ama^Aka^Aga;
		Ce = Ame^Ake^Age^Abe^Ase;
		Ci = Agi^Abi^Asi^Ami^Aki;
		Co = Aso^Amo^Ako^Ago^Abo;
		Cu = Aku^Agu^Abu^Asu^Amu;
		Da = Cu^rol64(Ce, 1);
		De = Ca^rol64(Ci, 1);
		Di = Ce^rol64(Co, 1);
		Do = Ci^rol64(Cu, 1);
		Du = Co^rol64(Ca, 1);

		Ba = (Aba^Da);
		Be = rol64((Ake^De), 44);
		Bi = rol64((Asi^Di), 43);
		Bo = rol64((Ago^Do), 21);
		Bu = rol64((Amu^Du), 14);
		Aba = Ba ^((~Be)&  Bi);
		Aba ^= RoundConstants64[i + 2];
		Ake = Be ^((~Bi)&  Bo);
		Asi = Bi ^((~Bo)&  Bu);
		Ago = Bo ^((~Bu)&  Ba);
		Amu = Bu ^((~Ba)&  Be);

		Bi = rol64((Ama^Da), 3);
		Bo = rol64((Abe^De), 45);
		Bu = rol64((Aki^Di), 61);
		Ba = rol64((Aso^Do), 28);
		Be = rol64((Agu^Du), 20);
		Ama = Ba ^((~Be)&  Bi);
		Abe = Be ^((~Bi)&  Bo);
		Aki = Bi ^((~Bo)&  Bu);
		Aso = Bo ^((~Bu)&  Ba);
		Agu = Bu ^((~Ba)&  Be);

		Bu = rol64((Aga^Da), 18);
		Ba = rol64((Ame^De), 1);
		Be = rol64((Abi^Di), 6);
		Bi = rol64((Ako^Do), 25);
		Bo = rol64((Asu^Du), 8);
		Aga = Ba ^((~Be)&  Bi);
		Ame = Be ^((~Bi)&  Bo);
		Abi = Bi ^((~Bo)&  Bu);
		Ako = Bo ^((~Bu)&  Ba);
		Asu = Bu ^((~Ba)&  Be);

		Be = rol64((Asa^Da), 36);
		Bi = rol64((Age^De), 10);
		Bo = rol64((Ami^Di), 15);
		Bu = rol64((Abo^Do), 56);
		Ba = rol64((Aku^Du), 27);
		Asa = Ba ^((~Be)&  Bi);
		Age = Be ^((~Bi)&  Bo);
		Ami = Bi ^((~Bo)&  Bu);
		Abo = Bo ^((~Bu)&  Ba);
		Aku = Bu ^((~Ba)&  Be);

		Bo = rol64((Aka^Da), 41);
		Bu = rol64((Ase^De), 2);
		Ba = rol64((Agi^Di), 62);
		Be = rol64((Amo^Do), 55);
		Bi = rol64((Abu^Du), 39);
		Aka = Ba ^((~Be)&  Bi);
		Ase = Be ^((~Bi)&  Bo);
		Agi = Bi ^((~Bo)&  Bu);
		Amo = Bo ^((~Bu)&  Ba);
		Abu = Bu ^((~Ba)&  Be);

		Ca = Aba^Ama^Aga^Asa^Aka;
		Ce = Ake^Abe^Ame^Age^Ase;
		Ci = Asi^Aki^Abi^Ami^Agi;
		Co = Ago^Aso^Ako^Abo^Amo;
		Cu = Amu^Agu^Asu^Aku^Abu;
		Da = Cu^rol64(Ce, 1);
		De = Ca^rol64(Ci, 1);
		Di = Ce^rol64(Co, 1);
		Do = Ci^rol64(Cu, 1);
		Du = Co^rol64(Ca, 1);

		Ba = (Aba^Da);
		Be = rol64((Abe^De), 44);
		Bi = rol64((Abi^Di), 43);
		Bo = rol64((Abo^Do), 21);
		Bu = rol64((Abu^Du), 14);
		Aba = Ba ^((~Be)&  Bi);
		Aba ^= RoundConstants64[i + 3];
		Abe = Be ^((~Bi)&  Bo);
		Abi = Bi ^((~Bo)&  Bu);
		Abo = Bo ^((~Bu)&  Ba);
		Abu = Bu ^((~Ba)&  Be);

		Bi = rol64((Aga^Da), 3);
		Bo = rol64((Age^De), 45);
		Bu = rol64((Agi^Di), 61);
		Ba = rol64((Ago^Do), 28);
		Be = rol64((Agu^Du), 20);
		Aga = Ba ^((~Be)&  Bi);
		Age = Be ^((~Bi)&  Bo);
		Agi = Bi ^((~Bo)&  Bu);
		Ago = Bo ^((~Bu)&  Ba);
		Agu = Bu ^((~Ba)&  Be);

		Bu = rol64((Aka^Da), 18);
		Ba = rol64((Ake^De), 1);
		Be = rol64((Aki^Di), 6);
		Bi = rol64((Ako^Do), 25);
		Bo = rol64((Aku^Du), 8);
		Aka = Ba ^((~Be)&  Bi);
		Ake = Be ^((~Bi)&  Bo);
		Aki = Bi ^((~Bo)&  Bu);
		Ako = Bo ^((~Bu)&  Ba);
		Aku = Bu ^((~Ba)&  Be);

		Be = rol64((Ama^Da), 36);
		Bi = rol64((Ame^De), 10);
		Bo = rol64((Ami^Di), 15);
		Bu = rol64((Amo^Do), 56);
		Ba = rol64((Amu^Du), 27);
		Ama = Ba ^((~Be)&  Bi);
		Ame = Be ^((~Bi)&  Bo);
		Ami = Bi ^((~Bo)&  Bu);
		Amo = Bo ^((~Bu)&  Ba);
		Amu = Bu ^((~Ba)&  Be);

		Bo = rol64((Asa^Da), 41);
		Bu = rol64((Ase^De), 2);
		Ba = rol64((Asi^Di), 62);
		Be = rol64((Aso^Do), 55);
		Bi = rol64((Asu^Du), 39);
		Asa = Ba ^((~Be)&  Bi);
		Ase = Be ^((~Bi)&  Bo);
		Asi = Bi ^((~Bo)&  Bu);
		Aso = Bo ^((~Bu)&  Ba);
		Asu = Bu ^((~Ba)&  Be);
	}
}

#endif /* !KECCAK_SMALL */

static inline void xor_lane(struct KeccakContext *ctx, int lane, uint64_t val)
{
	ctx->u.state64[lane] ^= val;
}

static void extract(uint8_t *dst, const struct KeccakContext *ctx, int startLane, int laneCount)
{
	const uint64_t *src = ctx->u.state64 + startLane;

	while (laneCount--) {
		le64enc(dst, *src++);
		dst += 8;
	}
}


#else /* KECCAK_32BIT */


/*
 * 32-bit implementation - one 64-bit lane is mapped
 * to two interleaved 32-bit words.
 */

static const uint32_t RoundConstants32[2*KECCAK_ROUNDS] = {
	0x00000001, 0x00000000, 0x00000000, 0x00000089,
	0x00000000, 0x8000008b, 0x00000000, 0x80008080,
	0x00000001, 0x0000008b, 0x00000001, 0x00008000,
	0x00000001, 0x80008088, 0x00000001, 0x80000082,
	0x00000000, 0x0000000b, 0x00000000, 0x0000000a,
	0x00000001, 0x00008082, 0x00000000, 0x00008003,
	0x00000001, 0x0000808b, 0x00000001, 0x8000000b,
	0x00000001, 0x8000008a, 0x00000001, 0x80000081,
	0x00000000, 0x80000081, 0x00000000, 0x80000008,
	0x00000000, 0x00000083, 0x00000000, 0x80008003,
	0x00000001, 0x80008088, 0x00000000, 0x80000088,
	0x00000001, 0x00008000, 0x00000000, 0x80008082,
};

#define KeccakAtoD_round0() \
	Cx = Abu0^Agu0^Aku0^Amu0^Asu0; \
	Du1 = Abe1^Age1^Ake1^Ame1^Ase1; \
	Da0 = Cx^rol32(Du1, 1); \
	Cz = Abu1^Agu1^Aku1^Amu1^Asu1; \
	Du0 = Abe0^Age0^Ake0^Ame0^Ase0; \
	Da1 = Cz^Du0; \
        \
	Cw = Abi0^Agi0^Aki0^Ami0^Asi0; \
	Do0 = Cw^rol32(Cz, 1); \
	Cy = Abi1^Agi1^Aki1^Ami1^Asi1; \
	Do1 = Cy^Cx; \
        \
	Cx = Aba0^Aga0^Aka0^Ama0^Asa0; \
	De0 = Cx^rol32(Cy, 1); \
	Cz = Aba1^Aga1^Aka1^Ama1^Asa1; \
	De1 = Cz^Cw; \
        \
	Cy = Abo1^Ago1^Ako1^Amo1^Aso1; \
	Di0 = Du0^rol32(Cy, 1); \
	Cw = Abo0^Ago0^Ako0^Amo0^Aso0; \
	Di1 = Du1^Cw; \
        \
	Du0 = Cw^rol32(Cz, 1); \
	Du1 = Cy^Cx;

#define KeccakAtoD_round1() \
	Cx = Asu0^Agu0^Amu0^Abu1^Aku1; \
	Du1 = Age1^Ame0^Abe0^Ake1^Ase1; \
	Da0 = Cx^rol32(Du1, 1); \
	Cz = Asu1^Agu1^Amu1^Abu0^Aku0; \
	Du0 = Age0^Ame1^Abe1^Ake0^Ase0; \
	Da1 = Cz^Du0; \
        \
	Cw = Aki1^Asi1^Agi0^Ami1^Abi0; \
	Do0 = Cw^rol32(Cz, 1); \
	Cy = Aki0^Asi0^Agi1^Ami0^Abi1; \
	Do1 = Cy^Cx; \
        \
	Cx = Aba0^Aka1^Asa0^Aga0^Ama1; \
	De0 = Cx^rol32(Cy, 1); \
	Cz = Aba1^Aka0^Asa1^Aga1^Ama0; \
	De1 = Cz^Cw; \
        \
	Cy = Amo0^Abo1^Ako0^Aso1^Ago0; \
	Di0 = Du0^rol32(Cy, 1); \
	Cw = Amo1^Abo0^Ako1^Aso0^Ago1; \
	Di1 = Du1^Cw; \
        \
	Du0 = Cw^rol32(Cz, 1); \
	Du1 = Cy^Cx;

#define KeccakAtoD_round2() \
	Cx = Aku1^Agu0^Abu1^Asu1^Amu1; \
	Du1 = Ame0^Ake0^Age0^Abe0^Ase1; \
	Da0 = Cx^rol32(Du1, 1); \
	Cz = Aku0^Agu1^Abu0^Asu0^Amu0; \
	Du0 = Ame1^Ake1^Age1^Abe1^Ase0; \
	Da1 = Cz^Du0; \
        \
	Cw = Agi1^Abi1^Asi1^Ami0^Aki1; \
	Do0 = Cw^rol32(Cz, 1); \
	Cy = Agi0^Abi0^Asi0^Ami1^Aki0; \
	Do1 = Cy^Cx; \
        \
	Cx = Aba0^Asa1^Ama1^Aka1^Aga1; \
	De0 = Cx^rol32(Cy, 1); \
	Cz = Aba1^Asa0^Ama0^Aka0^Aga0; \
	De1 = Cz^Cw; \
        \
	Cy = Aso0^Amo0^Ako1^Ago0^Abo0; \
	Di0 = Du0^rol32(Cy, 1); \
	Cw = Aso1^Amo1^Ako0^Ago1^Abo1; \
	Di1 = Du1^Cw; \
        \
	Du0 = Cw^rol32(Cz, 1); \
	Du1 = Cy^Cx;

#define KeccakAtoD_round3() \
	Cx = Amu1^Agu0^Asu1^Aku0^Abu0; \
	Du1 = Ake0^Abe1^Ame1^Age0^Ase1; \
	Da0 = Cx^rol32(Du1, 1); \
	Cz = Amu0^Agu1^Asu0^Aku1^Abu1; \
	Du0 = Ake1^Abe0^Ame0^Age1^Ase0; \
	Da1 = Cz^Du0; \
        \
	Cw = Asi0^Aki0^Abi1^Ami1^Agi1; \
	Do0 = Cw^rol32(Cz, 1); \
	Cy = Asi1^Aki1^Abi0^Ami0^Agi0; \
	Do1 = Cy^Cx; \
        \
	Cx = Aba0^Ama0^Aga1^Asa1^Aka0; \
	De0 = Cx^rol32(Cy, 1); \
	Cz = Aba1^Ama1^Aga0^Asa0^Aka1; \
	De1 = Cz^Cw; \
        \
	Cy = Ago1^Aso0^Ako0^Abo0^Amo1; \
	Di0 = Du0^rol32(Cy, 1); \
	Cw = Ago0^Aso1^Ako1^Abo1^Amo0; \
	Di1 = Du1^Cw; \
        \
	Du0 = Cw^rol32(Cz, 1); \
	Du1 = Cy^Cx;

static void keccak_f(struct KeccakContext *ctx)
{
	uint32_t *state = ctx->u.state32;
	uint32_t Da0, De0, Di0, Do0, Du0;
	uint32_t Da1, De1, Di1, Do1, Du1;
	uint32_t Ca0, Ce0, Ci0, Co0, Cu0;
	uint32_t Cx, Cy, Cz, Cw;
	int i;

#define Ba Ca0
#define Be Ce0
#define Bi Ci0
#define Bo Co0
#define Bu Cu0

#define Aba0 state[0]
#define Aba1 state[1]
#define Abe0 state[2]
#define Abe1 state[3]
#define Abi0 state[4]
#define Abi1 state[5]
#define Abo0 state[6]
#define Abo1 state[7]
#define Abu0 state[8]
#define Abu1 state[9]
#define Aga0 state[10]
#define Aga1 state[11]
#define Age0 state[12]
#define Age1 state[13]
#define Agi0 state[14]
#define Agi1 state[15]
#define Ago0 state[16]
#define Ago1 state[17]
#define Agu0 state[18]
#define Agu1 state[19]
#define Aka0 state[20]
#define Aka1 state[21]
#define Ake0 state[22]
#define Ake1 state[23]
#define Aki0 state[24]
#define Aki1 state[25]
#define Ako0 state[26]
#define Ako1 state[27]
#define Aku0 state[28]
#define Aku1 state[29]
#define Ama0 state[30]
#define Ama1 state[31]
#define Ame0 state[32]
#define Ame1 state[33]
#define Ami0 state[34]
#define Ami1 state[35]
#define Amo0 state[36]
#define Amo1 state[37]
#define Amu0 state[38]
#define Amu1 state[39]
#define Asa0 state[40]
#define Asa1 state[41]
#define Ase0 state[42]
#define Ase1 state[43]
#define Asi0 state[44]
#define Asi1 state[45]
#define Aso0 state[46]
#define Aso1 state[47]
#define Asu0 state[48]
#define Asu1 state[49]

	for (i = 0; i < KECCAK_ROUNDS*2; i += 8) {
		/* Code for 4 rounds */
		KeccakAtoD_round0();

		Ba = (Aba0^Da0);
		Be = rol32((Age0^De0), 22);
		Bi = rol32((Aki1^Di1), 22);
		Bo = rol32((Amo1^Do1), 11);
		Bu = rol32((Asu0^Du0), 7);
		Aba0 = Ba ^((~Be)&  Bi);
		Aba0 ^= RoundConstants32[i + 0];
		Age0 = Be ^((~Bi)&  Bo);
		Aki1 = Bi ^((~Bo)&  Bu);
		Amo1 = Bo ^((~Bu)&  Ba);
		Asu0 = Bu ^((~Ba)&  Be);

		Ba = (Aba1^Da1);
		Be = rol32((Age1^De1), 22);
		Bi = rol32((Aki0^Di0), 21);
		Bo = rol32((Amo0^Do0), 10);
		Bu = rol32((Asu1^Du1), 7);
		Aba1 = Ba ^((~Be)&  Bi);
		Aba1 ^= RoundConstants32[i + 1];
		Age1 = Be ^((~Bi)&  Bo);
		Aki0 = Bi ^((~Bo)&  Bu);
		Amo0 = Bo ^((~Bu)&  Ba);
		Asu1 = Bu ^((~Ba)&  Be);

		Bi = rol32((Aka1^Da1), 2);
		Bo = rol32((Ame1^De1), 23);
		Bu = rol32((Asi1^Di1), 31);
		Ba = rol32((Abo0^Do0), 14);
		Be = rol32((Agu0^Du0), 10);
		Aka1 = Ba ^((~Be)&  Bi);
		Ame1 = Be ^((~Bi)&  Bo);
		Asi1 = Bi ^((~Bo)&  Bu);
		Abo0 = Bo ^((~Bu)&  Ba);
		Agu0 = Bu ^((~Ba)&  Be);

		Bi = rol32((Aka0^Da0), 1);
		Bo = rol32((Ame0^De0), 22);
		Bu = rol32((Asi0^Di0), 30);
		Ba = rol32((Abo1^Do1), 14);
		Be = rol32((Agu1^Du1), 10);
		Aka0 = Ba ^((~Be)&  Bi);
		Ame0 = Be ^((~Bi)&  Bo);
		Asi0 = Bi ^((~Bo)&  Bu);
		Abo1 = Bo ^((~Bu)&  Ba);
		Agu1 = Bu ^((~Ba)&  Be);

		Bu = rol32((Asa0^Da0), 9);
		Ba = rol32((Abe1^De1), 1);
		Be = rol32((Agi0^Di0), 3);
		Bi = rol32((Ako1^Do1), 13);
		Bo = rol32((Amu0^Du0), 4);
		Asa0 = Ba ^((~Be)&  Bi);
		Abe1 = Be ^((~Bi)&  Bo);
		Agi0 = Bi ^((~Bo)&  Bu);
		Ako1 = Bo ^((~Bu)&  Ba);
		Amu0 = Bu ^((~Ba)&  Be);

		Bu = rol32((Asa1^Da1), 9);
		Ba = (Abe0^De0);
		Be = rol32((Agi1^Di1), 3);
		Bi = rol32((Ako0^Do0), 12);
		Bo = rol32((Amu1^Du1), 4);
		Asa1 = Ba ^((~Be)&  Bi);
		Abe0 = Be ^((~Bi)&  Bo);
		Agi1 = Bi ^((~Bo)&  Bu);
		Ako0 = Bo ^((~Bu)&  Ba);
		Amu1 = Bu ^((~Ba)&  Be);

		Be = rol32((Aga0^Da0), 18);
		Bi = rol32((Ake0^De0), 5);
		Bo = rol32((Ami1^Di1), 8);
		Bu = rol32((Aso0^Do0), 28);
		Ba = rol32((Abu1^Du1), 14);
		Aga0 = Ba ^((~Be)&  Bi);
		Ake0 = Be ^((~Bi)&  Bo);
		Ami1 = Bi ^((~Bo)&  Bu);
		Aso0 = Bo ^((~Bu)&  Ba);
		Abu1 = Bu ^((~Ba)&  Be);

		Be = rol32((Aga1^Da1), 18);
		Bi = rol32((Ake1^De1), 5);
		Bo = rol32((Ami0^Di0), 7);
		Bu = rol32((Aso1^Do1), 28);
		Ba = rol32((Abu0^Du0), 13);
		Aga1 = Ba ^((~Be)&  Bi);
		Ake1 = Be ^((~Bi)&  Bo);
		Ami0 = Bi ^((~Bo)&  Bu);
		Aso1 = Bo ^((~Bu)&  Ba);
		Abu0 = Bu ^((~Ba)&  Be);

		Bo = rol32((Ama1^Da1), 21);
		Bu = rol32((Ase0^De0), 1);
		Ba = rol32((Abi0^Di0), 31);
		Be = rol32((Ago1^Do1), 28);
		Bi = rol32((Aku1^Du1), 20);
		Ama1 = Ba ^((~Be)&  Bi);
		Ase0 = Be ^((~Bi)&  Bo);
		Abi0 = Bi ^((~Bo)&  Bu);
		Ago1 = Bo ^((~Bu)&  Ba);
		Aku1 = Bu ^((~Ba)&  Be);

		Bo = rol32((Ama0^Da0), 20);
		Bu = rol32((Ase1^De1), 1);
		Ba = rol32((Abi1^Di1), 31);
		Be = rol32((Ago0^Do0), 27);
		Bi = rol32((Aku0^Du0), 19);
		Ama0 = Ba ^((~Be)&  Bi);
		Ase1 = Be ^((~Bi)&  Bo);
		Abi1 = Bi ^((~Bo)&  Bu);
		Ago0 = Bo ^((~Bu)&  Ba);
		Aku0 = Bu ^((~Ba)&  Be);

		KeccakAtoD_round1();

		Ba = (Aba0^Da0);
		Be = rol32((Ame1^De0), 22);
		Bi = rol32((Agi1^Di1), 22);
		Bo = rol32((Aso1^Do1), 11);
		Bu = rol32((Aku1^Du0), 7);
		Aba0 = Ba ^((~Be)&  Bi);
		Aba0 ^= RoundConstants32[i + 2];
		Ame1 = Be ^((~Bi)&  Bo);
		Agi1 = Bi ^((~Bo)&  Bu);
		Aso1 = Bo ^((~Bu)&  Ba);
		Aku1 = Bu ^((~Ba)&  Be);

		Ba = (Aba1^Da1);
		Be = rol32((Ame0^De1), 22);
		Bi = rol32((Agi0^Di0), 21);
		Bo = rol32((Aso0^Do0), 10);
		Bu = rol32((Aku0^Du1), 7);
		Aba1 = Ba ^((~Be)&  Bi);
		Aba1 ^= RoundConstants32[i + 3];
		Ame0 = Be ^((~Bi)&  Bo);
		Agi0 = Bi ^((~Bo)&  Bu);
		Aso0 = Bo ^((~Bu)&  Ba);
		Aku0 = Bu ^((~Ba)&  Be);

		Bi = rol32((Asa1^Da1), 2);
		Bo = rol32((Ake1^De1), 23);
		Bu = rol32((Abi1^Di1), 31);
		Ba = rol32((Amo1^Do0), 14);
		Be = rol32((Agu0^Du0), 10);
		Asa1 = Ba ^((~Be)&  Bi);
		Ake1 = Be ^((~Bi)&  Bo);
		Abi1 = Bi ^((~Bo)&  Bu);
		Amo1 = Bo ^((~Bu)&  Ba);
		Agu0 = Bu ^((~Ba)&  Be);

		Bi = rol32((Asa0^Da0), 1);
		Bo = rol32((Ake0^De0), 22);
		Bu = rol32((Abi0^Di0), 30);
		Ba = rol32((Amo0^Do1), 14);
		Be = rol32((Agu1^Du1), 10);
		Asa0 = Ba ^((~Be)&  Bi);
		Ake0 = Be ^((~Bi)&  Bo);
		Abi0 = Bi ^((~Bo)&  Bu);
		Amo0 = Bo ^((~Bu)&  Ba);
		Agu1 = Bu ^((~Ba)&  Be);

		Bu = rol32((Ama1^Da0), 9);
		Ba = rol32((Age1^De1), 1);
		Be = rol32((Asi1^Di0), 3);
		Bi = rol32((Ako0^Do1), 13);
		Bo = rol32((Abu1^Du0), 4);
		Ama1 = Ba ^((~Be)&  Bi);
		Age1 = Be ^((~Bi)&  Bo);
		Asi1 = Bi ^((~Bo)&  Bu);
		Ako0 = Bo ^((~Bu)&  Ba);
		Abu1 = Bu ^((~Ba)&  Be);

		Bu = rol32((Ama0^Da1), 9);
		Ba = (Age0^De0);
		Be = rol32((Asi0^Di1), 3);
		Bi = rol32((Ako1^Do0), 12);
		Bo = rol32((Abu0^Du1), 4);
		Ama0 = Ba ^((~Be)&  Bi);
		Age0 = Be ^((~Bi)&  Bo);
		Asi0 = Bi ^((~Bo)&  Bu);
		Ako1 = Bo ^((~Bu)&  Ba);
		Abu0 = Bu ^((~Ba)&  Be);

		Be = rol32((Aka1^Da0), 18);
		Bi = rol32((Abe1^De0), 5);
		Bo = rol32((Ami0^Di1), 8);
		Bu = rol32((Ago1^Do0), 28);
		Ba = rol32((Asu1^Du1), 14);
		Aka1 = Ba ^((~Be)&  Bi);
		Abe1 = Be ^((~Bi)&  Bo);
		Ami0 = Bi ^((~Bo)&  Bu);
		Ago1 = Bo ^((~Bu)&  Ba);
		Asu1 = Bu ^((~Ba)&  Be);

		Be = rol32((Aka0^Da1), 18);
		Bi = rol32((Abe0^De1), 5);
		Bo = rol32((Ami1^Di0), 7);
		Bu = rol32((Ago0^Do1), 28);
		Ba = rol32((Asu0^Du0), 13);
		Aka0 = Ba ^((~Be)&  Bi);
		Abe0 = Be ^((~Bi)&  Bo);
		Ami1 = Bi ^((~Bo)&  Bu);
		Ago0 = Bo ^((~Bu)&  Ba);
		Asu0 = Bu ^((~Ba)&  Be);

		Bo = rol32((Aga1^Da1), 21);
		Bu = rol32((Ase0^De0), 1);
		Ba = rol32((Aki1^Di0), 31);
		Be = rol32((Abo1^Do1), 28);
		Bi = rol32((Amu1^Du1), 20);
		Aga1 = Ba ^((~Be)&  Bi);
		Ase0 = Be ^((~Bi)&  Bo);
		Aki1 = Bi ^((~Bo)&  Bu);
		Abo1 = Bo ^((~Bu)&  Ba);
		Amu1 = Bu ^((~Ba)&  Be);

		Bo = rol32((Aga0^Da0), 20);
		Bu = rol32((Ase1^De1), 1);
		Ba = rol32((Aki0^Di1), 31);
		Be = rol32((Abo0^Do0), 27);
		Bi = rol32((Amu0^Du0), 19);
		Aga0 = Ba ^((~Be)&  Bi);
		Ase1 = Be ^((~Bi)&  Bo);
		Aki0 = Bi ^((~Bo)&  Bu);
		Abo0 = Bo ^((~Bu)&  Ba);
		Amu0 = Bu ^((~Ba)&  Be);

		KeccakAtoD_round2();

		Ba = (Aba0^Da0);
		Be = rol32((Ake1^De0), 22);
		Bi = rol32((Asi0^Di1), 22);
		Bo = rol32((Ago0^Do1), 11);
		Bu = rol32((Amu1^Du0), 7);
		Aba0 = Ba ^((~Be)&  Bi);
		Aba0 ^= RoundConstants32[i + 4];
		Ake1 = Be ^((~Bi)&  Bo);
		Asi0 = Bi ^((~Bo)&  Bu);
		Ago0 = Bo ^((~Bu)&  Ba);
		Amu1 = Bu ^((~Ba)&  Be);

		Ba = (Aba1^Da1);
		Be = rol32((Ake0^De1), 22);
		Bi = rol32((Asi1^Di0), 21);
		Bo = rol32((Ago1^Do0), 10);
		Bu = rol32((Amu0^Du1), 7);
		Aba1 = Ba ^((~Be)&  Bi);
		Aba1 ^= RoundConstants32[i + 5];
		Ake0 = Be ^((~Bi)&  Bo);
		Asi1 = Bi ^((~Bo)&  Bu);
		Ago1 = Bo ^((~Bu)&  Ba);
		Amu0 = Bu ^((~Ba)&  Be);

		Bi = rol32((Ama0^Da1), 2);
		Bo = rol32((Abe0^De1), 23);
		Bu = rol32((Aki0^Di1), 31);
		Ba = rol32((Aso1^Do0), 14);
		Be = rol32((Agu0^Du0), 10);
		Ama0 = Ba ^((~Be)&  Bi);
		Abe0 = Be ^((~Bi)&  Bo);
		Aki0 = Bi ^((~Bo)&  Bu);
		Aso1 = Bo ^((~Bu)&  Ba);
		Agu0 = Bu ^((~Ba)&  Be);

		Bi = rol32((Ama1^Da0), 1);
		Bo = rol32((Abe1^De0), 22);
		Bu = rol32((Aki1^Di0), 30);
		Ba = rol32((Aso0^Do1), 14);
		Be = rol32((Agu1^Du1), 10);
		Ama1 = Ba ^((~Be)&  Bi);
		Abe1 = Be ^((~Bi)&  Bo);
		Aki1 = Bi ^((~Bo)&  Bu);
		Aso0 = Bo ^((~Bu)&  Ba);
		Agu1 = Bu ^((~Ba)&  Be);

		Bu = rol32((Aga1^Da0), 9);
		Ba = rol32((Ame0^De1), 1);
		Be = rol32((Abi1^Di0), 3);
		Bi = rol32((Ako1^Do1), 13);
		Bo = rol32((Asu1^Du0), 4);
		Aga1 = Ba ^((~Be)&  Bi);
		Ame0 = Be ^((~Bi)&  Bo);
		Abi1 = Bi ^((~Bo)&  Bu);
		Ako1 = Bo ^((~Bu)&  Ba);
		Asu1 = Bu ^((~Ba)&  Be);

		Bu = rol32((Aga0^Da1), 9);
		Ba = (Ame1^De0);
		Be = rol32((Abi0^Di1), 3);
		Bi = rol32((Ako0^Do0), 12);
		Bo = rol32((Asu0^Du1), 4);
		Aga0 = Ba ^((~Be)&  Bi);
		Ame1 = Be ^((~Bi)&  Bo);
		Abi0 = Bi ^((~Bo)&  Bu);
		Ako0 = Bo ^((~Bu)&  Ba);
		Asu0 = Bu ^((~Ba)&  Be);

		Be = rol32((Asa1^Da0), 18);
		Bi = rol32((Age1^De0), 5);
		Bo = rol32((Ami1^Di1), 8);
		Bu = rol32((Abo1^Do0), 28);
		Ba = rol32((Aku0^Du1), 14);
		Asa1 = Ba ^((~Be)&  Bi);
		Age1 = Be ^((~Bi)&  Bo);
		Ami1 = Bi ^((~Bo)&  Bu);
		Abo1 = Bo ^((~Bu)&  Ba);
		Aku0 = Bu ^((~Ba)&  Be);

		Be = rol32((Asa0^Da1), 18);
		Bi = rol32((Age0^De1), 5);
		Bo = rol32((Ami0^Di0), 7);
		Bu = rol32((Abo0^Do1), 28);
		Ba = rol32((Aku1^Du0), 13);
		Asa0 = Ba ^((~Be)&  Bi);
		Age0 = Be ^((~Bi)&  Bo);
		Ami0 = Bi ^((~Bo)&  Bu);
		Abo0 = Bo ^((~Bu)&  Ba);
		Aku1 = Bu ^((~Ba)&  Be);

		Bo = rol32((Aka0^Da1), 21);
		Bu = rol32((Ase0^De0), 1);
		Ba = rol32((Agi1^Di0), 31);
		Be = rol32((Amo0^Do1), 28);
		Bi = rol32((Abu0^Du1), 20);
		Aka0 = Ba ^((~Be)&  Bi);
		Ase0 = Be ^((~Bi)&  Bo);
		Agi1 = Bi ^((~Bo)&  Bu);
		Amo0 = Bo ^((~Bu)&  Ba);
		Abu0 = Bu ^((~Ba)&  Be);

		Bo = rol32((Aka1^Da0), 20);
		Bu = rol32((Ase1^De1), 1);
		Ba = rol32((Agi0^Di1), 31);
		Be = rol32((Amo1^Do0), 27);
		Bi = rol32((Abu1^Du0), 19);
		Aka1 = Ba ^((~Be)&  Bi);
		Ase1 = Be ^((~Bi)&  Bo);
		Agi0 = Bi ^((~Bo)&  Bu);
		Amo1 = Bo ^((~Bu)&  Ba);
		Abu1 = Bu ^((~Ba)&  Be);

		KeccakAtoD_round3();

		Ba = (Aba0^Da0);
		Be = rol32((Abe0^De0), 22);
		Bi = rol32((Abi0^Di1), 22);
		Bo = rol32((Abo0^Do1), 11);
		Bu = rol32((Abu0^Du0), 7);
		Aba0 = Ba ^((~Be)&  Bi);
		Aba0 ^= RoundConstants32[i + 6];
		Abe0 = Be ^((~Bi)&  Bo);
		Abi0 = Bi ^((~Bo)&  Bu);
		Abo0 = Bo ^((~Bu)&  Ba);
		Abu0 = Bu ^((~Ba)&  Be);

		Ba = (Aba1^Da1);
		Be = rol32((Abe1^De1), 22);
		Bi = rol32((Abi1^Di0), 21);
		Bo = rol32((Abo1^Do0), 10);
		Bu = rol32((Abu1^Du1), 7);
		Aba1 = Ba ^((~Be)&  Bi);
		Aba1 ^= RoundConstants32[i + 7];
		Abe1 = Be ^((~Bi)&  Bo);
		Abi1 = Bi ^((~Bo)&  Bu);
		Abo1 = Bo ^((~Bu)&  Ba);
		Abu1 = Bu ^((~Ba)&  Be);

		Bi = rol32((Aga0^Da1), 2);
		Bo = rol32((Age0^De1), 23);
		Bu = rol32((Agi0^Di1), 31);
		Ba = rol32((Ago0^Do0), 14);
		Be = rol32((Agu0^Du0), 10);
		Aga0 = Ba ^((~Be)&  Bi);
		Age0 = Be ^((~Bi)&  Bo);
		Agi0 = Bi ^((~Bo)&  Bu);
		Ago0 = Bo ^((~Bu)&  Ba);
		Agu0 = Bu ^((~Ba)&  Be);

		Bi = rol32((Aga1^Da0), 1);
		Bo = rol32((Age1^De0), 22);
		Bu = rol32((Agi1^Di0), 30);
		Ba = rol32((Ago1^Do1), 14);
		Be = rol32((Agu1^Du1), 10);
		Aga1 = Ba ^((~Be)&  Bi);
		Age1 = Be ^((~Bi)&  Bo);
		Agi1 = Bi ^((~Bo)&  Bu);
		Ago1 = Bo ^((~Bu)&  Ba);
		Agu1 = Bu ^((~Ba)&  Be);

		Bu = rol32((Aka0^Da0), 9);
		Ba = rol32((Ake0^De1), 1);
		Be = rol32((Aki0^Di0), 3);
		Bi = rol32((Ako0^Do1), 13);
		Bo = rol32((Aku0^Du0), 4);
		Aka0 = Ba ^((~Be)&  Bi);
		Ake0 = Be ^((~Bi)&  Bo);
		Aki0 = Bi ^((~Bo)&  Bu);
		Ako0 = Bo ^((~Bu)&  Ba);
		Aku0 = Bu ^((~Ba)&  Be);

		Bu = rol32((Aka1^Da1), 9);
		Ba = (Ake1^De0);
		Be = rol32((Aki1^Di1), 3);
		Bi = rol32((Ako1^Do0), 12);
		Bo = rol32((Aku1^Du1), 4);
		Aka1 = Ba ^((~Be)&  Bi);
		Ake1 = Be ^((~Bi)&  Bo);
		Aki1 = Bi ^((~Bo)&  Bu);
		Ako1 = Bo ^((~Bu)&  Ba);
		Aku1 = Bu ^((~Ba)&  Be);

		Be = rol32((Ama0^Da0), 18);
		Bi = rol32((Ame0^De0), 5);
		Bo = rol32((Ami0^Di1), 8);
		Bu = rol32((Amo0^Do0), 28);
		Ba = rol32((Amu0^Du1), 14);
		Ama0 = Ba ^((~Be)&  Bi);
		Ame0 = Be ^((~Bi)&  Bo);
		Ami0 = Bi ^((~Bo)&  Bu);
		Amo0 = Bo ^((~Bu)&  Ba);
		Amu0 = Bu ^((~Ba)&  Be);

		Be = rol32((Ama1^Da1), 18);
		Bi = rol32((Ame1^De1), 5);
		Bo = rol32((Ami1^Di0), 7);
		Bu = rol32((Amo1^Do1), 28);
		Ba = rol32((Amu1^Du0), 13);
		Ama1 = Ba ^((~Be)&  Bi);
		Ame1 = Be ^((~Bi)&  Bo);
		Ami1 = Bi ^((~Bo)&  Bu);
		Amo1 = Bo ^((~Bu)&  Ba);
		Amu1 = Bu ^((~Ba)&  Be);

		Bo = rol32((Asa0^Da1), 21);
		Bu = rol32((Ase0^De0), 1);
		Ba = rol32((Asi0^Di0), 31);
		Be = rol32((Aso0^Do1), 28);
		Bi = rol32((Asu0^Du1), 20);
		Asa0 = Ba ^((~Be)&  Bi);
		Ase0 = Be ^((~Bi)&  Bo);
		Asi0 = Bi ^((~Bo)&  Bu);
		Aso0 = Bo ^((~Bu)&  Ba);
		Asu0 = Bu ^((~Ba)&  Be);

		Bo = rol32((Asa1^Da0), 20);
		Bu = rol32((Ase1^De1), 1);
		Ba = rol32((Asi1^Di1), 31);
		Be = rol32((Aso1^Do0), 27);
		Bi = rol32((Asu1^Du0), 19);
		Asa1 = Ba ^((~Be)&  Bi);
		Ase1 = Be ^((~Bi)&  Bo);
		Asi1 = Bi ^((~Bo)&  Bu);
		Aso1 = Bo ^((~Bu)&  Ba);
		Asu1 = Bu ^((~Ba)&  Be);
	}
}

static void xor_lane(struct KeccakContext *ctx, int lane, uint64_t val)
{
	uint32_t x0, x1, t;
	uint32_t *dst = ctx->u.state32 + lane*2;

	x0 = val;
	t = (x0 ^ (x0 >>  1)) & 0x22222222;  x0 = x0 ^ t ^ (t <<  1);
	t = (x0 ^ (x0 >>  2)) & 0x0C0C0C0C;  x0 = x0 ^ t ^ (t <<  2);
	t = (x0 ^ (x0 >>  4)) & 0x00F000F0;  x0 = x0 ^ t ^ (t <<  4);
	t = (x0 ^ (x0 >>  8)) & 0x0000FF00;  x0 = x0 ^ t ^ (t <<  8);
	x1 = val >> 32;
	t = (x1 ^ (x1 >>  1)) & 0x22222222;  x1 = x1 ^ t ^ (t <<  1);
	t = (x1 ^ (x1 >>  2)) & 0x0C0C0C0C;  x1 = x1 ^ t ^ (t <<  2);
	t = (x1 ^ (x1 >>  4)) & 0x00F000F0;  x1 = x1 ^ t ^ (t <<  4);
	t = (x1 ^ (x1 >>  8)) & 0x0000FF00;  x1 = x1 ^ t ^ (t <<  8);
	dst[0] ^= (x0 & 0x0000FFFF) | (x1 << 16);
	dst[1] ^= (x0 >> 16) | (x1 & 0xFFFF0000);
}

static void extract(uint8_t *dst, const struct KeccakContext *ctx, int startLane, int laneCount)
{
	const uint32_t *src = ctx->u.state32 + startLane * 2;
	uint32_t t, x0, x1;

	while (laneCount--) {
		x0 = *src++;
		x1 = *src++;
		t = (x0 & 0x0000FFFF) | (x1 << 16);
		x1 = (x0 >> 16) | (x1 & 0xFFFF0000);
		x0 = t;
		t = (x0 ^ (x0 >>  8)) & 0x0000FF00;  x0 = x0 ^ t ^ (t <<  8);
		t = (x0 ^ (x0 >>  4)) & 0x00F000F0;  x0 = x0 ^ t ^ (t <<  4);
		t = (x0 ^ (x0 >>  2)) & 0x0C0C0C0C;  x0 = x0 ^ t ^ (t <<  2);
		t = (x0 ^ (x0 >>  1)) & 0x22222222;  x0 = x0 ^ t ^ (t <<  1);
		t = (x1 ^ (x1 >>  8)) & 0x0000FF00;  x1 = x1 ^ t ^ (t <<  8);
		t = (x1 ^ (x1 >>  4)) & 0x00F000F0;  x1 = x1 ^ t ^ (t <<  4);
		t = (x1 ^ (x1 >>  2)) & 0x0C0C0C0C;  x1 = x1 ^ t ^ (t <<  2);
		t = (x1 ^ (x1 >>  1)) & 0x22222222;  x1 = x1 ^ t ^ (t <<  1);
		le32enc(dst + 0, x0);
		le32enc(dst + 4, x1);
		dst += 8;
	}
}

#endif /* KECCAK_32BIT */


/*
 * Common code
 */

static void xor_byte(struct KeccakContext *ctx, int nbyte, uint8_t val)
{
	int o = nbyte / 8;
	int s = (nbyte % 8) * 8;

	xor_lane(ctx, o, (uint64_t)(val) << s);
}

static void add_bytes(struct KeccakContext *ctx, const uint8_t *p, unsigned int ofs, unsigned int len)
{
	uint64_t w;
	unsigned int m = ofs % 8;

	/* partial word */
	if (m) {
		m = 8 - m;
		if (m > len)
			m = len;
		while (m--) {
			xor_byte(ctx, ofs++, *p++);
			len--;
		}
	}

	/* full words */
	while (len >= 8) {
		w = le64dec(p);
		xor_lane(ctx, ofs / 8, w);
		ofs += 8;
		p += 8;
		len -= 8;
	}

	/* partial word */
	while (len--)
		xor_byte(ctx, ofs++, *p++);
}

static void extract_bytes(struct KeccakContext *ctx, uint8_t *dst, unsigned int ofs, unsigned int count)
{
	uint8_t lanebuf[8];
	unsigned int n, avail;

	if (ofs % 8 != 0 || count < 8) {
		avail = 8 - ofs % 8;
		n = (avail > count) ? count : avail;
		extract(lanebuf, ctx, ofs/8, 1);
		memcpy(dst, lanebuf + ofs%8, n);
		dst += n;
		ofs += n;
		count -= n;
	}

	if (count > 8) {
		n = count / 8;
		extract(dst, ctx, ofs/8, n);
		dst += n*8;
		ofs += n*8;
		count -= n*8;
	}

	if (count > 0) {
		extract(lanebuf, ctx, ofs/8, 1);
		memcpy(dst, lanebuf, count);
	}

	memset(lanebuf, 0, sizeof(lanebuf));
}

static inline void permute_if_needed(struct KeccakContext *ctx)
{
	if (ctx->pos == ctx->rbytes) {
		keccak_f(ctx);
		ctx->pos = 0;
	}
}

/*
 * Public API
 */

int keccak_init(struct KeccakContext *ctx, unsigned int capacity)
{
	if (capacity % 8 != 0 || capacity < 8 || capacity > (1600 - 8))
		return 0;
	memset(ctx, 0, sizeof(struct KeccakContext));
	ctx->rbytes = (1600 - capacity) / 8;
	return 1;
}

void keccak_absorb(struct KeccakContext *ctx, const void *data, size_t len)
{
	unsigned int n, avail;
	const uint8_t *src = data;

	while (len > 0) {
		avail = ctx->rbytes - ctx->pos;
		n = (len > avail) ? avail : len;

		add_bytes(ctx, src, ctx->pos, n);

		src += n;
		len -= n;
		ctx->pos += n;

		permute_if_needed(ctx);
	}
}

void keccak_squeeze(struct KeccakContext *ctx, uint8_t *dst, size_t len)
{
	unsigned int avail, n;

	while (len > 0) {
		avail = ctx->rbytes - ctx->pos;
		n = (len > avail) ? avail : len;

		extract_bytes(ctx, dst, ctx->pos, n);

		ctx->pos += n;
		dst += n;
		len -= n;

		permute_if_needed(ctx);
	}
}

void keccak_squeeze_xor(struct KeccakContext *ctx, uint8_t *dst, const void *data, size_t len)
{
	const uint8_t *src = data;
	unsigned int n, avail, i;

	while (len > 0) {
		avail = ctx->rbytes - ctx->pos;
		n = (len > avail) ? avail : len;

		extract_bytes(ctx, dst, ctx->pos, n);
		for (i = 0; i < n; i++)
			dst[i] ^= src[i];

		ctx->pos += n;
		src += n;
		dst += n;
		len -= n;

		permute_if_needed(ctx);
	}
}

void keccak_encrypt(struct KeccakContext *ctx, uint8_t *dst, const void *data, size_t len)
{
	const uint8_t *src = data;
	unsigned int n, avail;

	while (len > 0) {
		avail = ctx->rbytes - ctx->pos;
		n = (len > avail) ? avail : len;

		add_bytes(ctx, src, ctx->pos, n);
		extract_bytes(ctx, dst, ctx->pos, n);

		ctx->pos += n;
		src += n;
		dst += n;
		len -= n;

		permute_if_needed(ctx);
	}
}

void keccak_decrypt(struct KeccakContext *ctx, uint8_t *dst, const void *data, size_t len)
{
	const uint8_t *src = data;
	unsigned int n, avail, i;

	while (len > 0) {
		avail = ctx->rbytes - ctx->pos;
		n = (len > avail) ? avail : len;

		extract_bytes(ctx, dst, ctx->pos, n);
		for (i = 0; i < n; i++)
			dst[i] ^= src[i];
		add_bytes(ctx, dst, ctx->pos, n);

		ctx->pos += n;
		src += n;
		dst += n;
		len -= n;

		permute_if_needed(ctx);
	}
}

void keccak_pad(struct KeccakContext *ctx, const void *pad, size_t len)
{
	const uint8_t *src = pad;

	if (len > 0) {
		if (len > 1) {
			keccak_absorb(ctx, src, len - 1);
			src += len - 1;
		}
		xor_byte(ctx, ctx->pos, src[0]);
		xor_byte(ctx, ctx->rbytes - 1, 0x80);
	}
	keccak_f(ctx);
	ctx->pos = 0;
}

void keccak_rewind(struct KeccakContext *ctx)
{
	ctx->pos = 0;
}

void keccak_forget(struct KeccakContext *ctx)
{
	unsigned int rem = ctx->rbytes % 8;
	uint8_t buf[8];

	memset(ctx->u.state32, 0, ctx->rbytes - rem);
	if (rem) {
		extract_bytes(ctx, buf, ctx->rbytes - rem, rem);
		add_bytes(ctx, buf, ctx->rbytes - rem, rem);
		memset(buf, 0, sizeof(buf));
	}
	ctx->pos = 0;
}
