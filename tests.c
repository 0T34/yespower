/*-
 * Copyright 2013-2018 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
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

#include <stdio.h>
#include <string.h>

#include "yespower.h"

#undef TEST_PBKDF2_SHA1
#ifdef TEST_PBKDF2_SHA1

#include <assert.h>

#include "sha1.h"

static void print_PBKDF2_SHA1_raw(const char *passwd, size_t passwdlen,
    const char *salt, size_t saltlen, uint64_t c, size_t dkLen) {
	uint8_t dk[64];
	size_t i;

	assert(dkLen <= sizeof(dk));

	/* XXX This prints the strings truncated at first NUL */
	printf("PBKDF2_SHA1(\"%s\", \"%s\", %llu, %llu) = ",
	    passwd, salt, (unsigned long long)c, (unsigned long long)dkLen);

	PBKDF2_SHA1((const uint8_t *) passwd, passwdlen,
	    (const uint8_t *) salt, saltlen, c, dk, dkLen);

	for (i = 0; i < dkLen; i++) {
		printf("%02x%c", dk[i], i < dkLen - 1 ? ' ' : '\n');
	}
}

static void print_PBKDF2_SHA1(const char *passwd,
    const char *salt, uint64_t c, size_t dkLen) {
	print_PBKDF2_SHA1_raw(passwd, strlen(passwd), salt, strlen(salt), c,
	    dkLen);
}
#endif

static const char *pers_bsty_magic = "BSTY";

static void print_yespower(uint32_t N, uint32_t r, const char *pers) {
	yespower_params_t params = {
		.N = N,
		.r = r,
		.pers = (const uint8_t *)pers,
		.perslen = pers ? strlen(pers) : 0
	};
	uint8_t src[80];
	yespower_binary_t dst;
	size_t i;

	const char *q = (pers && pers != pers_bsty_magic) ? "\"": "";
	printf("yespower(%u, %u, %s%s%s) = ", N, r,
	    q, pers ? pers : "NULL", q);

	for (i = 0; i < sizeof(src); i++)
		src[i] = i * 3;

	if (pers == pers_bsty_magic) {
		params.pers = src;
		params.perslen = sizeof(src);
	}

	if (yespower_tls(src, sizeof(src), &params, &dst)) {
		puts("FAILED");
		return;
	}

	for (i = 0; i < sizeof(dst); i++) {
		printf("%02x%c", dst.uc[i], i < sizeof(dst) - 1 ? ' ' : '\n');
	}
}

static void print_yespower_loop(const char *pers) {
	uint32_t N, r;
	uint8_t src[80];
	yespower_binary_t dst, xor = {{0}};
	size_t i;

	printf("XOR of yespower = ");

	/*
	 * This value of src is chosen to trigger duplicate index in the last
	 * SMix2 invocation in yespower 0.5 for N=2048 with at least one of the
	 * values of r below.  This is needed to test that a non-save version
	 * of BlockMix is used in that special case.  Most other values of src
	 * would leave this untested.
	 */
	src[0] = 43;
	for (i = 1; i < sizeof(src); i++)
		src[i] = i * 3;

	for (N = 1024; N <= 4096; N <<= 1) {
		for (r = 8; r <= 32; r++) {
			yespower_params_t params = {
				.N = N,
				.r = r,
				.pers = (const uint8_t *)pers,
				.perslen = pers ? strlen(pers) : 0
			};
			if (yespower_tls(src, sizeof(src), &params, &dst)) {
				puts("FAILED");
				return;
			}
			for (i = 0; i < sizeof(xor); i++) {
				xor.uc[i] ^= dst.uc[i];
			}
		}
	}

	for (i = 0; i < sizeof(xor); i++) {
		printf("%02x%c", xor.uc[i], i < sizeof(xor) - 1 ? ' ' : '\n');
	}
}

int main(void) {
	setvbuf(stdout, NULL, _IOLBF, 0);

#ifdef TEST_PBKDF2_SHA1
	print_PBKDF2_SHA1("password", "salt", 1, 20);
	print_PBKDF2_SHA1("password", "salt", 2, 20);
	print_PBKDF2_SHA1("password", "salt", 4096, 20);
	print_PBKDF2_SHA1("password", "salt", 65536, 20);
	print_PBKDF2_SHA1("passwordPASSWORDpassword",
	    "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25);
	print_PBKDF2_SHA1_raw("pass\0word", 9, "sa\0lt", 5, 4096, 16);
	printf("\n");
#endif

	print_yespower(2048, 8, NULL);
	print_yespower(4096, 16, NULL);
	print_yespower(4096, 32, NULL);
	print_yespower(2048, 32, NULL);
	print_yespower(1024, 32, NULL);
	print_yespower(1024, 32, "personality test");

	print_yespower_loop(NULL);

	return 0;
}
