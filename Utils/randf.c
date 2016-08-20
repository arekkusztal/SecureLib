/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Arek Kusztal. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in
 *	   the documentation and/or other materials provided with the
 *	   distribution.
 *	 * Neither the name of SecureLib Project nor the names of its
 *	   contributors may be used to endorse or promote products derived
 *	   from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */




#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <asm/errno.h>

void hex_dump(const char *def, uint8_t *data, uint16_t len,
		uint16_t br);

#define GLOBAL_CONFIG_URANDOM

/* In linux since 1.3.30, i was playing football then... */
#ifdef GLOBAL_CONFIG_URANDOM
/* Some say cryptographically secure
   but only few knows it for sure... :)
   Not-blocking */
#define RANDOM "/dev/urandom"
#elif GLOBAL_CONFIG_URANDOM
/* Until deplate is whats we need, but may block...*/
#define RANDOM "/dev/random"
#endif

/* x86 Ivy Bridge, Broadwell */
/* RDRAND from Ivy Bridge RDSEED from Broadwell */

/* Power7+ */
/* pseries-rng gives us dev/hwrng */

static inline int
get_urandf(uint8_t *r, uint16_t size)
{
	int sd;
	uint16_t rd;

	rd = 0;
	sd = open(RANDOM, O_RDONLY);
	if (sd < 0) {
		/* Error reading urandom */
		return -ENOENT;
	}

	while (rd < size) {
		uint16_t res = read(sd, r + rd, size - rd);
		if (res < 0) {
			return -EFAULT;
		}
		rd += res;
	}

	close(sd);
	return 0;
}

int
get_randf(uint8_t *p, uint16_t sz)
{
	return get_urandf(p, sz);
}

int main()
{
	uint8_t *p;

#define SZ 28
	p = malloc(SZ);

	memset(p, 0, SZ);

	get_randf(p, SZ);

	hex_dump("Random", p, SZ, 8);

	free(p);

	return 0;
}



void hex_dump(const char *def, uint8_t *data, uint16_t len,
		uint16_t br)
{
	uint16_t i;

	printf("\n%s:\n", def);
	for (i = 0; i < len; ++i) {
		if (i && ( i % br ==0 ))
			printf("\n");
		printf("0x%02X ",data[i]);
	}
	printf("\n");
}
