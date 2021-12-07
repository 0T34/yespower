/*
 * HEFTY1 cryptographic hash function
 *
 * Copyright (c) 2014, dbcc14 <BM-NBx4AKznJuyem3dArgVY8MGyABpihRy5>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of the FreeBSD Project.
 */

#ifndef __HEFTY1_H__
#define __HEFTY1_H__

#include <stdint.h>

#define HEFTY1_DIGEST_BYTES 32
#define HEFTY1_BLOCK_BYTES 64
#define HEFTY1_STATE_WORDS 8
#define HEFTY1_SPONGE_WORDS 4

typedef struct HEFTY1_CTX {
    uint32_t h[HEFTY1_STATE_WORDS];
    uint8_t  block[HEFTY1_BLOCK_BYTES];
    uint64_t written;
    uint32_t sponge[HEFTY1_SPONGE_WORDS];
} HEFTY1_CTX;

void HEFTY1_Init(HEFTY1_CTX *ctx);
void HEFTY1_Update(HEFTY1_CTX *ctx, const void *data, size_t len);
void HEFTY1_Final(uint8_t d[HEFTY1_DIGEST_BYTES], HEFTY1_CTX *ctx);
void HEFTY1_Buf(const void *in, size_t len, uint8_t d[HEFTY1_DIGEST_BYTES]);

#endif /* __HEFTY1_H__ */
