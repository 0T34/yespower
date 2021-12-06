#ifndef _SHA1_H_
#define _SHA1_H_

#include <stdint.h>

/* Public API for Steve Reid's public domain SHA-1 implementation */
/* This file is in the public domain */

/** SHA-1 Digest size in bytes */
#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCKSIZE   64

/** SHA-1 Context */
typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} SHA1_CTX;

/** HMAC SHA-1 Context */
typedef struct {
	SHA1_CTX ictx;
	SHA1_CTX octx;
} HMAC_SHA1_CTX;

void SHA1_Init(SHA1_CTX *ctx);
void SHA1_Update(SHA1_CTX *ctx, const void *p, size_t len);
void SHA1_Final(uint8_t d[SHA1_DIGEST_SIZE], SHA1_CTX *ctx);
void SHA1_Buf(const void *in, size_t len, uint8_t d[SHA1_DIGEST_SIZE]);

void HMAC_SHA1_Init(HMAC_SHA1_CTX *ctx, const void *_k, size_t len);
void HMAC_SHA1_Update(HMAC_SHA1_CTX *ctx, const void *p, size_t len);
void HMAC_SHA1_Final(uint8_t d[SHA1_DIGEST_SIZE], HMAC_SHA1_CTX *ctx);
void HMAC_SHA1_Buf(const void *k, size_t klen, const void *in, size_t inlen,
                   uint8_t d[SHA1_DIGEST_SIZE]);

void PBKDF2_SHA1(const uint8_t *passwd, size_t passwdlen, const uint8_t *salt,
                 size_t saltlen, uint64_t count, uint8_t *buf, size_t dkLen);

#endif /* !_SHA1_H_ */
