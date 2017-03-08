/*
 * hash_functions.h
 *
 *  Created on: Aug 18, 2015
 *      Author: tslld
 */

#ifndef HASH_FUNCTIONS_H_
#define HASH_FUNCTIONS_H_

/*** SHA1 Various Length Definitions ***********************/
#define SHA1_BLOCK_LENGTH		( 512 / 8) 	// 64 bytes
#define SHA1_DIGEST_LENGTH		( 160 / 8) 	// 20 bytes
#define SHA1_DIGEST_STRING_LENGTH	(SHA1_DIGEST_LENGTH * 2 + 1)

/*** SHA-224/256/384/512 Various Length Definitions ***********************/
#define SHA224_BLOCK_LENGTH		( 512 / 8) 	// 64 bytes
#define SHA256_BLOCK_LENGTH		SHA224_BLOCK_LENGTH
#define SHA512_BLOCK_LENGTH		( 1024 / 8)	// 128 bytes
#define SHA384_BLOCK_LENGTH		SHA512_BLOCK_LENGTH

#define SHA224_DIGEST_LENGTH	( 224 / 8) 	// 28 bytes
#define SHA256_DIGEST_LENGTH	( 256 / 8) 	// 32 bytes
#define SHA384_DIGEST_LENGTH	( 384 / 8) 	// 48 bytes
#define SHA512_DIGEST_LENGTH	( 512 / 8) 	// 64 bytes

#define SHA224_DIGEST_STRING_LENGTH	(SHA224_DIGEST_LENGTH * 2 + 1)
#define SHA256_DIGEST_STRING_LENGTH	(SHA256_DIGEST_LENGTH * 2 + 1)
#define SHA384_DIGEST_STRING_LENGTH	(SHA384_DIGEST_LENGTH * 2 + 1)
#define SHA512_DIGEST_STRING_LENGTH	(SHA512_DIGEST_LENGTH * 2 + 1)

typedef struct {
   uchar data[SHA1_BLOCK_LENGTH];
   uint datalen;
   uint bitlen[2];
   uint state[5];
} SHA1_Context;

typedef struct {
   uchar data[SHA256_BLOCK_LENGTH];
   uint datalen;
   uint bitlen[2];
   uint state[8];
} SHA256_Context;

typedef SHA256_Context SHA224_Context;

typedef struct {
	uchar data[SHA512_BLOCK_LENGTH];
	uint datalen;
	uint64 bitlen[2];
	uint64 state[8];
} SHA512_Context;

typedef SHA512_Context SHA384_Context;

#define SHA1_CS(a,b) (((b) << (a)) | ((b) >> (32-(a))))

#define SHA256_F1(x) (ROTR32(x,2) ^ ROTR32(x,13) ^ ROTR32(x,22))
#define SHA256_F2(x) (ROTR32(x,6) ^ ROTR32(x,11) ^ ROTR32(x,25))
#define SHA256_F3(x) (ROTR32(x,7) ^ ROTR32(x,18) ^ SHFR(x, 3)) //((x) >> 3))
#define SHA256_F4(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ SHFR(x, 10)) //((x) >> 10))

#define SHA512_F1(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define SHA512_F2(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SHA512_F3(x) (ROTR64(x,  1) ^ ROTR64(x,  8) ^ SHFR(x,  7))
#define SHA512_F4(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ SHFR(x,  6))

/** Macro DBL_INT_ADD treats two unsigned integers a and b as one 64-bit integer (b, a) and adds c to it
 * 	Used in SHA256 transform
 * 	\param a, b, c	32-bit integers
 */
#ifndef DBL_INT_ADD
#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;
#endif

/** Macro DBL_INT_ADD treats two unsigned integers a and b as one 128-bit integer (b, a) and adds c to it
 * 	Used in SHA512 transform
 * 	\param a, b, c	64-bit integers
 */
#ifndef DBL_INT_ADD_128
#define DBL_INT_ADD_128(a,b,c) if (a > 0xffffffffffffffff - (c)) ++b; a += c;
#endif


/*
 * Macro for incrementally adding the unsigned 64-bit integer n to the unsigned
 * 128-bit integer (represented using a two-element array of 64-bit words)
 * Used in SHA512 transform
 * \param
 */
#ifndef ADD_INC_128
#define ADD_INC_128(w,n)	{ \
	(w)[0] += (uint64)(n); \
	if ((w)[0] < (n)) { \
		(w)[1]++; \
	} \
}
#endif


void sha1_init(SHA1_Context *ctx);
void sha1_update(SHA1_Context *ctx, uchar data[], uint len);
void sha1_final(SHA1_Context *ctx, uchar dgst[]);
void sha1_free(SHA1_Context *ctx);


void sha224_init(SHA224_Context *ctx);
void sha224_update(SHA224_Context *ctx, uchar data[], uint len);
void sha224_final(SHA224_Context *ctx, uchar dgst[]);
void sha224_free(SHA224_Context *ctx);

void sha256_init(SHA256_Context *ctx);
void sha256_update(SHA256_Context *ctx, uchar data[], uint len);
void sha256_final(SHA256_Context *ctx, uchar dgst[]);
void sha256_free(SHA256_Context *ctx);


void sha384_init(SHA384_Context *ctx);
void sha384_update(SHA384_Context *ctx, uchar data[], uint len);
void sha384_final(SHA384_Context *ctx, uchar dgst[]);
void sha384_free(SHA384_Context *ctx);

/* Given a message with arbitrary length, function SHA-1 hashes and returns a fixed digest of 160 bits */
char* sha1(const char* message);

/* Given a message with arbitrary length, function SHA2-224 hashes and returns a fixed digest of 256 bits */
char* sha224(const char* message);
char* get_dgst_224(const char* filename);

/* Given a message with arbitrary length, function SHA2-256 hashes and returns a fixed digest of 256 bits */
char* sha256(const char* message);
char* get_dgst_256(const char* filename);

/* Given a message with arbitrary length, function hashes and returns a fixed digest of 256 bits */
char* sha384(const char* message);
char* get_dgst_384(const char* filename);

#endif /* HASH_FUNCTIONS_H_ */
