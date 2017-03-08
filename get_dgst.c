/*
 * get_dgst.c
 *
 *  Created on: Nov 19, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "hash_functions.h"

/**	Given a file. Function hashes and returns a string
 * 	\param 	in_fname		name of the input file
 *	\return hash digest of the file in_fname
 */
char* get_dgst_224(const char* in_fname) {

	char *hash = malloc(SHA224_DIGEST_STRING_LENGTH);
	hash[SHA224_DIGEST_STRING_LENGTH] = '\0';
	FILE *msg_fp = NULL;
	SHA224_Context ctx;
	uchar buf[1000];
	uchar sha224sum[SHA224_DIGEST_LENGTH];
	int i;

	if (!(msg_fp = fopen( in_fname, "rb"))) {
		hash = sha224(in_fname);
	} else {
		sha224_init( &ctx );

		while ((i = fread( buf, 1, sizeof(buf), msg_fp )) > 0) {
			sha224_update(&ctx, buf, i);
		}

		sha224_final(&ctx, sha224sum);

		for(i = 0; i < SHA224_DIGEST_LENGTH ; ++i) {
			sprintf(hash +i*2, "%02x", sha224sum[i]);
		}
	}

	return hash;

}

char* get_dgst_256(const char* msg) {

	int i;
	SHA256_Context ctx;
	uchar buf[1000];
	uchar sha256sum[SHA256_DIGEST_LENGTH];
	char* hash = malloc(SHA256_DIGEST_STRING_LENGTH);
	hash[SHA256_DIGEST_STRING_LENGTH] = '\0';
	FILE *msg_fp = NULL;

	if (!(msg_fp = fopen( msg, "rb"))) {
		hash = sha256(msg);
	} else {
		sha256_init( &ctx );

		while ((i = fread( buf, 1, sizeof(buf), msg_fp )) > 0) {
			sha256_update(&ctx, buf, i);
		}

		sha256_final(&ctx, sha256sum);

		for(i = 0; i < SHA256_DIGEST_LENGTH ; ++i) {
			sprintf(hash +i*2, "%02x", sha256sum[i]);
		}
	}

	return hash;

}

char* get_dgst_384(const char* msg) {

	int i;
	SHA384_Context ctx;
	uchar buf[1000];
	uchar sha384sum[SHA384_DIGEST_LENGTH];
	char* hash = malloc(SHA384_DIGEST_STRING_LENGTH);
	hash[SHA384_DIGEST_STRING_LENGTH] = '\0';
	FILE *msg_fp = NULL;

	if (!(msg_fp = fopen( msg, "rb"))) {
		hash = sha384(msg);
	} else {
		sha384_init( &ctx );

		while ((i = fread( buf, 1, sizeof(buf), msg_fp )) > 0) {
			sha384_update(&ctx, buf, i);
		}

		sha384_final(&ctx, sha384sum);

		for(i = 0; i < SHA384_DIGEST_LENGTH ; ++i) {
			sprintf(hash +i*2, "%02x", sha384sum[i]);
		}
	}

	return hash;

}
