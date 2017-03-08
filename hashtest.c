/*
 * hftest.c
 *
 *  Created on: Oct 14, 2015
 *      Author: tslld
 */

#include"ecdsa.h"
#include"hash_functions.h"

/*
 * Testing SHA1, SHA2, the following msgs, vals are the standard FIPS-180-2 test vectors
 * http://csrc.nist.gov/groups/ST/toolkit/examples.html
 * http://www.di-mgt.com.au/sha_testvectors.html
 *
 */

static char *msg[] = {
		"",
		"abc",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
};

static char *sha160_val[] = {
		"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"a9993e364706816aba3e25717850c26c9cd0d89d",
		"84983e441c3bd26ebaae4aa1f95129e5e54670f1"
};

static char *sha224_val[] = {
		"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
		"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
		"75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
};

static char *sha256_val[] = {
		"e3b0c44298fc1c149afbf4c8996fb924" \
		"27ae41e4649b934ca495991b7852b855",
		"ba7816bf8f01cfea414140de5dae2223" \
		"b00361a396177a9cb410ff61f20015ad",
		"248d6a61d20638b8e5c026930c3e6039" \
		"a33ce45964ff2167f6ecedd419db06c1"
};

static char *sha384_val[] = {
		"38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743" \
		"4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
		"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163" \
		"1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
		"3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05ab" \
		"fe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"
};
/*
static char *sha512_val[] = {
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" \
		"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" \
		"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		"204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335" \
		"96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
};*/

int main(int argc, char* argv[]) {
    FILE *fp;
    int i, j;
    SHA256_Context ctx;
    uchar buf[1000];
    uchar sha256sum[32];

    char *output160 = malloc(SHA1_DIGEST_STRING_LENGTH);
    output160[SHA1_DIGEST_STRING_LENGTH] = '\0';
    char *output224 = malloc(SHA224_DIGEST_STRING_LENGTH);
    output224[SHA224_DIGEST_STRING_LENGTH] = '\0';
    char *output256 = malloc(SHA256_DIGEST_STRING_LENGTH);
    output256[SHA256_DIGEST_STRING_LENGTH] = '\0';
    char *output384 = malloc(SHA384_DIGEST_STRING_LENGTH);
    output384[SHA256_DIGEST_STRING_LENGTH] = '\0';


    if( argc < 2 ) {
        fprintf(stdout, "\nSHA-1 Validation Tests:\n\n" );

        for( i = 0; i < 3; i++ ) {
        	printf( "Test %d ", i + 1 );

        	output160 = sha1(msg[i]);

        	if( memcmp(output160, sha160_val[i], SHA1_DIGEST_STRING_LENGTH - 1) ) {
        		fprintf(stdout, "failed!\n" );
        		return( 1 );
        	}
        	fprintf(stdout, "Digest is %s \n", output160);
        	fprintf(stdout, "passed.\n" );
        }

        fprintf(stdout, "\nSHA-224 Validation Tests:\n\n" );

        for( i = 0; i < 3; i++ ) {
        	printf( "Test %d ", i + 1 );

        	output224 = sha224(msg[i]);

        	if( memcmp(output224, sha224_val[i], SHA224_DIGEST_STRING_LENGTH - 1) ) {
        		fprintf(stdout, "failed!\n" );
        		return( 1 );
        	}
        	fprintf(stdout, "Digest is %s \n", output224);
        	fprintf(stdout, "passed.\n" );
        }

        fprintf(stdout, "\nSHA-256 Validation Tests:\n\n" );
        for( i = 0; i < 3; i++ ) {
        	printf( "Test %d ", i + 1 );

        	output256 = sha256(msg[i]);

        	if( memcmp( output256, sha256_val[i], SHA256_DIGEST_STRING_LENGTH - 1) ) {
        		fprintf(stdout, "failed!\n" );
        		return( 1 );
        	}
        	fprintf(stdout, "Digest is %s \n", output256);
        	fprintf(stdout, "passed.\n" );
        }

        fprintf(stdout, "\nSHA-384 Validation Tests:\n\n" );

        for( i = 0; i < 3; i++ ) {
        	printf( "Test %d ", i + 1 );

        	output384 = sha384(msg[i]);

        	if( memcmp(output384, sha384_val[i], SHA384_DIGEST_STRING_LENGTH - 1) ) {
        		fprintf(stdout, "failed!\n" );
        		return( 1 );
        	}
        	fprintf(stdout, "Digest is %s \n", output384);
        	fprintf(stdout, "passed.\n" );
        }


        fprintf(stdout, "\n\n" );

    } else  {
    	if( ! ( fp = fopen( argv[1], "rb" ) ) ) {
    		perror( "fopen" );
    		return( 1 );
    	}

    	sha256_init( &ctx );

    	while( ( i = fread( buf, 1, sizeof( buf ), fp ) ) > 0 ) {
            sha256_update( &ctx, buf, i );
        }

    	sha256_final( &ctx, sha256sum );

    	for( j = 0; j < 32; j++ ) {
            printf( "%02x", sha256sum[j] );
        }

        printf( "  %s\n", argv[1] );
    }

    free(output160);
    free(output224);
    free(output256);
    free(output384);

    return( 0 );
}

