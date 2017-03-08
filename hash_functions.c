/*
 * hash_functions.c
 *
 *  Created on: Sep 8, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "hash_functions.h"

static void sha1_transform(SHA1_Context *ctx, uchar data[]);
static void sha224_256_transform(SHA256_Context *ctx, uchar data[]);
static void sha384_512_transform(SHA512_Context *ctx);

/* Hash constant words K defined in SHA-1   */
const uint K160[] = {
		0x5A827999,
		0x6ED9EBA1,
		0x8F1BBCDC,
		0xCA62C1D6
};

/* Hash constant words K for SHA-224 and SHA-256: */
const uint K256[64] = {
   0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
   0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
   0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
   0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
   0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
   0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
   0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
   0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};


/* Hash constant words K for SHA-384 and SHA-512: */
const uint64 K512[80] = {
	0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
	0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
	0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
	0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
	0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
	0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
	0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
	0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
	0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
	0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
	0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
	0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
	0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
	0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817
};

/** Process the next 512 bits of the message stored in the data array.
 *	\param ctx	pointer to the structure SHA1_Context
 *	\param data	data array
 */
static void sha1_transform(SHA1_Context *ctx, uchar data[]) {

    int i;  	             /* Loop counter                */
    uint temp;               /* Temporary word value        */
    uint W[80];         	 /* Word sequence               */
    uint wv[5];			     /* Word buffers                */

    /*
     *  Initialize the first 16 words in the array W
     */
    for(i = 0; i < 16; i++) {
        W[i] = data[i * 4] << 24;
        W[i] |= data[i * 4 + 1] << 16;
        W[i] |= data[i * 4 + 2] << 8;
        W[i] |= data[i * 4 + 3];
    }

    for(i = 16; i < 80; i++) {
       W[i] = SHA1_CS(1,W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]);
    }

    for (i = 0; i < 5; i++) {
    	wv[i] = ctx->state[i];
    }

    for(i = 0; i < 20; i++) {
        temp =  SHA1_CS(5,wv[0]) + ((wv[1] & wv[2]) | ((~wv[1]) & wv[3])) + wv[4] + W[i] + K160[0];
        wv[4] = wv[3];
        wv[3] = wv[2];
        wv[2] = SHA1_CS(30,wv[1]);
        wv[1] = wv[0];
        wv[0] = temp;
    }

    for(i = 20; i < 40; i++) {
    	temp = SHA1_CS(5,wv[0]) + (wv[1] ^ wv[2] ^ wv[3]) + wv[4] + W[i] + K160[1];
    	wv[4] = wv[3];
    	wv[3] = wv[2];
    	wv[2] = SHA1_CS(30,wv[1]);
    	wv[1] = wv[0];
    	wv[0] = temp;
    }

    for(i = 40; i < 60; i++) {
        temp = SHA1_CS(5,wv[0]) + ((wv[1] & wv[2]) | (wv[1] & wv[3]) | (wv[2] & wv[3])) + wv[4] + W[i] + K160[2];
        wv[4] = wv[3];
        wv[3] = wv[2];
        wv[2] = SHA1_CS(30,wv[1]);
        wv[1] = wv[0];
        wv[0] = temp;
    }

    for(i = 60; i < 80; i++)    {
    	temp = SHA1_CS(5,wv[0]) + (wv[1] ^ wv[2] ^ wv[3]) + wv[4] + W[i] + K160[3];
    	wv[4] = wv[3];
    	wv[3] = wv[2];
    	wv[2] = SHA1_CS(30,wv[1]);
    	wv[1] = wv[0];
    	wv[0] = temp;
    }

    for (i = 0; i < 5; i++) {
    	ctx->state[i] += wv[i];
    }

}


static void sha224_256_transform(SHA256_Context *ctx, uchar data[]) {
	uint i, j, t1, t2, m[64];
	uint wv[8];

	for (i=0,j=0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
	for ( ; i < 64; ++i)
		m[i] = SHA256_F4(m[i-2]) + m[i-7] + SHA256_F3(m[i-15]) + m[i-16];

	for (j = 0; j < 8; j++) {
		wv[j] = ctx->state[j];
	}

	for (i = 0; i < 64; ++i) {
		t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4],wv[5],wv[6]) + K256[i] + m[i];
		t2 = SHA256_F1(wv[0]) + MAJ(wv[0],wv[1],wv[2]);
		wv[7] = wv[6];
		wv[6] = wv[5];
		wv[5] = wv[4];
		wv[4] = wv[3] + t1;
		wv[3] = wv[2];
		wv[2] = wv[1];
		wv[1] = wv[0];
		wv[0] = t1 + t2;
	}

	for (j = 0; j < 8; j++) {
		ctx->state[j] += wv[j];
	}
}

static void sha384_512_transform(SHA512_Context *ctx){

	uint i, j;
	uint64 t1, t2, m[80];
	uint64 wv[8];

	for (i = 0, j = 0; i < 16; ++i, j += 8)
		m[i] = ((uint64) (ctx->data[j]) << 56) |
				((uint64) (ctx->data[j+1]) << 48) |
				((uint64) (ctx->data[j+2]) << 40) |
				((uint64) (ctx->data[j+3]) << 32) |
				((uint64) (ctx->data[j+4]) << 24) |
				((uint64) (ctx->data[j+5]) << 16) |
				((uint64) (ctx->data[j+6]) << 8) |
				((uint64) (ctx->data[j+7]));

	for ( ; i < 80; ++i)
		m[i] = SHA512_F4(m[i-2]) + m[i-7] + SHA512_F3(m[i-15]) + m[i-16];

	for (j = 0; j < 8; j++) {
		wv[j] = ctx->state[j];
	}

	for (i = 0; i < 80; ++i) {
		t1 = wv[7] + SHA512_F2(wv[4]) + CH(wv[4],wv[5],wv[6]) + K512[i] + m[i];
		t2 = SHA512_F1(wv[0]) + MAJ(wv[0],wv[1],wv[2]);
		wv[7] = wv[6];
		wv[6] = wv[5];
		wv[5] = wv[4];
		wv[4] = wv[3] + t1;
		wv[3] = wv[2];
		wv[2] = wv[1];
		wv[1] = wv[0];
		wv[0] = t1 + t2;
	}

	for (j = 0; j < 8; j++) {
		ctx->state[j] += wv[j];
	}
}


/**
 *
 */
void sha1_init(SHA1_Context *ctx) {
    ctx->datalen = 0;
    ctx->bitlen[0] = 0;
    ctx->bitlen[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

/**
 *
 */
void sha224_init(SHA256_Context *ctx) {
	ctx->datalen = 0;
	ctx->bitlen[0] = 0;
	ctx->bitlen[1] = 0;
	ctx->state[0] = 0xC1059ED8;
	ctx->state[1] = 0x367CD507;
	ctx->state[2] = 0x3070DD17;
	ctx->state[3] = 0xF70E5939;
	ctx->state[4] = 0xFFC00B31;
	ctx->state[5] = 0x68581511;
	ctx->state[6] = 0x64F98FA7;
	ctx->state[7] = 0xBEFA4FA4;
}

/*
 *
 *  Description: This function will initialize the SHA256 Context to generate a new SHA256 message digest.
 *
 *  Input: a context ctx
 *
 */

void sha256_init(SHA256_Context *ctx) {
   ctx->datalen = 0;
   ctx->bitlen[0] = 0;
   ctx->bitlen[1] = 0;
   ctx->state[0] = 0x6a09e667;
   ctx->state[1] = 0xbb67ae85;
   ctx->state[2] = 0x3c6ef372;
   ctx->state[3] = 0xa54ff53a;
   ctx->state[4] = 0x510e527f;
   ctx->state[5] = 0x9b05688c;
   ctx->state[6] = 0x1f83d9ab;
   ctx->state[7] = 0x5be0cd19;
}


/* Initial hash value H for SHA-384 */
void sha384_init(SHA384_Context *ctx){
	ctx->datalen = 0;
	ctx->bitlen[0] = 0;
	ctx->bitlen[1] = 0;
	ctx->state[0] = 0xcbbb9d5dc1059ed8;
	ctx->state[1] = 0x629a292a367cd507;
	ctx->state[2] = 0x9159015a3070dd17;
	ctx->state[3] = 0x152fecd8f70e5939;
	ctx->state[4] = 0x67332667ffc00b31;
	ctx->state[5] = 0x8eb44a8768581511;
	ctx->state[6] = 0xdb0c2e0d64f98fa7;
	ctx->state[7] = 0x47b5481dbefa4fa4;
}


/**
 *
 */
void sha1_update(SHA1_Context *ctx, uchar data[], uint len){

	int i;
	for (i=0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;

		ctx->bitlen[0] += 8;
		if (ctx->bitlen[0] == 0)
			ctx->bitlen[1]++;

		if (ctx->datalen == SHA1_BLOCK_LENGTH)	{
			sha1_transform(ctx, ctx->data);
		}
	}
}

/**
 *
 */
void sha224_update(SHA224_Context *ctx, uchar data[], uint len){
	sha256_update(ctx, data, len);
}


/*
 * Description: This function will update
 *
 * Input: context ctx
 *
 *
 */
void sha256_update(SHA256_Context *ctx, uchar data[], uint len){

   uint i;

   for (i=0; i < len; ++i) {
      ctx->data[ctx->datalen] = data[i];
      ctx->datalen++;
      if (ctx->datalen == SHA256_BLOCK_LENGTH) {
         sha224_256_transform(ctx,ctx->data);
         DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1], SHA256_BLOCK_LENGTH << 3); //512);
         ctx->datalen = 0;
      }
   }
}



void sha384_update(SHA384_Context *ctx, uchar data[], uint len){

	uint i;
	for (i=0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == SHA512_BLOCK_LENGTH) {
			DBL_INT_ADD_128(ctx->bitlen[0], ctx->bitlen[1], SHA512_BLOCK_LENGTH << 3);
			sha384_512_transform(ctx);
			ctx->datalen = 0;
		}
	}
}



/**
 *
 */
void sha1_final(SHA1_Context *ctx, uchar dgst[]) {
    uint i = ctx->datalen;

    // Pad whatever data is left in the buffer.
    if (ctx->datalen >= SHA1_BLOCK_LENGTH - 8) {
    	ctx->data[i++] = 0x80;
         while(i < SHA1_BLOCK_LENGTH)
        	 ctx->data[i++] = 0x00;
         sha1_transform(ctx, ctx->data);
         memset(ctx->data, 0, SHA1_BLOCK_LENGTH - 8);
     } else {
    	 ctx->data[i++] = 0x80;
         while(i < SHA1_BLOCK_LENGTH - 8)
        	 ctx->data[i++] = 0x00;
     }


    /** Append to the padding the total message's length in bits and transform.
     *  Store the message length as the last 8 octets
     */
    ctx->data[56] = ctx->bitlen[1] >> 24;
    ctx->data[57] = ctx->bitlen[1] >> 16;
    ctx->data[58] = ctx->bitlen[1] >> 8;
    ctx->data[59] = ctx->bitlen[1];
    ctx->data[60] = ctx->bitlen[0] >> 24;
    ctx->data[61] = ctx->bitlen[0] >> 16;
    ctx->data[62] = ctx->bitlen[0] >> 8;
    ctx->data[63] = ctx->bitlen[0];

    sha1_transform(ctx, ctx->data);

    for (i=0; i < 4; ++i) {
    	dgst[i]    = (ctx->state[0] >> (24-i*8)) & 0x000000ff;
    	dgst[i+4]  = (ctx->state[1] >> (24-i*8)) & 0x000000ff;
    	dgst[i+8]  = (ctx->state[2] >> (24-i*8)) & 0x000000ff;
    	dgst[i+12] = (ctx->state[3] >> (24-i*8)) & 0x000000ff;
    	dgst[i+16] = (ctx->state[4] >> (24-i*8)) & 0x000000ff;
    }
    /*
    for(i = 0; i < SHA1_DIGEST_LENGTH; ++i) {
        dgst[i] = ctx->state[i>>2] >> 8 * ( 3 - ( i & 0x03 ) );
    }*/
}
/**
 * 	\param
 * 	\param
 *
 */
void sha224_final(SHA224_Context *ctx, uchar dgst[]) {
	sha256_final(ctx, dgst);
}

/**
 *
 *
 */
void sha256_final(SHA256_Context *ctx, uchar dgst[]) {
	uint i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < SHA256_BLOCK_LENGTH - 8) {
		ctx->data[i++] = 0x80;
		while (i < SHA256_BLOCK_LENGTH - 8)
			ctx->data[i++] = 0x00;
	} else {
		ctx->data[i++] = 0x80;
		while (i < SHA256_BLOCK_LENGTH)
			ctx->data[i++] = 0x00;
		sha224_256_transform(ctx,ctx->data);
		memset(ctx->data, 0, SHA256_BLOCK_LENGTH - 8);
	}

	// Append to the padding the total message's length in bits and transform.
	DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen << 3);
	ctx->data[63] = ctx->bitlen[0];
	ctx->data[62] = ctx->bitlen[0] >> 8;
	ctx->data[61] = ctx->bitlen[0] >> 16;
	ctx->data[60] = ctx->bitlen[0] >> 24;
	ctx->data[59] = ctx->bitlen[1];
	ctx->data[58] = ctx->bitlen[1] >> 8;
	ctx->data[57] = ctx->bitlen[1] >> 16;
	ctx->data[56] = ctx->bitlen[1] >> 24;
	sha224_256_transform(ctx,ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	// Result

	for (i=0; i < 4; ++i) {
		dgst[i]    = (ctx->state[0] >> (24-i*8)) & 0x000000ff;
		dgst[i+4]  = (ctx->state[1] >> (24-i*8)) & 0x000000ff;
		dgst[i+8]  = (ctx->state[2] >> (24-i*8)) & 0x000000ff;
		dgst[i+12] = (ctx->state[3] >> (24-i*8)) & 0x000000ff;
		dgst[i+16] = (ctx->state[4] >> (24-i*8)) & 0x000000ff;
		dgst[i+20] = (ctx->state[5] >> (24-i*8)) & 0x000000ff;
		dgst[i+24] = (ctx->state[6] >> (24-i*8)) & 0x000000ff;
		dgst[i+28] = (ctx->state[7] >> (24-i*8)) & 0x000000ff;
	}
	/*
	for(i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		dgst[i] = ctx->state[i>>2] >> 8 * ( 3 - ( i & 0x03 ) );
	}*/


}


void sha384_final(SHA384_Context *ctx, uchar dgst[]){

	/* Sanity check: */
	assert(ctx != (SHA384_Context*)0);

	uint i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < (SHA512_BLOCK_LENGTH - 16)) {
		ctx->data[i++] = 0x80;
		while (i < (SHA512_BLOCK_LENGTH - 16))
			ctx->data[i++] = 0x00;
	} else {
		ctx->data[i++] = 0x80;
		while (i < SHA512_BLOCK_LENGTH)
			ctx->data[i++] = 0x00;
			sha384_512_transform(ctx);
	}

	/*
	 * 	Store the message length as the last 16 octets
	 * 	Append to the padding the total message's length in bits and transform.
	 */
	DBL_INT_ADD_128(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen << 3);
	ctx->data[112] = ctx->bitlen[1] >> 56;
	ctx->data[113] = ctx->bitlen[1] >> 48;
	ctx->data[114] = ctx->bitlen[1] >> 40;
	ctx->data[115] = ctx->bitlen[1] >> 32;
	ctx->data[116] = ctx->bitlen[1] >> 24;
	ctx->data[117] = ctx->bitlen[1] >> 16;
	ctx->data[118] = ctx->bitlen[1] >> 8;
	ctx->data[119] = ctx->bitlen[1];

	ctx->data[120] = ctx->bitlen[0] >> 56;
	ctx->data[121] = ctx->bitlen[0] >> 48;
	ctx->data[122] = ctx->bitlen[0] >> 40;
	ctx->data[123] = ctx->bitlen[0] >> 32;
	ctx->data[124] = ctx->bitlen[0] >> 24;
	ctx->data[125] = ctx->bitlen[0] >> 16;
	ctx->data[126] = ctx->bitlen[0] >> 8;
	ctx->data[127] = ctx->bitlen[0];

	sha384_512_transform(ctx);

	/** Since this implementation uses little endian byte ordering and SHA uses big endian,
	 * 	reverse all the bytes when copying the final state to the output hash.
	 */
	for (i=0; i < 8; ++i) {
		dgst[i]    = (ctx->state[0] >> (56-i*8)) & 0x000000ff;
		dgst[i+8]  = (ctx->state[1] >> (56-i*8)) & 0x000000ff;
		dgst[i+16] = (ctx->state[2] >> (56-i*8)) & 0x000000ff;
		dgst[i+24] = (ctx->state[3] >> (56-i*8)) & 0x000000ff;
		dgst[i+32] = (ctx->state[4] >> (56-i*8)) & 0x000000ff;
		dgst[i+40] = (ctx->state[5] >> (56-i*8)) & 0x000000ff;
		dgst[i+48] = (ctx->state[6] >> (56-i*8)) & 0x000000ff;
		dgst[i+56] = (ctx->state[7] >> (56-i*8)) & 0x000000ff;
	}
	/** or the following code
	 * 	giving the same result
	for(i = 0; i < SHA384_DIGEST_LENGTH; ++i) {
		dgst[i] = ctx->state[i>>3] >> 8 * ( 7 - ( i & 0x07 ) );
	}
	 *	or
    for (i = 0; i < SHA384_DIGEST_LENGTH; ++i)
    	dgst[i] = ctx->state[i >> 3] >> 8 * (7 - (i % 8));
	*/
}


/**	Release the pointer ctx of the structure SHA256_Context
 * 	\param ctx	pointer the the structure SHA256_Context
 */
void sha224_free(SHA224_Context *ctx){
	free(ctx);
}

void sha256_free(SHA256_Context *ctx){
	free(ctx);
}


void sha384_free(SHA384_Context *ctx){

	free(ctx);
}


/**	Compute the digest of a given message
 * 	\param msg	pointer to a array of characters
 *	\return 	hash digest of the message msg
 */
char* sha1(const char* msg){
	SHA1_Context ctx;
	uchar digest[SHA1_DIGEST_LENGTH];
	char* hash = malloc(SHA1_DIGEST_STRING_LENGTH);
	hash[SHA1_DIGEST_STRING_LENGTH] = '\0';
	int i;

	// Initialize sha context
	sha1_init(&ctx);

	sha1_update(&ctx, (uchar *) msg, strlen(msg));
	sha1_final(&ctx, digest);

	for(i = 0; i < SHA1_DIGEST_LENGTH ; ++i) {
		sprintf(hash +i*2, "%02x", digest[i]);
	}

	return hash;
}

/**	Returns hash as a string, must be released with free()
 * 	\param msg	pointer to a array of characters
 *	\return 	hash digest of the message msg
 */
char* sha224(const char* msg){
	SHA224_Context ctx;
	uchar digest[SHA224_DIGEST_LENGTH];
	char* hash = malloc(SHA224_DIGEST_STRING_LENGTH);
	hash[SHA224_DIGEST_STRING_LENGTH] = '\0';
	int i;

	// Initialize sha context
	sha224_init(&ctx);

	sha224_update(&ctx, (uchar *) msg, strlen(msg));
	sha224_final(&ctx, digest);

	for(i = 0; i < SHA224_DIGEST_LENGTH ; ++i) {
		sprintf(hash +i*2, "%02x", digest[i]);
	}

	return hash;
}

/**	Returns hash as a string, must be released with free()
 * 	\param msg	pointer to a array of characters
 *	\return 	hash digest of the message msg
 */
char* sha256(const char* msg){
	SHA256_Context ctx;
	uchar digest[SHA256_DIGEST_LENGTH];
	char* hash = malloc(SHA256_DIGEST_STRING_LENGTH);
	hash[SHA256_DIGEST_STRING_LENGTH] = '\0';
	int i;

	// Initialize sha context
	sha256_init(&ctx);

	sha256_update(&ctx, (uchar *) msg, strlen(msg));
	sha256_final(&ctx, digest);

	for(i = 0; i < SHA256_DIGEST_LENGTH ; ++i) {
		sprintf(hash +i*2, "%02x", digest[i]);
	}

	return hash;
}



/**	Returns hash as a string, must be released with free()
 * 	\param msg	pointer to a array of characters
 *	\return 	hash digest of the message msg
 */
char* sha384(const char* msg){
	SHA384_Context ctx;
	uchar digest[SHA384_DIGEST_LENGTH];
	char* hash = malloc(SHA384_DIGEST_STRING_LENGTH);
	hash[SHA384_DIGEST_STRING_LENGTH] = '\0';
	int i;

	// Initialize sha context
	sha384_init(&ctx);

	sha384_update(&ctx, (uchar *) msg, strlen(msg));
	sha384_final(&ctx, digest);

	for(i = 0; i < SHA384_DIGEST_LENGTH ; ++i) {
		sprintf(hash +i*2, "%02x", digest[i]);
	}

	return hash;
}


