/*
 * ecs_genkey.c
 *
 *  Created on: Nov 12, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"


/** Creates a new ec private (and optional a new public) key.
 *  \param  key  EC_KEY object
 *  \param 	genpub	0 generate private key; 1 generate public key
 *  \return 1 on success and 0 if an error occurred.
 */
int ec_key_generate_key(ec_key eckey, int genpub){
	int ok = 0;

	if (!eckey || !eckey->group) {
		fprintf(stdout, "EC_F_EC_KEY_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER");
		return (ok);
	}

	mpz_t priv_key;
	mpz_init(priv_key);

	if (genpub == 0) { // Generate the private key
		mpz_t c, tmp, order;
		mpz_init(c); mpz_init(tmp); mpz_init(order);
		ec_group_get_order(eckey->group, order);
		gmp_randstate_t state;
		gmp_randinit_mt(state);

		int N = mpz_sizeinbase(order, 2);	/* Get the size in bits of the order of the group of points */

		/** Get a random private key
		 * 	Key Pair Generation Using Extra Random Bits
		 * 	http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
		 */

		N += 64;	/* 	64 more bits are requested from the RBG than are needed for d so that bias
						produced by the mod function is negligible. */

		/** Return private key priv_key
		 *	c = random(0, 2^N - 1)
		 * 	priv_key = (c mod (order – 1)) + 1
		 */
		mpz_urandomb(c, state, N); 	// c \in [0, 2^N - 1] //mpz_urandomm(priv_key, state, order);
		mpz_sub_ui(tmp, order, 1);	// tmp = order - 1
		mpz_mod(c, c, tmp);			// c = c mod tmp
		mpz_add_ui(priv_key, c, 1);	// priv_key = c + 1

		mpz_set(eckey->priv_key, priv_key);
		mpz_clear(c); mpz_clear(tmp); mpz_clear(order);

	} else { // Given private key, generate the public key
		ec_group group = ec_key_get_group(eckey);
		mpz_set(priv_key, eckey->priv_key);
		ec_point pub_key = ecp_mul_atomic(group->generator, priv_key, group);

		//Print compressed public key
		char* pub_str = ec_point_compress(pub_key);
		fprintf(stdout, "Compressed public key is : %s\n", pub_str);
		ec_point_cpy(eckey->pub_key, pub_key);

		ec_point_free(pub_key);
		free(pub_str);
	}

	ok = 1;

	mpz_clear(priv_key);
	/* testing whether the pub_key is on the elliptic curve */
	/*
	if (!ec_point_is_on_curve(eckey->pub_key, eckey->group)) {
		fprintf(stdout, "Public key validation. Q is NOT_ON_CURVE \n");
		return (ok);
	} else
		fprintf(stdout, "pub_key is on the curve, well generated !\n");
	 */

	return (ok);
}


/** Creates a table of pre-computed multiples of the generator to
 *  accelerate further EC_KEY operations.
 *  \param  key  EC_KEY object
 *  \return 1 on success and 0 if an error occurred.
 */
int ec_key_precompute_mult(ec_key key) {

	return 1;
}
