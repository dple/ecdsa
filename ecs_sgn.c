/*
 * ecs_sign.c
 *
 *  Created on: Nov 2, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"
#include "field_ops.h"

/* This time-constant implementation returns a value 0x00 if x equal to 0, otherwise it returns 0xFF */
int iszero(mpz_t x) {
	srand(time(NULL));
	int randbit = rand() % 2;
	int mask = 0;
	if (!randbit)	// unpredictable
		mask = 0xF;
	else
		mask = 0xF0;

	if (mpz_sgn(x) == randbit)
		mask ^= 0xF;
	else
		mask ^= 0xF0;

	return mask;
}

/** Precompute parts of the signing operation
 *  \param  eckey  EC_KEY object containing a private EC key
 *  \param  kinv   mpz_t pointer for the inverse of k
 *  \param  rp     mpz_t pointer for x coordinate of k * generator
 *  \return 1 on success and 0 otherwise
 */
int ecdsa_sign_setup(const ec_key eckey, mpz_t kinv, mpz_t rp) {
	int ok = 0;

	mpz_t order, X, k, r;
	mpz_init(order); mpz_init(X); mpz_init(k); mpz_init(r);

	ec_group group;


	if (eckey == NULL || (group = ec_key_get_group(eckey)) == NULL) {
		fprintf(stdout, "ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_PASSED_NULL_PARAMETER");
		return 0;
	}


	ec_group_get_order(group, order);
	gmp_randstate_t state;
	gmp_randinit_mt(state);
	ec_point tmp_point;

	do {
		/* get random k */
		do
			mpz_urandomm(k, state, order);
		while (!mpz_sgn(k));	// until k <> 0

		/*
		 * We do not want timing information to leak the length of k, so we
		 * compute k*G using an equivalent scalar of fixed bit-length.
		 *
		 * k = k + order
		 */

		mpz_add(k, k, order);

		/* compute r the x-coordinate of k*G */
		tmp_point = ecp_mul_atomic(group->generator, k, group);

		mpz_mod(r, tmp_point->x, order);

	} while (!mpz_sgn(r)); // until r <> 0

	/* Compute the inverse of k
	 * We want inverse in constant time, therefore we utilize the fact
	 * order must be prime and use Fermats Little Theorem instead.
	 */
	if (!mod_invert(X, k, order)) {
		fprintf(stdout, "ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB");
		return 0;
	}

	/* save the pre-computed values  */
	mpz_set(rp, r);
	mpz_set(kinv, X);

	/* clear variables used */
	mpz_clear(order); mpz_clear(X); mpz_clear(k); mpz_clear(r);
	ec_point_free(tmp_point); //ec_group_free(group);

	ok = 1;

	return (ok);
}

/** Computes ECDSA signature of a given hash value using the supplied
 *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 *  \param  dgst     pointer to the hash value to sign
 *  \param  dgstlen  length of the hash value
 *  \param  kinv     big number with a pre-computed inverse k (optional)
 *  \param  rp       big number with a pre-computed rp value (optioanl),
 *                   see ECDSA_sign_setup
 *  \param  eckey    ec_key object containing a private EC key
 *  \return 1 on success and 0 otherwise
 */
ecdsa_sig ecdsa_sign(const char *dgst, int dgst_len, const mpz_t in_kinv, const mpz_t in_rp, const ec_key eckey) {

	if (eckey == NULL) {
		fprintf(stdout, "ECDSA_F_ECDSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER");
		return NULL;
	}

	mpz_t priv_key;
	mpz_init(priv_key);

	ec_key_get_private_key(priv_key, eckey);

	if (!mpz_sgn(priv_key)) {
		fprintf(stdout, "ECDSA_F_ECDSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER");
		mpz_clear(priv_key);
		return NULL;
	}

	ecdsa_sig ret = ecs_init();

	if (!ret) {
		fprintf(stdout, "ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE");
		return NULL;
	}

	mpz_t e, order;
	mpz_init(e); mpz_init(order);

	ec_group_get_order(eckey->group, order);

	// Convert message digest dgst to an integer e
	mpz_set_str(e, dgst, 16);

	/*
	printf("The length of message in bits is %d\n", n);
	printf("Value of bit string is: ");
	mpz_out_str(stdout, 16, m);
	printf("\n");*/

	assert(mpz_sizeinbase(e, 2) <= mpz_sizeinbase(order, 2));

	mpz_t kinv, s, tmp1, tmp2, ckinv;
	mpz_init(kinv); mpz_init(s); mpz_init(ckinv); mpz_init(tmp1); mpz_init(tmp2);

	//gmp_printf("Initiate s = %Zd, mpz_sgn(s) = %d", s, mpz_sgn(s));
	do {
		if (!mpz_sgn(in_kinv) || !mpz_sgn(in_rp)) {
			if (! ecdsa_sign_setup(eckey, kinv, ret->r)) {
				fprintf(stdout, "ECDSA_F_ECDSA_DO_SIGN, ERR_R_ECDSA_LIB");
				ecs_free(ret);
				return NULL;
			}
			mpz_set(ckinv, kinv);
		} else {
			mpz_set(ckinv, in_kinv);
			mpz_set(ret->r, in_rp);
		}

		/** Calculate s
		 * s = k^{-1} * (m + d * r) mod order = (k^{-1} mod n) * ((e+d*r) mod n) mod n
		 */
		mpz_mul(tmp1, priv_key, ret->r); 	// tmp1 = d * r

		mod_add(tmp2, e, tmp1, order);		// tmp2 = m + tmp1 mod order

		mod_mul(s, tmp2, ckinv, order);		// s = k^{-1} tmp2 mod order

		//gmp_printf("s = %Zd, mpz_sgn(s) = %d", s, mpz_sgn(s));

		if (mpz_sgn(s)) { 	/* s != 0 => we have a valid signature */
			mpz_set(ret->s, s);		// Set value of ret->s
			break;
		} else {
			/*
			 * if kinv and r have been supplied by the caller don't to
			 * generate new kinv and r values
			 */
			if ((mpz_sgn(in_kinv)) && (mpz_sgn(in_rp))) {
				fprintf(stdout, "ECDSA_F_ECDSA_DO_SIGN, ECDSA_R_NEED_NEW_SETUP_VALUES");
				break;
			}
		}
	}
	while (1);

	// Show e * s^{-1}
	/* mpz_t w, u1; mpz_init(w); mpz_init(u1);
	mpz_out_str(stdout, 16, order);
	mod_invert(w, s, order);
	mod_mul(u1, e, w, order);
	gmp_printf("e * s^{-1} = %Zd \n", u1);
	mpz_clear(w); mpz_clear(u1); */

	mpz_clear(priv_key); mpz_clear(e); mpz_clear(order);
	mpz_clear(tmp1); mpz_clear(tmp2);mpz_clear(s); mpz_clear(kinv); mpz_clear(ckinv);

	return ret;

}
