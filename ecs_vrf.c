/*
 * ecs_vrf.c
 *
 *  Created on: Nov 11, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"
#include "field_ops.h"

/** Verifies that the given signature is valid ECDSA signature
 *  of the supplied hash value using the specified public key.
 *  \param  dgst     pointer to the hash value
 *  \param  dgstlen  length of the hash value
 *  \param  sig      pointer to the ecdsa_sig structure
 *  \param  eckey    EC_KEY object containing a public EC key
 *  \return 1 if the signature is valid, 0 if the signature is invalid
 *          and -1 on error
 */
int ecdsa_verify(const char *dgst, int dgstlen, const ecdsa_sig sig, const ec_group group, ec_point pub_key) {
	int ok = 0;

	if (group == NULL || pub_key == NULL) {
		fprintf(stdout, "ECDSA_F_ECDSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER");
		return -1;
	}

	mpz_t order, e; mpz_init(order);

	ec_group_get_order(group, order);

	//verify that r and s are integers within [1, n-1]
	mpz_t one; mpz_init(one);
	mpz_set_ui(one, 1);
	if(	mpz_cmp(sig->r,one) < 0 && mpz_cmp(order, sig->r) <= 0 &&
			mpz_cmp(sig->s, one) < 0 && mpz_cmp(order,sig->s) <= 0) {
		ok = 0;
		goto err;
	}

	/* Convert bit string of hash digest to an integer e */
	mpz_init_set_str(e, dgst, 16);
	assert(mpz_sizeinbase(e, 2) <= mpz_sizeinbase(order, 2));

	//Initialize variables
	mpz_t w, u1, u2;
	mpz_init(w); mpz_init(u1); mpz_init(u2);

	/* Compute the inverse of s
	 * We want inverse in constant time, therefore we utilize the fact
	 * order must be prime and use Fermats Little Theorem instead.
	 */
	if (!mod_invert(w, sig->s, order)) {
		fprintf(stdout, "ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB");
		ok = -1;
		goto err;
	}

	//u1 = e * w mod order
	mod_mul(u1, e, w, order);

	//u2 = r * w mod n
	mod_mul(u2, sig->r, w, order);

	//x = u1*G + u2*Q
	ec_point pt_tmp1 = ecp_mul_atomic(group->generator, u1, group);
	ec_point pt_tmp2 = ecp_mul_atomic(pub_key, u2, group);
	ec_point X = ec_point_add_atomic(pt_tmp1, pt_tmp2, group);

	mpz_t x1; mpz_init(x1);
	mpz_mod(x1, X->x, order);
	//Get the result, by comparing x value with r and verifying that x is NOT at infinity

	if ((mpz_cmp(sig->r, x1) == 0) && !X->infinity)
		ok = 1;
	else
		ok = 0;

	mpz_clear(w); mpz_clear(u1); mpz_clear(u2); mpz_clear(x1);
	ec_point_free(X); ec_point_free(pt_tmp1); ec_point_free(pt_tmp2);

err:
	mpz_clear(one); mpz_clear(order); mpz_clear(e);
	ec_group_free(group); ec_point_free(pub_key);

	return (ok);

}
