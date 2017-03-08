/*
 * ecs_lib.c
 *
 *  Created on: Nov 12, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"
#include "field_ops.h"


/** Allocates and initialize a ECDSA_SIG structure
 *  \return pointer to a ECDSA_SIG structure or NULL if an error occurred
 */
ecdsa_sig ecs_init() {
	ecdsa_sig sig;
	sig = malloc(sizeof(struct ecdsa_sig_st));
	assert(sig != NULL);

	mpz_init(sig->r);
	mpz_init(sig->s);

	return sig;

}

/** Initialize and set values for a ECDSA_SIG structure
 * 	\param R	big number
 * 	\param S	big number
 *  \return 	pointer to a ECDSA_SIG structure or NULL if an error occurred
 */
ecdsa_sig ecs_init_set(mpz_t R, mpz_t S) {
	ecdsa_sig sig;
	sig = malloc(sizeof(struct ecdsa_sig_st));
	assert(sig != NULL);

	mpz_init_set(sig->r, R);
	mpz_init_set(sig->s, S);

	return sig;

}
