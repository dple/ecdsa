/*
 * ecs_lib.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"
#include "field_ops.h"

/** Get/Set the value r of the signature
 * 	\param P	pointer to an ec_point structure
 * 	\param X	BIG number, field characteristic
 * 								required to be initialized
 * 	\return		X-coordinate of P
 */
void ecs_get_r(ecdsa_sig sig, mpz_t R) {

	mpz_set(R, sig->r);
}

void ecs_set_r(ecdsa_sig sig, mpz_t R) {

	mpz_set(sig->r, R);
}



/** Get/Set the value r of the signature
 * 	\param P	pointer to an ec_point structure
 * 	\param X	BIG number, field characteristic
 * 								required to be initialized
 * 	\return		X-coordinate of P
 */
void ecs_get_s(ecdsa_sig sig, mpz_t S) {

	mpz_set(S, sig->s);
}

void ecs_set_s(ecdsa_sig sig, mpz_t S) {

	mpz_set(sig->s, S);
}
