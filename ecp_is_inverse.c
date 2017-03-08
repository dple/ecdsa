/*
 * ecp_is_inverse.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"


/** Compare two points P, Q on the elliptic curve EC
 * 	\param P		pointer to an ec_point structure
 *	\param Q		pointer to an ec_point structure
 *	\param field	BIG number, field characteristic
 * 	\return 		1 if P = -Q, otherwise returns 0
 */
bool ec_point_is_inverse(ec_point P, ec_point Q, mpz_t field) {
	bool rop;

	//If at infinity
	if(P->infinity && Q->infinity)
		return true;

	else if(P->infinity || Q->infinity)
		return false;

	else {
		mpz_t tmp; mpz_init(tmp);
		mpz_sub(tmp, field, P->y);
		rop = !mpz_cmp(P->x,Q->x) && !mpz_cmp(tmp,Q->y);;
		mpz_clear(tmp);
		return rop;
	}
}

