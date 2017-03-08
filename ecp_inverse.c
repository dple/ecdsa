/*
 * ecp_inverse.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */


#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"

/** Given a point P on the elliptic curve EC, return an inverse point R = -P
 * 	\param P		pointer to an ec_point structure
 * 	\param field	BIG number, field characteristic
 * 	\return			inverse point
 *
 */
ec_point ec_point_inverse(ec_point P, mpz_t field) {
	ec_point R = ec_point_init();

	if(P->infinity) { /* If P is the point at infinity */
		R->infinity = true;
	} else {
		mpz_set(R->x, P->x);
		mpz_sub(R->y, field, P->y);
	}
	return R;
}


