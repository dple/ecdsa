/*
 * ecp_cmp.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"

/** Compare two points P, Q on the elliptic curve EC in affine coordinates
 *	\param P		pointer to an ec_point structure
 *	\param Q		pointer to an ec_point structure
 *	\param field	BIG number, field characteristic
 * 	\return 		1 if P = Q, otherwise returns 0
 *
 */
int ec_point_cmp(ec_point P, ec_point Q, mpz_t field) {
	//If at infinity
	if(P->infinity && Q->infinity)
		return 1;
	else if(P->infinity || Q->infinity)
		return 0;
	else {
		return !mpz_cmp(P->x,Q->x) && !mpz_cmp(P->y,Q->y);;
	}
}
