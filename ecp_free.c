/*
 * point_clear.c
 *
 *  Created on: Sep 26, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec_point.h"


/** frees a ec_point structure
 *  \param  P  pointer to the ec_point structure
 */
void ec_point_free(ec_point P) {

	if (P == NULL)
		return;

	mpz_clear(P->x);
	mpz_clear(P->y);
	free(P);
}

