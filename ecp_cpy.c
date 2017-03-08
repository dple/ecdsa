/*
 * ecp_cpy.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"

/** Make a copy of the point P.
 * 	\param R	pointer to an ec_point structure
 *	\param P	pointer to an ec_point structure
 *	\return 1 if successful, 0 if failed
 */
int ec_point_cpy(ec_point dest, ec_point src){
	int ok = 0;
	if ((src == NULL) || (dest == NULL)) {
		fprintf(stdout, "Error ! Destination or source operator is NULL.\n");
		return (ok);
	}

	mpz_set(dest->x, src->x);
	mpz_set(dest->y, src->y);
	dest->infinity = src->infinity;

	ok = 1;

	return (ok);

}


