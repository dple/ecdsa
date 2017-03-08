/*
 * ec_cpy.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */


#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"



/** Make a copy of an group
 * 	\param dest		pointer to a ec_group structure
 * 	\param src		pointer to a ec_group structure
 *
 * 	\return 1 if success, 0 if fail
 */
int ec_group_cpy(ec_group dest, ec_group src) {

	if ((src == NULL) || (dest = NULL))
		return 0;

	if (!ec_point_cpy(dest->generator, src->generator))
		return 0;

	assert(dest->curve_name != NULL);
	strcpy(dest->curve_name, src->curve_name);

	mpz_set(dest->field, src->field);
	mpz_set(dest->A, src->A);
	mpz_set(dest->B, src->B);
	mpz_set(dest->order, src->order);
	mpz_set(dest->cofactor, src->cofactor);

	return 1;
}
