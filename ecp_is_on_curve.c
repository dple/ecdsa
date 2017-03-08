/*
 * ecp_is_on_curve.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"
#include "field_ops.h"

/** Check whether point P is on the curve EC
 * 	\param P	pointer to a ec_point structure
 * 	\param ec	pointer to the ec_group structure
 *
 * 	\return 	true or false
 */
int ec_point_is_on_curve(ec_point P, ec_group ec) {
	int ok = 0;
	mpz_t l, r, t, t1;

	if ((P == NULL) || (ec == NULL))
		return 0;

	mpz_init(l); mpz_init(r); mpz_init(t); mpz_init(t1);

	mod_sqr(l, P->y, ec->field);

	mod_sqr(t, P->x, ec->field);
	mod_mul(t1, t, P->x, ec->field);
	mod_mul(t, ec->A, P->x, ec->field);
	mod_addadd(r, t1, t, ec->B, ec->field);

	if (!mpz_cmp(l, r))
		ok = 1;

	mpz_clear(l); mpz_clear(r); mpz_clear(t); mpz_clear(t1);

	return (ok);

}


