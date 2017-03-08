/*
 * eck_cpy.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"


/** Copies a EC_KEY object.
 *  \param  dst  destination EC_KEY object
 *  \param  src  src EC_KEY object
 *	\return 1 if successful, 0 if failed
 */
int ec_key_copy(ec_key dest, const ec_key src) {

	if ((src == NULL) || (dest == NULL))
		return 0;

	if (!ec_group_cpy(dest->group, src->group))
		return 0;

	if (!ec_point_cpy(dest->pub_key, src->pub_key))
		return 0;

	mpz_set(dest->priv_key, src->priv_key);

	return 1;
}


