/*
 * eck_free.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"


/** Frees a EC_KEY object.
 *  \param  key  EC_KEY object to be freed.
 */
void ec_key_free(ec_key key) {

	if (key == NULL)
		return;

	mpz_clear(key->priv_key);
	free(key);

}

