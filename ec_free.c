/*
 * ec_clear.c
 *
 *  Created on: Oct 9, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec_point.h"

/** frees a ec_group structure
 *  \param  ec  pointer to the ec_group structure
 */
void ec_group_free(ec_group ec) {

	if (ec == NULL) //assert(ec != NULL);
		return;

	mpz_clear((*ec).field);
	mpz_clear((*ec).A);
	mpz_clear((*ec).B);
	ec_point_free((*ec).generator);
	mpz_clear((*ec).order);
	mpz_clear((*ec).cofactor);
	free((*ec).curve_name);
	free(ec);

}
