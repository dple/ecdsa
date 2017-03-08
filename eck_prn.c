/*
 * eck_prn.c
 *
 *  Created on: Nov 12, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"

/** Prints out the contents of a EC_KEY object
 *  \param  fp   file descriptor to which the information is printed
 *  \param  key  EC_KEY object
 *
 *  \return 1 on success and 0 if an error occurred
 */
void ec_key_print_fp(FILE *fp, const ec_key key) {

	ec_group_print_fp(fp, key->group);
	ec_point_print_fp(fp, key->pub_key);
	mpz_out_str(fp, 16, key->priv_key);

}

