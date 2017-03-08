/*
 * eck_dup.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"

/** Creates a new EC_KEY object and copies the content from src to it.
 *  \param  src  the source EC_KEY object
 *  \return newly created EC_KEY object or NULL if an error occurred.
 */
ec_key ec_key_dup(const ec_key src) {

	if (src == NULL)
		return NULL;

	ec_key ret;
	ret = malloc(sizeof(struct ec_key_st));
	assert(ret != NULL);

	ret->group = ec_group_dup(src->group);

	if(ret->group == NULL)
		return NULL;

	ret->pub_key = ec_point_dup(src->pub_key);

	if(ret->pub_key == NULL)
		return NULL;

	mpz_init_set(ret->priv_key, src->priv_key);

	return ret;
}
