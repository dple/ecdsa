/*
 * ec_dup.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"

/** Creates a new ec_point object  and copies the content from src to it
 *	\param	src		pointer the an ec_group structure
 *	\return	pointer the an ec_group structure
 */
ec_group ec_group_dup(ec_group src) {

	if (src == NULL)
		return NULL;

	ec_group ret;
	ret = malloc(sizeof(struct ec_group_st));
	assert(ret != NULL);

	int length = strlen(src->curve_name);
	ret->curve_name = (char*)malloc(sizeof(char) * (length + 1));
	assert(ret->curve_name != NULL);

	ret->curve_name[length] = '\0';
	strcpy(ret->curve_name, src->curve_name);

	mpz_init_set(ret->field, src->field);
	mpz_init_set(ret->A, src->A);
	mpz_init_set(ret->B, src->B);
	mpz_init_set(ret->order, src->order);
	mpz_init_set(ret->cofactor, src->cofactor);
	ret->generator = ec_point_dup(src->generator);

	return ret;
}

