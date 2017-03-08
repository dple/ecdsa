/*
 * ecp_dup.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */


#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"


/** Creates a new ec_point object  and copies the content from src to it
 * Simultaneous point initialize & assign a point from another point
 *	\param
 *	\return	pointer the an ec_point structure
 */
ec_point ec_point_dup(ec_point src) {

	if (src == NULL){
		fprintf(stdout, "Error ! Source operator is NULL.\n");
		return NULL;
	}

	ec_point ret;
	ret = malloc(sizeof(struct ec_point_st));
	assert(ret != NULL);

	mpz_init_set(ret->x, src->x);
	mpz_init_set(ret->y, src->y);
	ret->infinity = src->infinity;

	return ret;
}

