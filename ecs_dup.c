/*
 * ecs_dup.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */


#include "ecdsa.h"

ecdsa_sig ecs_dup(ecdsa_sig src) {

	if (src == NULL){
		fprintf(stdout, "Error ! Source operator is NULL.\n");
		return NULL;
	}

	ecdsa_sig ret;
	ret = malloc(sizeof(struct ecdsa_sig_st));
	assert(ret != NULL);

	mpz_init_set(ret->r, src->r);
	mpz_init_set(ret->s, src->s);

	return ret;
}
