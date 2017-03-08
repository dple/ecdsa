/*
 * ecs_cpy.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */


#include "ecdsa.h"

int ecs_cpy(ecdsa_sig dest, ecdsa_sig src) {
	int ok = 0;
	if ((src == NULL) || (dest == NULL)) {
		fprintf(stdout, "Error ! Destination or source operator is NULL.\n");
		return (ok);
	}

	mpz_set(dest->r, src->r);
	mpz_set(dest->s, src->s);

	ok = 1;

	return (ok);

}
