/*
 * ecs_cmp.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"

int ecs_cmp(ecdsa_sig S1, ecdsa_sig S2) {
	if ((S1 == NULL) || (S2 == NULL))
		return 0;

	return !mpz_cmp(S1->r, S2->r) && !mpz_cmp(S1->s, S2->s);
}

