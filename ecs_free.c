/*
 * ecs_free.c
 *
 *  Created on: Nov 12, 2015
 *      Author: tslld
 */

#include "ecdsa.h"

/** frees a ecdsa_sig structure
 *  \param  sig  pointer to the ecdsa_sig structure
 */
void ecs_free(ecdsa_sig sig) {
	assert(sig != NULL);

	mpz_clear((*sig).r);
	mpz_clear((*sig).s);

	free(sig);
}
