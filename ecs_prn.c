/*
 * ecs_prn.c
 *
 *  Created on: Nov 12, 2015
 *      Author: tslld
 */

#include "ecdsa.h"

/** Print out the content (r, s) of a ecdsa_sig structure
 *  \param	sig pointer to the ecdsa_sig structure
 */
void ecs_print_fp(FILE *fp, ecdsa_sig sig) {
	assert(sig != NULL);

	fprintf(fp, "\nSignature (r,s): \n");
	mpz_out_str(fp, 16, sig->r);
	fprintf(fp, "\n");
	mpz_out_str(fp, 16, sig->s);
	//fprintf(fp, ")\n");
}

