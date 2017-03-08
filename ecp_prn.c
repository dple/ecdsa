/*
 * ecp_prn.c
 *
 *  Created on: Nov 12, 2015
 *      Author: tslld
 */
#include "ecdsa.h"
//#include "ec.h"
#include "ec_point.h"


/*Print point to standard output stream*/
void ec_point_print_fp(FILE *fp, ec_point P) {

	assert(P != NULL);

	if(P->infinity)
		fprintf(fp, "Point is at infinity!\n");
	else {
		fprintf(fp, "the coordinates: (0x");
		mpz_out_str(fp, 16, P->x);
		fprintf(fp, " : 0x");
		mpz_out_str(fp, 16, P->y);
		fprintf(fp, ")\n");
	}
}

