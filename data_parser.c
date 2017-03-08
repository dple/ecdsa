/*
 * data_parser.c
 *
 *  Created on: Nov 19, 2015
 *      Author: tslld
 */

#include "ecdsa.h"

int get_curve_name_fp(const char* in_fname) {

	int ok = 0;
	char curve[9];
	FILE *ifp;

	if (in_fname == NULL ) { // No file name provided to open
		fprintf(stderr, "Need to provide the input file storing the private key \n");
		return (ok);
	}else {
		ifp = fopen(in_fname, "r");
		if(ifp == NULL) {
			fprintf(stderr, "Can't open input file %s to read the private key \n", in_fname);
			return (ok);
		} else {
			if (fscanf(ifp, "%s", curve) == EOF) {
				fprintf(stderr, "Can't get the curve name from file %s \n", in_fname);
				return (ok);
			}
		}
	}

	ok = 1;

	return (ok);
}
