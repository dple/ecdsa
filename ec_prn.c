/*
 * ec_print.c
 *
 *  Created on: Oct 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec_point.h"

/* print parameters of the elliptic curve being used */
void ec_group_print_fp(FILE *fp, ec_group ec) {
	fprintf(fp, "The curve's name is %s. \n", ec->curve_name);
	fprintf(fp,
			"This curve is defined by Weierstrass equation\n     y^2 = x^3 + a*x + b  (mod 0x");
	mpz_out_str(stdout, 16, ec->field);
	fprintf(fp, ")\n\t a = 0x");
	mpz_out_str(fp, 16, ec->A);
	fprintf(fp, "\n\t b = 0x");
	mpz_out_str(fp, 16, ec->B);
	fprintf(fp, "\nThe order of the cyclic group is 0x");
	mpz_out_str(fp, 16, ec->order);
	fprintf(fp, "\nThe generator of the group is the point G: \n");
	ec_point_print_fp(fp, ec->generator);
}
