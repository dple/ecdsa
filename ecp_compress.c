/*
 * ecp_compress.c
 *
 *  Created on: Nov 12, 2015
 *      Author: tslld
 */
#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"
#include "field_ops.h"


/** Decompress a point from hex string
 * 	\param P		pointer to an ec_point structure
 * 	\param xP		hex string of compressed point P
 * 	\param group	pointer to an ec_group
 */
void ec_point_decompress(ec_point P, char* xP, ec_group group) {
	// Initialize variables
	mpz_t x, a, b, t1, t2;
	mpz_init(x); mpz_init(a); mpz_init(b);
	mpz_init(t1); mpz_init(t2);

	//Get x coordinate
	mpz_set_str(x, xP + 2, 16);

	//alpha = x^3+a*x+b mod p
	//number_theory_exp_modp_ui(t1, x, 3, ec->p);//t1 = x^3 mod p
	mpz_mul(t1, x, x);
	mod_mul(t1, t1, x, group->field);
	mod_mul(t2, x, group->A, group->field);		//t3 = a*x mod p
	mod_addadd(a, t1, t2, group->B, group->field);

	// b = sqrt(a) mod p
	mod_sqrt(b, a, group->field);

	//Get y mod 2 from input
	mpz_set_ui(t2, xP[1] == '2' ? 0 : 1);

	//Set x
	mpz_set(P->x, x);

	//t2 = beta mod p
	mpz_mod_ui(t1, b, 2);
	if(mpz_cmp(t1, t2))
		mpz_set(P->y, b);	//y = beta
	else
		mpz_sub(P->y, group->field, b);//y = p -beta

	// Release variables
	mpz_clear(x); mpz_clear(a); mpz_clear(b);
	mpz_clear(t1); mpz_clear(t2);
}

/** Compress a point to hex string
 *	\param P	pointer to ec_point structure
 *	\return 	hex string
 */
char* ec_point_compress(ec_point P) {

	//Point should not be at infinity
	assert(!P->infinity);

	// length in hex
	int len = mpz_sizeinbase(P->x, 16) + 2;

	char* result = (char*)malloc(len + 1);
	result[len] = '\0';
	mpz_t t1; mpz_init(t1);

	//Add x coordinate in hex to result
	mpz_get_str(result + 2, 16, P->x);

	//Determine if it's odd or even
	mpz_mod_ui(t1, P->y, 2);
	if(mpz_cmp_ui(t1, 0))
		strncpy(result, "02", 2);
	else
		strncpy(result, "03", 2);

	mpz_clear(t1);

	return result;
}

