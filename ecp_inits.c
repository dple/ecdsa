/*
 * ec_point_inits.c
 *
 *  Created on: Sep 26, 2015
 *      Author: Le Duc-Phong
 *      Temasek Laboratories, NUS
 */

#include "ecdsa.h"
#include "ec_point.h"


/** Initialize a point
 *	\return	pointer the an ec_point structure
 */
ec_point ec_point_init() {
	ec_point ret;
	ret = malloc(sizeof(struct ec_point_st));
	assert(ret != NULL);

	mpz_init(ret->x);
	mpz_init(ret->y);
	ret->infinity = false;
	return ret;
}

ec_point_proj ec_point_proj_init() {
	ec_point_proj ret;
	ret = malloc(sizeof(struct ec_point_proj_st));
	assert(ret != NULL);

	mpz_init(ret->X);
	mpz_init(ret->Y);
	mpz_init(ret->Z);

	return ret;
}


/** Simultaneous initialize and set point P from GMP integers
 *	\param x	Big number representing the x-coordinates of the point
 *	\param y	Big number representing the y-coordinates of the point
 *	\return	pointer the an ec_point structure
 */
ec_point ec_point_init_set_mpz(mpz_t x, mpz_t y) {
	ec_point P;
	P = malloc(sizeof(struct ec_point_st));
	assert(P != NULL);

	mpz_init_set(P->x, x);
	mpz_init_set(P->y, y);
	P->infinity = false;
	return P;
}

ec_point_proj ec_point_proj_init_set_mpz(mpz_t x, mpz_t y, mpz_t z) {
	ec_point_proj P;
	P = malloc(sizeof(struct ec_point_proj_st));
	assert(P != NULL);

	mpz_init_set(P->X, x);
	mpz_init_set(P->Y, y);
	mpz_init_set(P->Z, z);

	return P;
}

/*Initialize and set point from strings of a base from 2-62*/
ec_point ec_point_init_set_str(const char *x, const char *y, int base) {
	ec_point P;
	P = malloc(sizeof(struct ec_point_st));
	assert(P != NULL);

	mpz_init_set_str(P->x, x, base);
	mpz_init_set_str(P->y, y, base);
	P->infinity = false;
	return P;
}

ec_point_proj ec_point_proj_init_set_str(const char *x, const char *y, const char *z, int base) {
	ec_point_proj P;
	P = malloc(sizeof(struct ec_point_proj_st));
	assert(P != NULL);

	mpz_init_set_str(P->X, x, base);
	mpz_init_set_str(P->Y, y, base);
	mpz_init_set_str(P->Z, z, base);

	return P;
}


ec_point ec_point_init_set_str_hex(const char *x, const char *y) {

	return ec_point_init_set_str(x, y, 16);

}

ec_point_proj ec_point_proj_init_set_str_hex(const char *x, const char *y, const char *z) {

	return ec_point_proj_init_set_str(x, y, z, 16);

}


/* Set point P from GMP integers.
 *
 * Require P was initialized
 */
void ec_point_set_mpz(ec_point P, mpz_t x, mpz_t y) {
	mpz_set(P->x, x);
	mpz_set(P->y, y);
	P->infinity = false;
}


/* Set point from strings of a base from 2-62
 *
 * Require point P was initialized and allocated a memory space
 *
 */
void ec_point_set_str(ec_point P, const char *x, const char *y, int base) {
	mpz_set_str(P->x, x, base);
	mpz_set_str(P->y, y, base);
}

/*Set point from hexadecimal strings*/
void ec_point_set_str_hex(ec_point P, const char *x, const char *y) {
	ec_point_set_str(P,x,y,16);
}


/* Set point to be a infinity
 * Require point P was initialized and allocated a memory space
 *
 */
void ec_point_set_at_infinity(ec_point P){
	P->infinity = true;
}

void ec_point_proj_set_at_infinity(ec_point_proj P){

	mpz_set_ui(P->Z, 0);
}
