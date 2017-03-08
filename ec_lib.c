/*
 * ec_lib.c
 *
 *  Created on: Oct 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"

/** Get/Set the order of the group of points being used on the elliptic curve
 * 	\param ec		pointer to an ec_group structure
 * 	\param order 	BIG number
 * 	\return
 */
void ec_group_get_order(ec_group ec, mpz_t order) {

	mpz_set(order, ec->order);
}

void ec_group_set_order(ec_group ec, mpz_t order) {

	mpz_set(ec->order, order);
}

/** Get/Set the co-factor the elliptic curve
 * 	\param ec		pointer to an ec_group structure
 * 	\param cofactor	BIG number
 * 	\return
 */
void ec_group_get_cofactor(ec_group ec, mpz_t cofactor){

	mpz_set(cofactor, ec->cofactor);
}

void ec_group_set_cofactor(ec_group ec, mpz_t cofactor){

	mpz_set(ec->cofactor, cofactor);
}

/** Get/Set the characteristic of field
 * 	\param ec		pointer to an ec_group structure
 * 	\param field	BIG number
 * 	\return
 */
void ec_group_get_field(ec_group ec, mpz_t field){

	mpz_set(field, ec->field);
}

void ec_group_set_field(ec_group ec, mpz_t field){

	mpz_set(ec->field, field);
}

/** Get/Set the parameter A the elliptic curve
 * 	\param ec	pointer to an ec_group structure
 * 	\param A	BIG number
 * 	\return
 */
void ec_group_get_a(ec_group ec, mpz_t a){

	mpz_set(a, ec->A);
}

void ec_group_set_a(ec_group ec, mpz_t a){

	mpz_set(ec->A, a);
}

/** Get/Set the parameter B of the elliptic curve
 * 	\param ec	pointer to an ec_group structure
 * 	\param B	BIG number
 * 	\return
 */
void ec_group_get_b(ec_group ec, mpz_t b){

	mpz_set(b, ec->B);
}

void ec_group_set_b(ec_group ec, mpz_t b){

	mpz_set(ec->B, b);
}


/** Set the name of a curve
 * 	\param ec		pointer to an ec_group structure
 * 	\param name 	string name
 * 	\return
 * */
int ec_group_set_name(ec_group ec, const char* name) {

	int ok = 0;

	if(name == NULL)
		return (ok);

	int length = strlen(name);

	/* Allocate memory of curve name is NULL */
	if (ec->curve_name == NULL) {
		ec->curve_name = (char*)malloc(sizeof(char) * (length + 1));
		ec->curve_name[length] = '\0';
	}

	if(ec->curve_name == NULL)
		return (ok);

	strcpy(ec->curve_name, name);

	ok = 1;

	return (ok);
}

/* Get the name of the elliptic curve being used */
char* ec_group_get_name(ec_group ec) {

	if ((ec == NULL) || (ec->curve_name == NULL)) {
		fprintf(stdout, "Cannot get the curve name. Parsing NULL parameters !\n");
		return NULL;
	}

	char* name;
	int length = strlen(ec->curve_name);
	name = (char*)malloc(sizeof(char) * (length + 1));

	if(name == NULL) {
		fprintf(stdout, "Couldn't allocate a memory ! \n");
		return NULL;
	}

	name[length] = '\0';

	strcpy(name, ec->curve_name);

	return name;
}

