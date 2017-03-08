/*
 *  Created on: Sep 8, 2015
 *      Author: tslld
 */


#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"
#include "field_ops.h"

/** Get/Set the X-coordinates of the point
 * 	\param P	pointer to an ec_point structure
 * 	\param X	BIG number, field characteristic
 * 								required to be initialized
 * 	\return		X-coordinate of P
 */
void ec_point_get_x(ec_point P, mpz_t X) {

	mpz_set(X, P->x);
}

void ec_point_set_x(ec_point P, mpz_t X) {

	mpz_set(P->x, X);
}

/** Get/Set the Y-coordinates of the point
 * 	\param P	pointer to an ec_point structure
 * 	\param Y	BIG number, field characteristic
 * 								required to be initialized
 * 	\return		Y-coordinate of P
 */
void ec_point_get_y(ec_point P, mpz_t Y) {

	mpz_set(Y, P->y);
}

void ec_point_set_y(ec_point P, mpz_t Y) {

	mpz_set(P->y, Y);
}

