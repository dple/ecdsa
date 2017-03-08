/*
 * ecp_is_point_at_infinity.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec_point.h"

bool ec_point_is_at_infinity(ec_point P) {

	return P->infinity;

}


