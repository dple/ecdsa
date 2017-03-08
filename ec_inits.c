/*
 * ec.c
 *
 *  Created on: Sep 9, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"
#include "utils.h"


struct curve_params {
	char* name;
	const char *p, *a, *b, *Gx, *Gy, *order, *cofactor;
};

static const struct curve_params curves_params[] = {
	{
			/* Certicom recommendations P-224 */
			"secp224k1",
			/* p */
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D",
			/* a */
			"00000000000000000000000000000000000000000000000000000000",
			/* b */
			"00000000000000000000000000000000000000000000000000000005",
			/* Gx */
			"A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C",
			/* Gy */
			"7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5",
			/* order */
			"010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7",
			/* cofactor */
			"01",
	},
	{
			/* NIST P-224 */
			"secp224r1",
			/* p */
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
			/* a */
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
			/* b */
			"B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
			/* Gx */
			"B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
			/* Gy */
			"BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
			/* order */
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
			/* cofactor */
			"01",
	},
	{
			/* Certicom 256 bits curve */
			"secp256k1",
			/* p */
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
			/* a */
			"0000000000000000000000000000000000000000000000000000000000000000",
			/* b */
			"0000000000000000000000000000000000000000000000000000000000000007",
			/* Gx */
			"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
			/* Gy */
			"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
			/* order */
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
			/* cofactor */
			"01",
	},
	{
			/* NIST P-256 */
			"secp256r1",
			/* p */
			"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
			/* a */
			"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
			/* b */
			"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
			/* Gx */
			"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
			/* Gy */
			"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
			/* order */
			"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
			/* cofactor */
			"01",
	},

};



/** Allocates and initialize a ec_group structure
 *  \return pointer to a ec_group structure or NULL if an error occurred
 */
ec_group ec_group_init() {
	ec_group ec;
	ec = malloc(sizeof(struct ec_group_st));
	assert(ec != NULL);

	mpz_init(ec->A);
	mpz_init(ec->B);
	mpz_init(ec->field);
	mpz_init(ec->order);
	mpz_init(ec->cofactor);
	ec->generator = ec_point_init();

	return ec;
}

ec_group ec_group_init_by_curve_name(const char* name) {
	ec_group ret = ec_group_init();
	int ok = 0;
	unsigned int i;

	int no_curves = sizeof(curves_params) / sizeof(struct curve_params);
	for (i = 0; i < no_curves; i++) {
		if (strcmp(curves_params[i].name, name) == 0) {
			ec_group_set_str_hex(ret, name, curves_params[i].p, curves_params[i].a, curves_params[i].b, curves_params[i].Gx,
					curves_params[i].Gy, curves_params[i].order, curves_params[i].cofactor);
			ok = 1;
			break;
		}
	}

	if (ok == 0) {
		return NULL;
	}

	return ret;
}

/** Set up parameters for a ec_group from Big number mpz_t
 * \param  ec   	pointer to the ec_group structure
 * \param  name  	pointer to a constant string
 * \param  field  	mpz_t big number, the characteristic of the finite field
 * \param  a, b   	mpz_t big number, the curve parameters of the Weierstrass form
 * \param  Gx, Gy	coordinates of the generator
 * \param order		the order of subgroup of points used on the curve
 * \param cofactor 	the cofactor of the curve
 *
 * \return pointer to a ec_group structure or NULL if an error occurred
 *
 */
void ec_group_set_mpz(ec_group ret, const char* name, mpz_t field, mpz_t a, mpz_t b, mpz_t Gx, mpz_t Gy, mpz_t order, mpz_t cofactor) {

	int length = strlen(name);
	ret->curve_name = (char*)malloc(sizeof(char) * (length + 1));
	assert(ret->curve_name != NULL);

	ret->curve_name[length] = '\0';
	strcpy(ret->curve_name, name);

	mpz_init_set(ret->field, field);
	mpz_init_set(ret->A, a);
	mpz_init_set(ret->B, b);
	mpz_init_set(ret->order, order);
	mpz_init_set(ret->cofactor, cofactor);
	ret->generator = ec_point_init_set_mpz(Gx, Gy);

	gmp_printf("\n We work on curve E: y^2 = x^3 + %Zd x + %Zd over finite field F_p: %Zd \n", a, b, field);
	printf("The size of the finite field F_p = %d bits \n", bitlength(field));
	gmp_printf("The order of the curve E = %Zd \n", order);

}

/**  Initialize and assign an elliptic curve from big integers
 * \param  ec   	pointer to the ec_group structure
 * \param  name  	pointer to a constant string
 * \param  field  	mpz_t big number, the characteristic of the finite field
 * \param  a, b   	mpz_t big number, the curve parameters of the Weierstrass form
 * \param  Gx, Gy	coordinates of the generator
 * \param order		the order of subgroup of points used on the curve
 * \param cofactor 	the cofactor of the curve
 *
 * \return pointer to a ec_group structure or NULL if an error occurred
 */
ec_group ec_group_init_set_mpz(const char* name, mpz_t field, mpz_t a, mpz_t b, mpz_t Gx, mpz_t Gy, mpz_t order, mpz_t cofactor) {
	ec_group ret;
	ret = malloc(sizeof(struct ec_group_st));
	assert(ret != NULL);

	int length = strlen(name);
	ret->curve_name = (char*)malloc(sizeof(char) * (length + 1));
	assert(ret->curve_name != NULL);

	ret->curve_name[length] = '\0';
	strcpy(ret->curve_name, name);

	mpz_init_set(ret->field, field);
	mpz_init_set(ret->A, a);
	mpz_init_set(ret->B, b);
	mpz_init_set(ret->order, order);
	mpz_init_set(ret->cofactor, cofactor);
	ret->generator = ec_point_init_set_mpz(Gx, Gy);

	gmp_printf("\n We work on curve E: y^2 = x^3 + %Zd x + %Zd over finite field F_p: %Zd \n", a, b, field);
	printf("The size of the finite field F_p = %d bits \n", bitlength(field));
	gmp_printf("The order of the curve E = %Zd \n", order);

	return ret;
}

/*
 * Initialize and set parameters of a curve from strings
 *
 * \param  ec   	pointer to the ec_group structure
 * \param  name  	pointer to a constant string
 * \param  field  	mpz_t big number, the characteristic of the finite field
 * \param  a, b   	mpz_t big number, the curve parameters of the Weierstrass form
 * \param  Gx, Gy	coordinates of the generator
 * \param order		the order of subgroup of points used on the curve
 * \param cofactor 	the cofactor of the curve
 *
 * \return pointer to a ec_group structure or NULL if an error occurred
 */

ec_group ec_group_init_set_str(const char* name, const char* field, const char* a, const char* b,
								const char* Gx, const char* Gy, const char* order, const char* cofactor,
								int base) {

	ec_group ret;
	ret = malloc(sizeof(struct ec_group_st));
	assert(ret != NULL);

	int len = strlen(name);
	ret->curve_name = (char*)malloc(sizeof(char) * (len + 1));
	assert(ret->curve_name != NULL);

	ret->curve_name[len] = '\0';
	strcpy(ret->curve_name, name);

	mpz_init_set_str(ret->field, field, base);
	mpz_init_set_str(ret->A, a, base);
	mpz_init_set_str(ret->B, b, base);
	ret->generator = ec_point_init_set_str(Gx, Gy, base);
	mpz_init_set_str(ret->order, order, base);
	mpz_init_set_str(ret->cofactor, cofactor, base);

	return ret;
}

/*
 * Assign parameters of a curve from strings
 *
 * \param  ec   	pointer to the ec_group structure
 * \param  name  	pointer to a constant string
 * \param  field  	mpz_t big number, the characteristic of the finite field
 * \param  a, b   	mpz_t big number, the curve parameters of the Weierstrass form
 * \param  Gx, Gy	coordinates of the generator
 * \param order		the order of subgroup of points used on the curve
 * \param cofactor 	the cofactor of the curve
 *
 * \return pointer to a ec_group structure or NULL if an error occurred
 */
void ec_group_set_str(ec_group ret, const char* name, const char* field, const char* a, const char* b,
								const char* Gx, const char* Gy, const char* order, const char* cofactor,
								int base) {

	int len = strlen(name);
	ret->curve_name = (char*)malloc(sizeof(char) * (len + 1));
	assert(ret->curve_name != NULL);

	ret->curve_name[len] = '\0';
	strcpy(ret->curve_name, name);

	mpz_init_set_str(ret->field, field, base);
	mpz_init_set_str(ret->A, a, base);
	mpz_init_set_str(ret->B, b, base);
	ret->generator = ec_point_init_set_str(Gx, Gy, base);
	mpz_init_set_str(ret->order, order, base);
	mpz_init_set_str(ret->cofactor, cofactor, base);
}


/*
 * Initialize and assign parameters of a curve from strings in hex
 *
 * \param  ec   	pointer to the ec_group structure
 * \param  name  	pointer to a constant string
 * \param  field  	mpz_t big number, the characteristic of the finite field
 * \param  a, b   	mpz_t big number, the curve parameters of the Weierstrass form
 * \param  Gx, Gy	coordinates of the generator
 * \param order		the order of subgroup of points used on the curve
 * \param cofactor 	the cofactor of the curve
 *
 * \return pointer to a ec_group structure or NULL if an error occurred
 */
ec_group ec_group_init_set_str_hex(const char* name, const char* field, const char* a, const char* b,
									const char* Gx, const char* Gy, const char* order, const char* cofactor) {

	return ec_group_init_set_str(name, field, a, b, Gx, Gy, order, cofactor, 16);
}

/*
 * Assign parameters of a curve from strings in hex
 *
 * \param  ec   	pointer to the ec_group structure
 * \param  name  	pointer to a constant string
 * \param  field  	mpz_t big number, the characteristic of the finite field
 * \param  a, b   	mpz_t big number, the curve parameters of the Weierstrass form
 * \param  Gx, Gy	coordinates of the generator
 * \param order		the order of subgroup of points used on the curve
 * \param cofactor 	the cofactor of the curve
 *
 * \return pointer to a ec_group structure or NULL if an error occurred
 */
void ec_group_set_str_hex(ec_group ret, const char* name, const char* field, const char* a, const char* b,
									const char* Gx, const char* Gy, const char* order, const char* cofactor) {

	ec_group_set_str(ret, name, field, a, b, Gx, Gy, order, cofactor, 16);
}
