/*
 * ec.h
 *
 *  Created on: Aug 18, 2015
 *      Author: tslld
 */

#ifndef EC_H_
#define EC_H_

/** Print out elliptic curve parameters
 */
void ec_group_print_fp(FILE *fp, ec_group ec);

/* Load a curve depending on it's curve number, defined by the enumerate */

/* Get/Set the order of the group of points being used on the elliptic curve */
void ec_group_get_order(ec_group ec, mpz_t order);
void ec_group_set_order(ec_group ec, mpz_t order);

/* Get/Set the field characteristic of the elliptic curve */
void ec_group_get_field(ec_group ec, mpz_t field);
void ec_group_set_field(ec_group ec, mpz_t field);

/* Get/Set the parameter A of the elliptic curve */
void ec_group_get_a(ec_group ec, mpz_t a);
void ec_group_set_a(ec_group ec, mpz_t a);

/* Get/Set the parameter B of the elliptic curve */
void ec_group_get_b(ec_group ec, mpz_t b);
void ec_group_set_b(ec_group ec, mpz_t b);

/* Get/Set the co-factor the elliptic curve */
void ec_group_get_cofactor(ec_group ec, mpz_t cofactor);
void ec_group_set_cofactor(ec_group ec, mpz_t cofactor);

/* Set name for an elliptic curve */
int ec_group_set_name(ec_group ec, const char* name);
/* Get name of the elliptic curve */
char* ec_group_get_name(ec_group ec);


/* Initialize a curve, i.e., allocate memory for parameters of the curve */
ec_group ec_group_init();

/* Create a new EC group from a given name */
ec_group ec_group_init_by_curve_name(const char* name);

/** Creates a new ec_group object  and copies the content from src to it
 *	\param	ec_group	pointer to an ec_group structure
 *	\return	pointer the an ec_group structure
 */
ec_group ec_group_dup(ec_group src);

/** Make a copy of an group
 * 	\param dest		pointer to a ec_group structure
 * 	\param src		pointer to a ec_group structure
 */
int ec_group_cpy(ec_group dest, ec_group src);


/* Initialize a curve with big integers as parameters */
void ec_group_set_mpz(ec_group ec, const char* name, mpz_t a, mpz_t b, mpz_t p, mpz_t r, mpz_t h, mpz_t Gx, mpz_t Gy);
ec_group ec_group_init_set_mpz(const char* name, mpz_t a, mpz_t b, mpz_t p, mpz_t r, mpz_t h, mpz_t Gx, mpz_t Gy);

/* Initialize a curve from strings */
void ec_group_set_str(ec_group ec, const char* name, const char* field, const char* a, const char* b, const char* Gx,
								const char* Gy,	const char* order, const char* cofactor, int base);
ec_group ec_group_init_set_str(const char* name, const char* field, const char* a, const char* b, const char* Gx,
								const char* Gy,	const char* order, const char* cofactor, int base);
/* Initialize a curve from hexadecimal strings */
void ec_group_set_str_hex(ec_group ec, const char* name, const char* field, const char* a, const char* b, const char* Gx,
								const char* Gy, const char* order, const char* cofactor);
ec_group ec_group_init_set_str_hex(const char* name, const char* field, const char* a, const char* b, const char* Gx,
								const char* Gy, const char* order, const char* cofactor);

/* Release memory used by curve parameters */
void ec_group_free(ec_group ec);



/************************************************************************/
/* 				Arithmetic operations on elliptic curve					*/
/************************************************************************/

/* Add two points P, Q in atomic principle. If P = Q, perform a doubling */
ec_point ec_point_add_atomic(ec_point P, ec_point Q, ec_group ec);
ec_point ec_point_add(ec_point P, ec_point Q, ec_group ec);
ec_point ec_point_dbl(ec_point P, ec_group ec);


/*Set point R = 2P*/
// pt_point point_doubling(pt_point P, pt_curve ec);

/* Perform scalar multiplication to P, with the factor scalar on the curve curve EC due to the atomic principle */
ec_point ecp_mul_atomic(const ec_point P, const mpz_t scalar, ec_group ec);
ec_point ecp_mul_montgomery(ec_point P, mpz_t scalar, ec_group ec);
ec_point ecp_mul_rand_montgomery(ec_point P, mpz_t scalar, ec_group ec);

/* Perform scalar multiplication to P, with the factor scalar on the curve curve EC due to the atomic principle */
ec_point ec_sec_wmul(const ec_point P, const mpz_t scalar, ec_group ec);





#endif /* EC_H_ */
