/*
 * ec_point.h
 *
 *  Created on: Aug 18, 2015
 *      Author: tslld
 */

#ifndef EC_POINT_H_
#define EC_POINT_H_

/****************************************************************/
/*						Point operations						*/
/****************************************************************/

/** Return the additive inverse of the point P, in the curve curve
 * \param P 	pointer to the ec_point structure
 * \param mod	characteristic of the finite field on which the ec points defined
 * \return 		pointer to a ec_point structure
 */
ec_point ec_point_inverse(ec_point P, mpz_t mod);

/** Check whether point P is inverse of point Q
 * 	\param P	pointer to a ec_point structure
 * 	\param Q	pointer to a ec_point structure
 * 	\return 	true or false
 */
bool ec_point_is_inverse(ec_point P, ec_point Q, mpz_t mod);

/** Check whether point P is the point at infinity
 * 	\param P	pointer to a ec_point structure
 * 	\return 	true or false
 */
bool ec_point_is_at_infinity(ec_point P);

/** Check whether point P is on the curve
 * 	\param P	pointer to a ec_point structure
 * 	\param ec	pointer to the ec_group structure
 *
 * 	\return 	1 on success or 0 on any error occurred
 */

/** Get/Set the X-coordinates of the point
 * 	\param P	pointer to an ec_point structure
 * 	\param X	BIG number, field characteristic
 * 								required to be initialized
 * 	\return		X-coordinate of P
 */
void ec_point_get_x(ec_point P, mpz_t X);
void ec_point_set_x(ec_point P, mpz_t X);

/** Get/Set the Y-coordinates of the point
 * 	\param P	pointer to an ec_point structure
 * 	\param Y	BIG number, field characteristic
 * 								required to be initialized
 * 	\return		Y-coordinate of P
 */
void ec_point_get_y(ec_point P, mpz_t Y);
void ec_point_set_y(ec_point P, mpz_t Y);

int ec_point_is_on_curve(ec_point P, ec_group ec);


/** Print point to standard output stream
 * 	\param fp	pointer to a FILE
 * 	\param P	pointer to a ec_point structure
 */
void ec_point_print_fp(FILE *fp, ec_point P);

/** Compare two points return 1 if they are the same, returns 0 if not the same
 * 	\param P	pointer to a ec_point structure
 * 	\param Q	pointer to a ec_point structure
 * 	\return 	true or false
 */
int ec_point_cmp(ec_point P, ec_point Q, mpz_t mod);

/**	Compress the point P to a string
 *	\param P	pointer to an ec_point structure
 *	\return 	a string
 */
char* ec_point_compress(ec_point P);

/**	Deompress the point P to a string
 *	\param P	pointer to an ec_point structure
 *	\return 	a string
 */
void ec_point_decompress(ec_point P, char* zPoint, ec_group ec);

/** Release point
 *	\param P	pointer to an ec_point structure
 */
void ec_point_free(ec_point P);


/************************************************************************/
/*		Method to initialize and set a point on elliptic curve			*/
/************************************************************************/
/** Initialize a point
 *	\return 	pointer to an ec_point structure initialized
 */
ec_point ec_point_init();
ec_point_proj ec_point_proj_init();

/** Make a copy of the point P.
 * 	\param R	pointer to an ec_point structure
 *	\param P	pointer to an ec_point structure
 *	\return 1 if successful, 0 if failed
 */
int ec_point_cpy(ec_point dest, ec_point src);

/** Initialize and assign a point from the point P.
 *	\param P	pointer to an ec_point structure
 *	\return 	pointer to an ec_point structure
 */
ec_point ec_point_dup(ec_point src);

/*Set point from gmp integers */
void ec_point_set_mpz(ec_point P, mpz_t x, mpz_t y);
ec_point ec_point_init_set_mpz(mpz_t x, mpz_t y);
ec_point_proj ec_point_proj_init_set_mpz(mpz_t x, mpz_t y, mpz_t z);


/*Set point from strings of a base from 2-62*/
void ec_point_set_str(ec_point P, const char *x, const char *y, int base);
ec_point ec_point_init_set_str(const char *x, const char *y, int base);
ec_point_proj ec_point_proj_init_set_str(const char *x, const char *y, const char *z, int base);

/*Set point from hexadecimal strings*/
void ec_point_set_str_hex(ec_point P, const char *x, const char *y);
ec_point ec_point_init_set_str_hex(const char *x, const char *y);
ec_point_proj ec_point_proj_init_set_str_hex(const char *x, const char *y, const char* z);


/* Set point to be a infinity */
void ec_point_set_at_infinity(ec_point P);
void ec_point_proj_set_at_infinity(ec_point_proj P);


/*
 * Convert point from affine coordinates to projective coordinates and visa
 */

//void affine2proj(pt_point_proj P, pt_point Q, mpz_t mod);
//void proj2affine(pt_point P, pt_point_proj Q, mpz_t mod);



#endif /* EC_POINT_H_ */
