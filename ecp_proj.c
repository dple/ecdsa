/*
 * ecp_proj.c
 *
 *  Created on: Dec 1, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec_point.h"
#include "field_ops.h"

/*
 * Copy in constant time: if icopy == 1, copy in to out, if icopy == 0, copy
 * out to itself.
 */

void copy_conditional(ec_point_proj dst, const ec_point_proj src, mpz_t icopy) {
    mpz_t mask1; mpz_init(mask1); mpz_neg(mask1, icopy);
    mpz_t mask2; mpz_init(mask2); mpz_com(mask2, mask1);
    mpz_t tmp, tmp2;
    mpz_init(tmp); mpz_init(tmp2);

    mpz_and(tmp, src->X, mask1);
    mpz_and(tmp2, src->X, mask2);
    mpz_xor(dst->X, tmp, tmp2);

    mpz_and(tmp, src->Y, mask1);
    mpz_and(tmp2, src->Y, mask2);
    mpz_xor(dst->Y, tmp, tmp2);

    mpz_and(tmp, src->Z, mask1);
    mpz_and(tmp2, src->Z, mask2);
    mpz_xor(dst->Z, tmp, tmp2);

}

// Create a mask of only ones if the arguments a and b are equal, else a mask of only zeros
void eq_makemask(int mask, int a, int b) {
	mask = 0;
	mask |= a ^ b;
	mask--;
}

/******************************************************************************/
/*-
 *                       ELLIPTIC CURVE POINT OPERATIONS
 *
 * Points are represented in Jacobian projective coordinates:
 * (X, Y, Z) corresponds to the affine point (X/Z^2, Y/Z^3),
 * or to the point at infinity if Z == 0.
 *
 */

/*-
 * Double an elliptic curve point:
 * (X', Y', Z') = 2 * (X, Y, Z), where
 * X' = (3 * (X - Z^2) * (X + Z^2))^2 - 8 * X * Y^2
 * Y' = 3 * (X - Z^2) * (X + Z^2) * (4 * X * Y^2 - X') - 8 * Y^2
 * Z' = (Y + Z)^2 - Y^2 - Z^2 = 2 * Y * Z
 * Outputs can equal corresponding inputs, i.e., x_out == x_in is allowed,
 * while x_out == y_in is not (maybe this works, but it's not tested).
 */
ec_point_proj ec_point_proj_dbl(ec_point_proj P, ec_group ec) {
	mpz_t field, a;
	mpz_init_set(field, ec->field);
	mpz_init_set(a, ec->A);

	ec_point_proj R;
	// Initialize the point R
	R = ec_point_proj_init();
	mpz_t XX, YY, ZZ, S, M, T, tmp, tmp1;
	mpz_init(XX); mpz_init(YY); mpz_init(ZZ); mpz_init(S); mpz_init(M); mpz_init(T); mpz_init(tmp); mpz_init(tmp1);

	mod_sec_sqr(XX, P->X, field);		// XX = X1^2
	mod_sec_sqr(YY, P->Y, field);		// YY = Y1^2
	mod_sec_sqr(ZZ, P->Z, field);		// ZZ = Z1^2

	mod_sec_mul(tmp, P->X, YY, field); 	// S = 4*X1*YY
	mod_4mul(S, tmp, field);

	mod_add_add(M, XX, XX, XX, field);	// M = 3*XX+a*ZZ^2
	mpz_sqr(tmp, ZZ);
	mod_mul(tmp1, tmp, a, field);
	mod_sec_add(M, M, tmp1, field);

	mpz_sqr(tmp, M);       				// T = M^2-2*S
	mod_subsub(T, tmp, S, S, field);

	mpz_set(R->X, T);					// X3 = T
	mpz_sub(tmp, S, T);	  	  	  	  	// Y3 = M*(S-T)-8*YY^2
	mod_sec_mul(tmp1, M, tmp, field);
	mod_sec_sqr(tmp, YY, field);
	mod_8mul(tmp, tmp, field);
	mod_sub(R->Y, tmp1, tmp, field);

	mpz_mul(tmp, P->Y, P->Z);  	  	  	// Z3 = 2*Y1*Z1
	mpz_add(tmp1, tmp, tmp);
	mpz_mod(R->Z, tmp1, field);

	mpz_clear(a); mpz_clear(field);
	mpz_clear(XX); mpz_clera(YY); mpz_clear(ZZ); mpz_clear(S); mpz_clear(M); mpz_clear(T); mpz_clear(tmp); mpz_clear(tmp1);

	return R;
}


/** Add two elliptic curve points:
 * 	(X_1, Y_1, Z_1) + (X_2, Y_2, Z_2) = (X_3, Y_3, Z_3), where
 * 	X_3 = (Z_1^3 * Y_2 - Z_2^3 * Y_1)^2 - (Z_1^2 * X_2 - Z_2^2 * X_1)^3 -
 * 	2 * Z_2^2 * X_1 * (Z_1^2 * X_2 - Z_2^2 * X_1)^2
 * 	Y_3 = (Z_1^3 * Y_2 - Z_2^3 * Y_1) * (Z_2^2 * X_1 * (Z_1^2 * X_2 - Z_2^2 * X_1)^2 - X_3) -
 *        Z_2^3 * Y_1 * (Z_1^2 * X_2 - Z_2^2 * X_1)^3
 * 	Z_3 = (Z_1^2 * X_2 - Z_2^2 * X_1) * (Z_1 * Z_2)
 *
 * 	This runs faster if 'mixed' is set, which requires Z_2 = 1 or Z_2 = 0.
 */

/** This function is not entirely constant-time: it includes a branch for
 * 	checking whether the two input points are equal, (while not equal to the
 * 	point at infinity). This case never happens during single point
 * 	multiplication, so there is no timing leak for ECDH or ECDSA signing.
 */
ec_point_proj ec_point_proj_add(ec_point_proj P, ec_point_proj Q, ec_group ec) {
	mpz_t field, a;
	mpz_init_set(field, ec->field);
	mpz_init_set(a, ec->A);

	ec_point_proj R;
	// Initialize the point R
	R = ec_point_proj_init();
	mpz_t A, B, C, D, E, F, EEE, tmp, tmp1;
	mpz_init(A); mpz_init(B); mpz_init(C); mpz_init(D); mpz_init(E); mpz_init(F);
	mpz_init(EEE); mpz_init(tmp); mpz_init(tmp1);

	mpz_sqr(tmp, Q->Z);				// Z2^2
	mpz_mul(tmp1, P->X, tmp);		// A = X1 Z2^2
	mpz_mod(A, tmp1, field);

	mpz_mul(tmp1, tmp, Q->Z); 		// Z2^3
	mpz_mul(tmp, P->Y, tmp1);		// C = Y1 Z2^3
	mpz_mod(C, tmp, field);

	mpz_sqr(tmp, P->Z);				// Z1^2
	mpz_mul(tmp1, Q->X, tmp);		// B = X2 Z1^2
	mpz_mod(B, tmp1, field);

	mpz_mul(tmp1, tmp, P->Z); 		// Z1^3
	mpz_mul(tmp, Q->Y, tmp1);		// D = Y2 Z1^3
	mpz_mod(D, tmp, field);

	mod_sub(E, B, A, field);
	mod_sub(F, D, C, field);

	// B, D no longer use, so B = E^2, D = F2
	mpz_sqr(B, E, E); mpz_sqr(D, F, F);

	mpz_mul(EEE, E, B); 			// E^3
	mpz_mul(tmp, A, B);				// tmp = AE^2

	mpz_sub(tmp1, D, EEE);			// X3 = F^2 - E^3 - 2*AE^2
	mpz_sub(D, tmp1, tmp);
	mpz_sub(tmp1, D, tmp);
	mpz_mod(R->X, tmp1, field);

	mpz_sub(tmp1, tmp - R->X); 		// AE^2 - X3
	mpz_mul(tmp, F, tmp1);			// tmp = F(AE^2 - X3)
	mpz_mul(tmp1, C, EEE);
	mod_sub(R->Y, tmp, tmp1);

	mpz_mul(tmp, P->Z, Q->Z);
	mod_mul(R->Z, tmp, E, field);

	mpz_clear(a); mpz_clear(field);
	mpz_clear(A); mpz_clera(B); mpz_clear(C); mpz_clear(D); mpz_clear(E); mpz_clear(F);
	mpz_clear(EEE); mpz_clear(tmp); mpz_clear(tmp1);

	return R;
}

/**	Compute point multiplication
 * 	\param scalar	big number
 * 	\param P		pointer to an ec_point_proj structure
 * 	\param group	pointer to an ec_group structre
 * 	\return 		pointer to an ec_point_proj structure
 *
 */

/** This function is implemented by using Montgomery ladder, constant-time/power side channel
 *
 */
ec_point_proj ec_point_proj_mul(ec_point_proj P, mpz_t scalar, ec_group group) {
	mpz_t field, a;
	mpz_init_set(field, group->field);
	mpz_init_set(a, group->A);

	ec_point_proj R[2];
	// Initialize the point R
	R[0] = ec_point_proj_init();
	R[1] = ec_point_proj_init_set_mpz(P->X, P->Y, P->Z);

	int k = mpz_sizeinbase(scalar, 2); //Set k = bit length of the exponent

	int b, nb;
	for(int i = k - 1; i >= 0; i--) {
		b = mpz_tstbit(scalar, i);
		nb = 1 - b;

		ec_point_proj_add(R[nb], R[nb], R[b], group);
		ec_point_proj_dbl(R[b], R[b], group);
	}


	return R[0];
}
