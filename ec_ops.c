/*
 * arithECC.c
 *
 *  Created on: Sep 26, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec_point.h"
#include "field_ops.h"

/* Add two points P and Q in affine coordinates. If P = Q, perform a doubling, but in atomic principle
 *
 * Require:
 *
 * Input: P, Q
 * Output: R = P + Q. If P = Q, R = 2P
 *
 * ec: the elliptic curve
 *
 */
ec_point ec_point_add_atomic(ec_point P, ec_point Q, ec_group ec) {
	mpz_t field;
	mpz_init_set(field, ec->field);

	ec_point R;
	// Initialize the point R
	R = ec_point_init();


	//If Q is at infinity, set R to P
	if(Q->infinity) {
		ec_point_cpy(R, P);

	} else
		if(P->infinity){ //If P is at infinity set R to be Q
			ec_point_cpy(R, Q);
		} else
			if(ec_point_is_inverse(P, Q, field)) { // If P = -Q, return R be the point at infinity
				ec_point_set_at_infinity(R);
			} else {
				//Initialize slope variable lambda
				mpz_t lambda; mpz_init(lambda);
				//Initialize temporary variables
				mpz_t t1; mpz_init_set_str(t1, "1", 10);
				mpz_t t2; mpz_init(t2);
				mpz_t t3; mpz_init(t3);

				// Calculate lambda
				if (ec_point_cmp(P,Q, field)) { //If the points are the same use point doubling
					//R = point_doubling(P, ec);
					mod_sec_sqr(t1, P->x, field);
					mod_addadd(t2, t1, t1, t1, field);
					mod_add(t3, t2, ec->A, field);
					mod_add(t1,P->y,P->y, field);
				} else {
				// Calculate lambda: lambda = (Py - Qy)/(Px-Qx) mod p
					mod_sec_sqr(t1, t1, field); // dummy operation
					mod_addadd(t2, t1, t1, t1, field); // dummy operation
					mod_sub(t3, P->y, Q->y, field);
					mod_sub(t1, P->x, Q->x, field);
				}

				mod_sec_invert(t2, t1, field);
				mod_sec_mul(lambda, t3, t2, field);

				// Rx = lambda^2 - Px - Qx
				mod_sec_sqr(t1, lambda, field);
				mod_subsub(R->x, t1, P->x, Q->x, field);

				// Ry = lambda(Px - Rx) - Py mod p
				mod_sub(t1, P->x, R->x, field);
				mod_mulsub(R->y, t1, lambda, P->y, field);

				//Clear variables, release memory
				mpz_clear(t1); mpz_clear(t2); mpz_clear(t3); mpz_clear(lambda);
			}
	return R;
}

ec_point ec_point_dbl(ec_point P, ec_group ec) {
	mpz_t field;
	mpz_init_set(field, ec->field);

	ec_point R;
	// Initialize the point R
	R = ec_point_init();


	//If Q is at infinity, set R to P
	if(P->infinity) {
		ec_point_set_at_infinity(R);

	} else {
		//Initialize slope variable lambda
		mpz_t lambda; mpz_init(lambda);
		//Initialize temporary variables
		mpz_t t1; mpz_init_set_ui(t1, 1);
		mpz_t t2; mpz_init(t2);
		mpz_t t3; mpz_init(t3);

		// Calculate lambda = (3Px^2 + a)/2Py
		mod_sec_sqr(t1, P->x, field);
		mod_addadd(t2, t1, t1, t1, field);
		mod_add(t3, t2, ec->A, field);
		mod_add(t1,P->y,P->y, field);

		mod_sec_invert(t2, t1, field);
		mod_sec_mul(lambda, t3, t2, field);

		// Rx = lambda^2 - 2Px
		mod_sec_sqr(t1, lambda, field);
		mod_subsub(R->x, t1, P->x, P->x, field);

		// Ry = lambda(Px - Rx) - Py mod p
		mod_sub(t1, P->x, R->x, field);
		mod_mulsub(R->y, t1, lambda, P->y, field);

		//Clear variables, release memory
		mpz_clear(t1); mpz_clear(t2); mpz_clear(t3); mpz_clear(lambda);
	}
	return R;
}

ec_point ec_point_add(ec_point P, ec_point Q, ec_group ec) {
	mpz_t field;
	mpz_init_set(field, ec->field);

	ec_point R;
	// Initialize the point R
	R = ec_point_init();

	//If Q is at infinity, set R to P
	if(Q->infinity) {
		ec_point_cpy(R, P);

	} else
		if(P->infinity){ //If P is at infinity set R to be Q
			ec_point_cpy(R, Q);
		} else
			if(ec_point_is_inverse(P, Q, field)) { // If P = -Q, return R be the point at infinity
				ec_point_set_at_infinity(R);
			} else {
				//Initialize slope variable lambda
				mpz_t lambda; mpz_init(lambda);
				//Initialize temporary variables
				mpz_t t1; mpz_init(t1);
				mpz_t t2; mpz_init(t2);

				// Calculate lambda: lambda = (Py - Qy)/(Px-Qx) mod p
				mod_sub(t1, P->x, Q->x, field);
				mod_sec_invert(t2, t1, field);
				mod_sub(t1, P->y, Q->y, field);
				mod_sec_mul(lambda, t1, t2, field);

				// Rx = lambda^2 - Px - Qx
				mod_sec_sqr(t1, lambda, field);
				mod_subsub(R->x, t1, P->x, Q->x, field);

				// Ry = lambda(Px - Rx) - Py mod p
				mod_sub(t1, P->x, R->x, field);
				mod_mulsub(R->y, t1, lambda, P->y, field);

				//Clear variables, release memory
				mpz_clear(t1); mpz_clear(t2); mpz_clear(lambda);
			}
	return R;
}

/** Perform scalar multiplication to P, with the factor scalar on the curve curve EC
 *
 */
ec_point ecp_mul_atomic(ec_point P, mpz_t scalar, ec_group group) {

	ec_point Rop = ec_point_init();
	// Initialize R as the point at infinity, the neutral element of the group
	ec_point_set_at_infinity(Rop);

	if(!P->infinity) {
		//Initializing variables
		unsigned int k, b;
		ec_point R[2];

		R[0] = ec_point_init(); R[0]->infinity = true;
		R[1] = ec_point_dup(P);

		k = mpz_sizeinbase(scalar, 2);
		int i = k - 1; b = 0;

		while (i >= 0) {

			R[0] = ec_point_add_atomic(R[0], R[b], group);

			b = b ^ mpz_tstbit(scalar, i);
			i -= (1 - b);

		}

		ec_point_cpy(Rop, R[0]);

		//Release temporary variables
		ec_point_free(R[0]);
		ec_point_free(R[1]);
	}
	return Rop;

}

ec_point ecp_mul_montgomery(ec_point P, mpz_t scalar, ec_group group) {

	ec_point Rop = ec_point_init();
	// Initialize R as the point at infinity, the neutral element of the group
	ec_point_set_at_infinity(Rop);

	if(!P->infinity) {
		//Initializing variables
		int i, bit, ibit;
		ec_point R[2];

		R[0] = ec_point_init(); R[0]->infinity = true;
		R[1] = ec_point_dup(P);

		int k = mpz_sizeinbase(scalar, 2);

		for(i = k - 1; i >= 0; i--) {
			bit = mpz_tstbit(scalar, i); ibit = bit ^ 0x1;

			R[ibit] = ec_point_add(R[bit], R[ibit], group);
			R[bit] = ec_point_dbl(R[bit], group);
		}

		ec_point_cpy(Rop, R[0]);

		//Release temporary variables
		ec_point_free(R[0]);
		ec_point_free(R[1]);
	}
	return Rop;

}

/** Return a random bit
 *
 */
static int coin_toss() {

	return rand() & 0x1;
}

/** Compute modular exponentiation using repeated Montgomery powering ladder.
 * 	This algorithm can be used as a countermeasures to thwart timing, simple side-channel analysis and fault attack.
 * 	Proposed by Coron at CHES 1999
 *
 * 	@return: rop = base ^ exp mod N. Assume that base, exp, N > 0
 *
 */
ec_point ecp_mul_rand_montgomery(ec_point P, mpz_t scalar, ec_group group){

	ec_point Rop = ec_point_init();
	// Initialize R as the point at infinity, the neutral element of the group
	ec_point_set_at_infinity(Rop);

	if(!P->infinity) {
		//Initializing variables
		int i, k, bit, randbit, irandbit;
		ec_point R[2];

		R[0] = ec_point_init(); R[0]->infinity = true;
		srand(time(NULL)); //     <- srand() here, just ONCE

		randbit = coin_toss();
		if (! randbit)
			R[1] = ec_point_dup(P);
		else {
			R[1] = ec_point_init();
			R[1]->infinity = true;
		}

		k = mpz_sizeinbase(scalar, 2);

		for(i = k - 1; i >= 0; i--) {
			bit = mpz_tstbit(scalar, i);

			if (bit ^ randbit)
				randbit = coin_toss();
			irandbit = randbit ^ 0x1;

			R[randbit] = ec_point_add_atomic(R[0], R[randbit ^ bit], group);
			R[irandbit] = ec_point_add_atomic(R[randbit], P, group);
		}

		ec_point_cpy(Rop, R[0]);

		//Release temporary variables
		ec_point_free(R[0]);
		ec_point_free(R[1]);
	}

	return Rop;
}


/* Perform scalar multiplication to P, with the factor scalar on the curve curve EC
 *
 * Using the window method, but in silence mode to cached-based timing attacks on pre-computed table
 *
 */
ec_point ec_sec_wmul(ec_point P, mpz_t scalar, ec_group ec) {
	ec_point Ret = ec_point_init();
	// Initialize R as the point at infinity, the neutral element of the group
	ec_point_set_at_infinity(Ret);

	if(!P->infinity) {
		//Initializing variables
		unsigned int i, k, b;
		ec_point R[2];
		R[0] = ec_point_init(); R[0]->infinity = true;
		R[1] = ec_point_dup(P); 	//point_copy(t, x);

		k = mpz_sizeinbase(scalar, 2);
		i = k - 1; b = 0;

		while(i >= 0) {
			R[0] = ec_point_add_atomic(R[0], R[b], ec);

			b = b ^ mpz_tstbit(scalar, i);
			i -= (1 - b);
		}

		ec_point_cpy(Ret, R[0]);

		//Release temporary variables
		ec_point_free(R[0]);
		ec_point_free(R[1]);
	}
	return Ret;
}



/* Doubling a point in affine coordinates (Z = 1) on elliptic curve ec
 *
 * Input: point P
 * Output: R = 2P
 *
 * ec: elliptic curve
 */
/*
pt_point point_doubling(pt_point P, pt_curve ec) {
	pt_point R; R = point_init();

	//If at infinity
	if(P->infinity) 	{
		R->infinity = true;
	} else {
		//Initialize slope variable
		mpz_t s;mpz_init(s);
		//Initialize temporary variables
		mpz_t t1;mpz_init(t1);
		mpz_t t2;mpz_init(t2);
		mpz_t t3;mpz_init(t3);
		mpz_t t4;mpz_init(t4);
		mpz_t t5;mpz_init(t5);

		//Calculate slope
		//s = (3*Px² + a) / (2*Py) mod p
		number_theory_exp_modp_ui(t1, P->X, 2, ec->p);	//t1 = Px² mod p
		mpz_mul_ui(t2, t1, 3);				//t2 = 3 * t1
		mpz_mod(t3, t2, ec->p);			//t3 = t2 mod p
		mpz_add(t4, t3, ec->A);			//t4 = t3 + a
		mpz_mod(t5, t4, ec->p);			//t5 = t4 mod p

		mpz_mul_ui(t1, P->Y, 2);			//t1 = 2*Py
		number_theory_inverse(t2, t1, ec->p);		//t2 = t1^-1 mod p
		mpz_mul(t1, t5, t2);				//t1 = t5 * t2
		mpz_mod(s, t1, ec->p);			//s = t1 mod p

		//Calculate Rx
		//Rx = s² - 2*Px mod p
		number_theory_exp_modp_ui(t1, s, 2, ec->p);//t1 = s² mod p
		mpz_mul_ui(t2, P->X, 2);		//t2 = Px*2
		mpz_mod(t3, t2, ec->p);		//t3 = t2 mod p
		mpz_sub(t4, t1, t3);			//t4 = t1 - t3
		mpz_mod(R->X, t4, ec->p);	//Rx = t4 mod p

		//Calculate Ry using algorithm shown to the right of the commands
		//Ry = s(Px-Rx) - Py mod p
		mpz_sub(t1, P->X, R->X);			//t1 = Px - Rx
		mpz_mul(t2, s, t1);					//t2 = s*t1
		mpz_sub(t3, t2, P->Y);				//t3 = t2 - Py
		mpz_mod(R->Y, t3, ec->p);	//Ry = t3 mod p

		//Clear variables, release memory
		mpz_clear(t1);
		mpz_clear(t2);
		mpz_clear(t3);
		mpz_clear(t4);
		mpz_clear(t5);
		mpz_clear(s);
	}
}*/
