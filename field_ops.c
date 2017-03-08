/*
 * arithFp.c
 *
 *  Created on: Sep 10, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "field_ops.h"

/** Verify whether x = 0 mod N
 *	\param
 *	\param
 *	\return
 *
 */
bool mod_is_zero(mpz_t x, mpz_t N) {

	return !mpz_cmp(x, 0) || !mpz_cmp(x, N);
}

/* Compute a modular negative element, R = -A mod N
 *
 * Require: all element were initialized and A < N
 *
 */
void mod_neg(mpz_t R, mpz_t A, mpz_t N){
	mpz_sub(R, N, A);
}

/*
 * Compute a modular addition. Require: all element were initialized
 *
 * Input: A, B, N where A, B < N
 * Output: R = A + B mod N
 */
void mod_add(mpz_t R, mpz_t A, mpz_t B, mpz_t N) {
	mpz_add(R, A, B);
	if (mpz_cmp(R, N) > 0){
		mpz_sub(R, R, N);
	}
	//mpz_mod(R, R, N); //mpz_set(R, A);
}

/** Secure compute modular addition. Silent from timing analysis
 *
 */
void mod_sec_add(mpz_t R, mpz_t A, mpz_t B, mpz_t N) {
	mpz_t T[2];
	mpz_init(T[0]); mpz_init(T[1]);

	mpz_add(T[0], A, B);
	mpz_sub(T[1], T[0], N);

	int i = mpz_sgn(T[1]);
	i = (i & 0xF) % 0xF;
	mpz_set(R, T[i]);
	mpz_clear(T[0]); mpz_clear(T[1]);
}

/*
 * Compute a modular addition. Require: all element were initialized
 *
 * Input: A, B, C, N where A, B, C < N
 * Output: R = A + B + C mod N
 */
void mod_addadd(mpz_t R, mpz_t A, mpz_t B, mpz_t C, mpz_t N) {
	mpz_add(R, A, B);
	mpz_add(R, R, C);
	while (mpz_cmp(R, N) > 0){
		mpz_sub(R, R, N);
	}
}

/*
 * Compute a modular subtraction. Require: all element were initialized.
 *
 * Input: A, B, N where A, B < N
 * Output: R = A - B mod N
 */
void mod_sub(mpz_t R, mpz_t A, mpz_t B, mpz_t N) {

	if (mpz_cmp(A, B) >= 0)
		mpz_sub(R, A, B);
	else {
		mpz_add(R, A, N);
		mpz_sub(R, R, B);
	}
}

void mod_sec_sub(mpz_t R, mpz_t A, mpz_t B, mpz_t N) {
	mpz_t T[2];
	mpz_init(T[0]); mpz_init(T[1]);

	mpz_sub(T[1], A, B);
	mpz_add(T[0], T[1], N);

	int mask = mpz_sgn(T[1]);
	mask = (mask & 0xF) % 0xF;

	mpz_set(R, T[mask]);
	mpz_clear(T[0]); mpz_clear(T[1]);
}

/** Compute a modular subtraction. Require: all element were initialized.
 *
 * 	\params A, B, C, N where A, B, C < N
 * 	\return R = A - B - C mod N
 */
void mod_subsub(mpz_t R, mpz_t A, mpz_t B, mpz_t C, mpz_t N) {
	mpz_t tmp; mpz_init(tmp);

	if (mpz_cmp(A, B) >= 0) {
		mpz_sub(tmp, A, B);
		if (mpz_cmp(tmp, C) >= 0)
			mpz_sub(R, tmp, C);
		else {
			mpz_add(tmp, tmp, N);
			mpz_sub(R, tmp, C);
		}
	}
	else if (mpz_cmp(A, C) >= 0) {
		mpz_sub(tmp, A, C);
		mpz_add(tmp, tmp, N);
		mpz_sub(R, tmp, B);
	}
	else {
		mod_add(tmp, B, C, N);
		mod_sub(R, A, tmp, N);
	}
	mpz_clear(tmp);
}

/*
 * Compute a modular multiplication
 *
 * Require all element were initialized
 *
 * Input: A, B, N where A, B < N
 * Output: R = A x B mod N
 */
void mod_mul(mpz_t R, mpz_t A, mpz_t B, mpz_t N) {
	mpz_mul(R, A, B);
	mpz_mod(R, R, N); // mpz_set(R, A);
}

/**	Compute 4 * A
 *
 */
void mod_4mul(mpz_t R, mpz_t A, mpz_t N) {
	mpz_t tmp; mpz_init(tmp);
	mpz_add(R, A, A);
	mpz_add(tmp, R, R);
	mpz_mod(R, tmp, N);
	mpz_clear(tmp);
}

/**	Compute 8 * A
 *
 */
void mod_8mul(mpz_t R, mpz_t A, mpz_t N) {
	mpz_t tmp; mpz_init(tmp);
	mpz_add(tmp, A, A);
	mpz_add(R, tmp, tmp);
	mpz_add(tmp, R, R);
	mpz_mod(R, tmp, N);
	mpz_clear(tmp);
}


/*
 * Compute a modular multiplication, in data-independent time
 */
void mod_sec_mul(mpz_t R, mpz_t A, mpz_t B, mpz_t N) {
	//mpz_sec_mul(A, A, B);
	mpz_mul(R, A, B);
	mpz_mod(R, R, N); //	mpz_set(R, A);
}

/*
 * Compute a modular multiplication between a mpz_t and long integer
 *
 * Require all element were initialized
 *
 * Input: A, B, N where A, B < N
 * Output: R = A x B mod N
 */
void mod_mul_si(mpz_t R, mpz_t A, long int b, mpz_t N) {
	mpz_mul_si(R, A, b);
	mpz_mod(R, R, N); // mpz_set(R, A);
}

/*
 * Compute a modular multiplication between a mpz_t and unsigned long integer
 *
 * Require all element were initialized
 *
 * Input: A, B, N where A, B < N
 * Output: R = A x B mod N
 */
void mod_mul_ui(mpz_t R, mpz_t A, unsigned long int b, mpz_t N) {
	mpz_mul_ui(R, A, b);
	mpz_mod(R, R, N); // mpz_set(R, A);
}

/* Compute R = A*B - C mod N */
void mod_mulsub(mpz_t R, mpz_t A, mpz_t B, mpz_t C, mpz_t N) {
	mpz_t tmp; mpz_init(tmp);
	mpz_mul(tmp, A, B);
	if (mpz_cmp(tmp, N) <= 0)
		mod_sub(R, tmp, C, N);
	else {
		mpz_sub(R, tmp, C);
		mpz_mod(R, R, N);
	}
}

/*
 * Compute a modular square. Require all element were initialized
 *
 * Input: A, N where A < N
 * Output: R = A^2 mod N
 */
void mod_sqr(mpz_t R, mpz_t A, mpz_t N) {
	mod_mul(R, A, A, N);

}

/*
 * Compute a modular square, in data-independent time
 */

void mod_sec_sqr(mpz_t R, mpz_t A, mpz_t N) {
	mod_sec_mul(R, A, A, N);
}

/*
 * Compute a modular inverse. Return 1 on success, and 0 on failure. Modulus N must be odd
 *
 * Require all element were initialized
 *
 * Input: A, N
 * Output: R = A^{-1} mod N
 */
int mod_invert(mpz_t R, mpz_t A, mpz_t N) {

	if (UNLIKELY (mpz_tstbit(N, 0) == 0)) {
		printf("Modulus N must be odd. DIVIDE BY ZERO !\n");
		return 0;
	}
	return mpz_invert(R, A, N);

}

/* Perform a modular inverse, in data-independent time */
/*int mod_sec_invert(mpz_t R, mpz_t A, mpz_t N) {

	if (UNLIKELY (mpz_tstbit(N, 0) == 0)) {
		printf("Modulus N must be odd. DIVIDE BY ZERO !\n");
		return 0;
	}
	// return mpz_sec_invert(R, A, N);
	return mpz_invert(R, A, N);
}*/

/** Perform a modular inverse R = A^{-1} mod P, in data-independent time using the little Fermat theorem
 *	\param R 	return value
 *	\param A 	big number to be inverted
 *	\pram  P	modulus
 */
void mod_Fermat_invert(mpz_t R, mpz_t A, mpz_t P) {
	mpz_t E;
	mpz_init(E);
	mpz_sub_ui(E, E, 2);
	modexp_atomic(R, A, E, P);
	mpz_clear(E);
}

/** Perform a modular inverse R = A^{-1} mod P, using the extended Euclidean algorithm
 *	Require order must be prime
 *	\param R	return value
 *	\param A
 *	\param
 *
 *	\return
 */
int mod_sec_invert(mpz_t R, mpz_t A, mpz_t P) {
	//Initialize variables
	mpz_t a;mpz_init(a);
	mpz_t b;mpz_init(b);
	mpz_t q;mpz_init(q);
	mpz_t r;mpz_init(r);
	mpz_t x;mpz_init(x);
	mpz_t lastx;mpz_init(lastx);
	mpz_t y;mpz_init(y);
	mpz_t lasty;mpz_init(lasty);
	mpz_t t1;mpz_init(t1);
	mpz_t t2;mpz_init(t2);

	//Copy b, since we don't want to alter P or A
	mpz_set(b, P);
	mpz_set(a, A);

	//Set variables
	mpz_set_ui(x, 0);
	mpz_set_ui(y, 1);
	mpz_set_ui(lastx, 1);
	mpz_set_ui(lasty, 0);

	//while b != 0
	while(mpz_sgn(b) != 0) {
		//r = a mod b;
		mpz_mod(r, a, b);

		//q = (a - r)/b
		mpz_sub(t1, a, r);
		mpz_divexact(q,t1,b);

		mpz_set(a, b);

		//temp := x
		//x := lastx-quotient*x
		//lastx := temp
		mpz_set(t1, x);
		mpz_mul(t2, q, x);
		mpz_sub(x, lastx, t2);
		mpz_mod(lastx, t1, P);//We must keep it mod p, so why not just do it where instead of using set

		//temp := y
		//y := lasty-quotient*y
		//lasty := temp
		mpz_set(t1, y);
		mpz_mul(t2, q, y);
		mpz_sub(y, lasty, t2);
		mpz_mod(lasty, t1, P);//We must keep it mod p, so why not just do it where instead of using set

		//Set b = r
		mpz_set(b, r);
	}
	/*d = a, greatest common divisitor
	 *lastx = x
	 *lasty = y
	 *in d = a*x+b*y
	 *Thus x is the multiplicative inverse of a mod b
	 *if d = 1, since otherwise there's no mulitplicative inverse.
	 *But when b is a prime, a must be coprime thus d=1
	 */

	//Set the result
	mpz_set(R, lastx);

	//Clear variables
	mpz_clear(a); mpz_clear(b); mpz_clear(r); mpz_clear(q); mpz_clear(x);
	mpz_clear(y); mpz_clear(lastx); mpz_clear(lasty); mpz_clear(t1); mpz_clear(t2);
	return 1;

}

void mod_sqrt(mpz_t R, mpz_t A, mpz_t N) {

}

/*
 * Compute modular exponentiation using repeated L-to-R square-and-multiply always algorithm
 *
 * This algorithm can be used as a countermeasures to thwart timing and simple side-channel analysis attack
 *
 * Proposed by Coron at CHES 1999
 *
 * Input: a base, an exponent exp and a modulus N
 * Output: rop = base ^ exp mod N. Assume that base, exp, N > 0
 *
 */

void modexp_multiply_always(mpz_t rop, mpz_t base, mpz_t exp, mpz_t N){

	int i, b;
	mpz_t R[2];
	mp_size_t k;

	k = mpz_sizeinbase(exp, 2); //Set k = bit length of the exponent

	if (UNLIKELY ((k == 0) || (mpz_tstbit(N, 0) == 0))) {
		printf("Invalid modulus. DIVIDE BY ZERO !\n");
		return;
	}

	mpz_init_set(R[0], base); mpz_init_set(R[1], base);

	for(i = k - 2; i >= 0; i--) {

		mpz_mul(R[0], R[0], R[0]);
		mpz_mod(R[0], R[0], N);

		b = 1 - mpz_tstbit(exp,i);

		mpz_mul(R[b], R[0], base);
		mpz_mod(R[b], R[b], N);
	}

	mpz_set(rop, R[0]);
	mpz_clear(R[0]);mpz_clear(R[1]);
}

/*
 * Compute base ^ exp mod N, using atomicity algorithm
 *
 * This algorithm can be used as a countermeasures to thwart timing and simple side-channel analysis attack
 *
 * @return: rop = base ^ exp mod N. Assume that base, exp, N > 0
 *
 */
void modexp_atomic(mpz_t rop, mpz_t base, mpz_t exp, mpz_t N){

	int i, k, b;
	mpz_t R[2];

	k = mpz_sizeinbase(exp, 2); //Set t = bit length

	if (UNLIKELY ((k == 0) || (mpz_tstbit(N, 0) == 0))) {
		printf("Invalid modulus. DIVIDE BY ZERO !\n");
		return;
	}

	i = k - 1; mpz_init_set_ui(R[0], 1); mpz_init_set(R[1], base);
	b = 0;

	while(i >= 0) {
		mpz_mul(R[0], R[0], R[b]);
		mpz_mod(R[0], R[0], N);

		b = b ^ mpz_tstbit(exp,i);
		i -= (1 - b);
	}

	mpz_set(rop, R[0]);
	mpz_clear(R[0]); mpz_clear(R[1]);

}

/*
 * Copy in constant time: if icopy == 1, copy in to out, if icopy == 0, copy
 * out to itself.
 */
void copy_conditional(mpz_t out, const mpz_t in, int icopy) {
    unsigned i;
    /*
     * icopy is a (64-bit) 0 or 1, so copy is either all-zero or all-one
     */
    mpz_t copy; mpz_init(copy); //mpz_neg(copy, icopy);
    mpz_t tmp; mpz_init(tmp);
    for (i = 0; i < 4; ++i) {
        //tmp = copy & (in[i] ^ out[i]);
        //out[i] ^= tmp;
    }
    mpz_clear(copy);mpz_clear(tmp);
}

/** Return a random bit
 *
 */
static int coinToss() {

	return rand() & 0x1;
}

/** Compute modular exponentiation using repeated Montgomery powering ladder.
 * 	This algorithm can be used as a countermeasures to thwart timing, simple side-channel analysis and fault attack.
 * 	Proposed by Coron at CHES 1999
 *
 * 	@return: rop = base ^ exp mod N. Assume that base, exp, N > 0
 *
 */
void modexp_rand_montgomery_ladder(mpz_t rop, mpz_t base, mpz_t exp, mpz_t N){

	int i, k, bit, randbit, irandbit;
	mpz_t R[2];

	k = mpz_sizeinbase(exp, 2); //Set k = bit length of the exponent

	if (UNLIKELY ((k == 0) || (mpz_tstbit(N, 0) == 0))) {
		printf("Invalid modulus. DIVIDE BY ZERO !\n");
		return;
	}

	mpz_init_set_ui(R[0], 1);
	srand(time(NULL)); //     <- srand() here, just ONCE

	randbit = coinToss();

	if (! randbit)
		mpz_init_set(R[1], base);
	else
		mpz_init_set_ui(R[1], 1);

	for(i = k - 1; i >= 0; i--) {
		bit = mpz_tstbit(exp,i);

		if (bit ^ randbit)
			randbit = coinToss();

		mpz_mul(R[randbit], R[0], R[randbit ^ bit]);
		mpz_mod(R[randbit], R[randbit], N);

		irandbit = randbit ^ 0x1;

		mpz_mul(R[irandbit], R[randbit], base);
		mpz_mod(R[irandbit], R[irandbit], N);
	}

	mpz_set(rop, R[0]);
	mpz_clear(R[0]);mpz_clear(R[1]);
}

/** Implementing the randomized Montgomery powering ladder proposed in WISTP 2015
 *
 */
void modexp_montgomery_ladder(mpz_t rop, mpz_t rop2, mpz_t base, mpz_t exp, mpz_t N){

	int i, k, bit, ibit;
	mpz_t R[2];

	k = mpz_sizeinbase(exp, 2); //Set k = bit length of the exponent

	if (UNLIKELY ((k == 0) || (mpz_tstbit(N, 0) == 0))) {
		printf("Invalid modulus. DIVIDE BY ZERO !\n");
		return;
	}

	mpz_init_set_ui(R[0], 1);
	mpz_init_set(R[1], base);

	for(i = k - 1; i >= 0; i--) {
		bit = mpz_tstbit(exp,i); ibit = bit ^ 0x1;

		mpz_mul(R[ibit], R[ibit], R[bit]);
		mpz_mod(R[ibit], R[ibit], N);

		mpz_mul(R[bit], R[bit], R[bit]);
		mpz_mod(R[bit], R[bit], N);
	}

	mpz_set(rop, R[0]);mpz_set(rop2, R[1]);
	mpz_clear(R[0]);mpz_clear(R[1]);
}


/* Secure window-based modular exponentiation against side channel analysis */
void modexp_window(mpz_t rop, mpz_t base, mpz_t exp, mpz_t N) {

	mpz_powm_sec(rop, base, exp, N);
}


