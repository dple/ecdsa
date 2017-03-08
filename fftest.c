/*
 * Fptest.c
 *
 *  Created on: Oct 29, 2015
 *      Author: tslld
 */

#include<stdio.h>
#include<gmp.h>
#include"field_ops.h"

// Values represented in hex string
static char* field[] = {
		"11",	// 17
		"17",	// 23
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001"	// GF of curve secp224k1
};

static char* op1[] = {
		"9",	//
		"8",	// 8
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE"
};

static char* op2[] = {
		"B",
		"11",	// 17
		"B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4"
};

static char* Radd[] = {
		"3",
		"2",	// 2
		"B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB1"
};

static char* Rsub[] = {
		"F",
		"E",	// 14
		"4BFAF57AF3FB4C540ABECDA9AFBB4F4728402745D8F4C6BCDCAA004A"
};

static char* Rmul[] = {
		"E",
		"15",	// 21
		"E3F0E070DBF1E4FC203C68FD0F31EDD578C075D18ADE543695FE00E7"
};
static char* Rinv[] = {
		"2",
		"3",	// 3
		"55555555555555555555555555555555000000000000000000000000"
};

static char* Rexp[] = {
		"F",
		"D",	// 3
		"5503EADDBE959F1392D758B763260B5CE839ED865F22A33AB60166A5"
};


static void GF_add_test(mpz_t R, mpz_t a, mpz_t b, mpz_t field) {
	fprintf(stdout, "Modular addition checking ...\n");
	mpz_t Rop; mpz_init(Rop);

	mod_sec_add(Rop, a, b, field);

	if (mpz_cmp(Rop, R) == 0)
		fprintf(stdout, "passed ! \n");
	else
		fprintf(stdout, "failed ! \n");
	mpz_clear(Rop);
}


static void GF_sub_test(mpz_t R, mpz_t a, mpz_t b, mpz_t field) {
	fprintf(stdout, "Modular subtraction checking ...\n");
	mpz_t Rop; mpz_init(Rop);

	mod_sec_sub(Rop, a, b, field);

	if (mpz_cmp(Rop, R) == 0)
		fprintf(stdout, "passed ! \n");
	else
		fprintf(stdout, "failed ! \n");
	mpz_clear(Rop);
}

static void GF_mul_test(mpz_t R, mpz_t a, mpz_t b, mpz_t field) {
	fprintf(stdout, "Modular multiplication checking ...\n");
	mpz_t Rop; mpz_init(Rop);

	mod_sec_mul(Rop, a, b, field);

	if (mpz_cmp(Rop, R) == 0)
		fprintf(stdout, "passed ! \n");
	else
		fprintf(stdout, "failed ! \n");
	mpz_clear(Rop);
}

static void GF_inv_test(mpz_t R, mpz_t a, mpz_t field) {
	fprintf(stdout, "Modular inversion checking ...\n");
	mpz_t Rop; mpz_init(Rop);

	mod_sec_invert(Rop, a, field);

	if (mpz_cmp(Rop, R) == 0)
		fprintf(stdout, "passed ! \n");
	else
		fprintf(stdout, "failed ! \n");
	mpz_clear(Rop);
}

static void GF_exp_test(mpz_t R, mpz_t a, mpz_t b, mpz_t field) {
	fprintf(stdout, "Modular exponentiation checking ...\n");
	mpz_t Rop, Rop2; mpz_init(Rop); mpz_init(Rop2);

	//modexp_atomic(Rop, a, b, field);
	//modexp_montgomery_ladder(Rop, Rop2, a, b, field);
	modexp_rand_montgomery_ladder(Rop, a, b, field);

	if (mpz_cmp(Rop, R) == 0)
		fprintf(stdout, "passed ! \n");
	else
		fprintf(stdout, "failed ! \n");
	mpz_clear(Rop); mpz_clear(Rop2);
}


int main(int agrc, char* argv[]) {
	int i;
	mpz_t a, b, Ra, Rs, Rm, Ri, Re, mod;
	mpz_init(a); mpz_init(b); mpz_init(Ra); mpz_init(Rs); mpz_init(Rm); mpz_init(Ri); mpz_init(Re); mpz_init(mod);

	fprintf(stdout, "\nVerifying the finite field operations ...\n");

	for (i = 0; i < 3; i++) {
		fprintf(stdout, "\nChecking the prime finite field GF(p), where p = 0x%s\n", field[i]);
		mpz_set_str(mod, field[i], 16);
		mpz_set_str(a, op1[i], 16);
		mpz_set_str(b, op2[i], 16);
		mpz_set_str(Ra, Radd[i], 16);
		mpz_set_str(Rs, Rsub[i], 16);
		mpz_set_str(Rm, Rmul[i], 16);
		mpz_set_str(Ri, Rinv[i], 16);
		mpz_set_str(Re, Rexp[i], 16);

		GF_add_test(Ra, a, b, mod);
		GF_sub_test(Rs, a, b, mod);
		GF_mul_test(Rm, a, b, mod);
		GF_inv_test(Ri, a, mod);
		GF_exp_test(Re, a, b, mod);
	}

	mpz_clear(a); mpz_clear(b); mpz_clear(Ra); mpz_clear(Rs); mpz_clear(Rm); mpz_clear(Ri); mpz_clear(mod);

	return 1;
}
