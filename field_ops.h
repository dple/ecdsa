/*
 * arithFp.h
 *
 *  Created on: Sep 10, 2015
 *      Author: tslld
 */

#ifndef FIELD_OPS_H_
#define FIELD_OPS_H_

/* Perform modular operations: multiplication, square, inverse */
void mod_neg(mpz_t R, mpz_t A, mpz_t N);
void mod_sec_add(mpz_t R, mpz_t A, mpz_t B, mpz_t N);
void mod_addadd(mpz_t R, mpz_t A, mpz_t B, mpz_t C, mpz_t N);

void mod_sub(mpz_t R, mpz_t A, mpz_t B, mpz_t N);
void mod_subsub(mpz_t R, mpz_t A, mpz_t B, mpz_t C, mpz_t N);

void mod_mul(mpz_t R, mpz_t A, mpz_t B, mpz_t N);
void mod_mul_si(mpz_t R, mpz_t A, long int b, mpz_t N);
void mod_mul_ui(mpz_t R, mpz_t A, unsigned long int b, mpz_t N);
void mod_mulsub(mpz_t R, mpz_t A, mpz_t B, mpz_t C, mpz_t N);

void mod_sqr(mpz_t R, mpz_t A, mpz_t N);
int mod_invert(mpz_t R, mpz_t A, mpz_t N);

/* Perform a modular operations in data-independent time */
void mod_add(mpz_t R, mpz_t A, mpz_t B, mpz_t N);
void mod_sec_sub(mpz_t R, mpz_t A, mpz_t B, mpz_t N);
void mod_sec_mul(mpz_t R, mpz_t A, mpz_t B, mpz_t N);
void mod_sec_sqr(mpz_t R, mpz_t A, mpz_t N);
int mod_sec_invert(mpz_t R, mpz_t A, mpz_t N);

/* Number theory functions */
void mod_sqrt(mpz_t R, mpz_t A, mpz_t N);

/* Compute base ^ exp mod N, using left-to-right square-and-multiply always algorithm */
void modexp_multiply_always(mpz_t rop, mpz_t base, mpz_t exp, mpz_t N);

/* Compute base ^ exp mod N, using atomicity algorithm */
void modexp_atomic(mpz_t rop, mpz_t base, mpz_t exp, mpz_t N);

/* Compute base ^ exp mod N, using Montgomery powering ladder */
void modexp_montgomery_ladder(mpz_t rop, mpz_t rop2, mpz_t base, mpz_t exp, mpz_t N);

/** Randomized Montgomery powering ladder.
 * 	Can be used to prevent power analysis in horizontal setting
 */
void modexp_rand_montgomery_ladder(mpz_t rop, mpz_t base, mpz_t exp, mpz_t N);


/* Secure window-based modular exponentiation against side channel analysis */
void modexp_window(mpz_t rop, mpz_t base, mpz_t exp, mpz_t N);

#endif /* FIELD_OPS_H_ */
