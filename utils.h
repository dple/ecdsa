/*
 * utils.h
 *
 *  Created on: Apr 14, 2011
 *      Author: dple
 */

#ifndef UTILS_H_
#define UTILS_H_


/*
 * Useful functions for integer
 */
char trapkey(void);
int getNumber();

// Accepts a decimal integer and returns a binary coded string
char* dectobin(long i);

// Show a decimal number in binary
void showbits(int h);

// Count the number of 1-bits, the Hamming weight for an integer
int hammingWeight(unsigned int n);

 // Count the number of bits
int bitcount(unsigned int n);

// If the bit at position pos is 1, function return true. Else return false
bool bit(int n, int pos);

// Extract a chain of bit from a number n
int extract(int n, int tail, int size);

/*
 * Useful functions for gmp integers
 */
int bitlength(mpz_t x);
bool mod_is_zero(mpz_t x, mpz_t mod);


/*
#ifndef __linux__
	#undef USE_GMP
#endif
#ifdef USE_GMP
#include <gmpxx.h>
#endif

#ifdef _MSC_VER
	typedef unsigned __int64 uint64;
	typedef __int64 sint64;
#else
	typedef unsigned long long uint64;
	typedef long long sint64;
#endif
typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;
*/

/*
#ifdef _WIN32

#include <time.h>

static inline double GetCurrTime();
#else

#include <sys/time.h>
#include <stdio.h>

static inline double GetCurrTime();
#endif

static inline uint64 getRdtsc();
*/


#endif /* UTILS_H_ */
