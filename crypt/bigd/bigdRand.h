/* $Id: bigdRand.h $ */

/** @file
    Interface for BigDigits "bd" random number functions using a "pretty-good" internal RNG

@par The internal random number generator (RNG)
The internal RNG uses a variant of the random number generation algorithm 
in Appendix A of ANSI X9.31-1998, but using the Tiny Encryption Algorithm (TEAX)
instead of the Data Encryption Algorithm (DEA). 
It uses the current time and process ID as a seed. 
Although not strictly crypto secure, it is "pretty good", and certainly much better than
anything using the built-in rand() function in C. Look at the source code and make your own call.

@par 
If you want proper cryptographic security, use the bdRandomSeeded() function with a call to a
secure RNG function that you trust.
*/

/******************** SHORT COPYRIGHT NOTICE**************************
This source code is part of the BigDigits multiple-precision
arithmetic library Version 2.4 originally written by David Ireland,
copyright (c) 2001-13 D.I. Management Services Pty Limited, all rights
reserved. It is provided "as is" with no warranties. You may use
this software under the terms of the full copyright notice
"bigdigitsCopyright.txt" that should have been included with this
library or can be obtained from <www.di-mgt.com.au/bigdigits.html>.
This notice must always be retained in any copy.
******************* END OF COPYRIGHT NOTICE***************************/
/*
	Last updated:
	$Date: 2013-04-27 17:19:00 $
	$Revision: 2.4.0 $
	$Author: dai $
*/

#ifndef BIGDRAND_H_
#define BIGDRAND_H_ 1

#include "bigd.h"
#include "bigdRand.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Generate a single random digit using internal RNG. */
bdigit_t bdRandDigit(void);

/** Generate a random BIGD number of bit length at most \c nbits using internal RNG
@param[out] a to receive generated random number
@param[in]  nbits maximum number of bits
@returns Number of digits actually set  
*/
size_t bdRandomBits(BIGD a, size_t nbits);

/* Added in [v2.4] */
/** Generate array of random octets (bytes) using internal RNG
 *  @remarks This function is in the correct form for BD_RANDFUNC. 
 */ 
int bdRandomOctets(unsigned char *bytes, size_t nbytes, const unsigned char *seed, size_t seedlen);

/** Generate a number at random from a uniform distribution in [0, n-1] */
size_t bdRandomNumber(BIGD a, BIGD n);

#ifdef __cplusplus
}
#endif

#endif /* BIGDRAND_H_ */
