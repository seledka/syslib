/* $Id: bigdigitsRand.h $ */

/** @file
    Interface for BigDigits "mp" random number functions using a "pretty-good" internal RNG
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

/*	[v2.2] changed name from spRandom to bigdigitsRand */

#ifndef BIGDIGITSRAND_H_
#define BIGDIGITSRAND_H_ 1

#include "bigdigits.h"

#ifdef __cplusplus
extern "C" {
#endif

/**	Returns a "better" pseudo-random digit using internal RNG. */
DIGIT_T spBetterRand(void);

/** Generate a random mp number of bit length at most \c nbits using internal RNG 
@param[out] a to receive generated random number
@param[in]  ndigits number of digits in a
@param[in]  nbits maximum number of bits
@returns Number of digits actually set 
*/
size_t mpRandomBits(DIGIT_T a[], size_t ndigits, size_t nbits);

/* Added in [v2.4] */
/** Generate array of random octets (bytes) using internal RNG
 *  @remarks This function is in the correct form for BD_RANDFUNC to use in bdRandomSeeded(). 
  * \c seed is ignored. */
int mpRandomOctets(unsigned char *bytes, size_t nbytes, const unsigned char *seed, size_t seedlen);

#ifdef __cplusplus
}
#endif

#endif /* BIGDIGITSRAND_H_ */
