#ifndef SYSLIB_HASH_H_INCLUDED
#define SYSLIB_HASH_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(BOOL) hash_CalcMD5(const LPBYTE lpData,DWORD dwSize,LPBYTE lpOut);
SYSLIBEXP(BOOL) hash_CalcMD6(const LPBYTE lpData,DWORD dwSize,LPBYTE lpOut);
SYSLIBEXP(BOOL) hash_CalcSHA1(const LPBYTE lpData,DWORD dwLen,LPBYTE lpHash);
SYSLIBEXP(BOOL) hash_CalcSHA512(const LPBYTE lpData,DWORD dwLen,LPBYTE lpHash);

#ifdef __cplusplus
struct MD5_CTX
{
    unsigned long state[4];
    unsigned long count[2];
    unsigned char buffer[64];
};

namespace SYSLIB
{
    void MD5Init(MD5_CTX *context);
    void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputLen);
    void MD5Final(unsigned char digest[16],MD5_CTX *context);
};

struct SHA1_CTX
{
  DWORD H[5];
  DWORD W[80];
  int lenW;
  DWORD sizeHi, sizeLo;
};

namespace SYSLIB
{
    void SHA1Init(SHA1_CTX *ctx);
    void SHA1Update(SHA1_CTX *ctx, LPBYTE dataIn, int len);
    void SHA1Finish(SHA1_CTX *ctx, byte hashout[20]);
};
#endif

#endif // SYSLIB_HASH_H_INCLUDED
