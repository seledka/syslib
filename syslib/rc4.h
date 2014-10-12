#ifndef SYSLIB_RC4_H_INCLUDED
#define SYSLIB_RC4_H_INCLUDED

#include "syslib_exp.h"

#ifdef __cplusplus
SYSLIBEXP(void) rc4Full(LPCVOID lpKey,WORD wKeySize,LPCVOID lpBuf,DWORD dwSize,LPVOID lpOut=NULL);
#else
SYSLIBEXP(void) rc4Full(LPCVOID lpKey,WORD wKeySize,LPCVOID lpBuf,DWORD dwSize,LPVOID lpOut);
#endif

SYSLIBEXP(LPBYTE) rc4FullEx(LPCVOID lpKey,WORD wKeySize,LPCVOID lpBuf,DWORD dwSize);

#endif // SYSLIB_RC4_H_INCLUDED
