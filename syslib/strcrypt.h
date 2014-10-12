#ifndef SYSLIB_STRCRYPT_H_INCLUDED
#define SYSLIB_STRCRYPT_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(LPCSTR) DecryptStringA(LPCSTR lpCrypedString,DWORD dwLen,DWORD dwKey);
SYSLIBEXP(LPCWSTR) DecryptStringW(LPCSTR lpCrypedString,DWORD dwLen,DWORD dwKey);

#ifdef UNICODE
#define DecryptString DecryptStringW
#else
#define DecryptString DecryptStringA
#endif

#endif // SYSLIB_STRCRYPT_H_INCLUDED
