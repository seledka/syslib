#ifndef SYSLIB_CHKSUM_H_INCLUDED
#define SYSLIB_CHKSUM_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(DWORD) chksum_crc32(LPBYTE lpData,DWORD dwSize);

SYSLIBEXP(DWORD) GetFileChecksumA(LPCSTR lpFileName);
SYSLIBEXP(DWORD) GetFileChecksumW(LPCWSTR lpFileName);

#ifdef UNICODE
#define GetFileChecksum GetFileChecksumW
#else
#define GetFileChecksum GetFileChecksumA
#endif

SYSLIBEXP(DWORD) MurmurHash3(LPBYTE lpData,DWORD dwSize);

#endif // SYSLIB_CHKSUM_H_INCLUDED
