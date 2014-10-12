#ifndef SYSLIB_RSA_H_INCLUDED
#define SYSLIB_RSA_H_INCLUDED

#include "syslib_exp.h"

typedef LPVOID RSA_KEY;

SYSLIBEXP(BOOL) RSA_KeyGen(DWORD dwBitsCount,RSA_KEY *lppPrivKey,RSA_KEY *lppPubKey);

SYSLIBEXP(DWORD) RSA_CryptBuffer(RSA_KEY rsaKey,LPBYTE lpBufIn,DWORD dwBufSize,LPBYTE *lppBufOut);
SYSLIBEXP(DWORD) RSA_CryptBufferFull(RSA_KEY rsaKey,LPBYTE lpBufIn,DWORD dwBufSize,LPBYTE *lppBufOut);

SYSLIBEXP(BOOL) RSA_CryptFileW(RSA_KEY rsaKey,LPCWSTR lpFileIn,LPCWSTR lpFileOut);
SYSLIBEXP(BOOL) RSA_CryptFileA(RSA_KEY rsaKey,LPCSTR lpFile,LPCSTR lpFileOut);

#ifdef UNICODE
#define RSA_CryptFile RSA_CryptFileW
#else
#define RSA_CryptFile RSA_CryptFileA
#endif


SYSLIBEXP(BOOL) RSA_SignBuffer(RSA_KEY rsaPrivKey,LPBYTE lpBufIn,DWORD dwBufSize,LPBYTE lpSign);

SYSLIBEXP(BOOL) RSA_SignFileW(RSA_KEY rsaPrivKey,LPCWSTR lpFile,LPBYTE lpSign);
SYSLIBEXP(BOOL) RSA_SignFileA(RSA_KEY rsaPrivKey,LPCSTR lpFile,LPBYTE lpSign);

#ifdef UNICODE
#define RSA_SignFile RSA_SignFileW
#else
#define RSA_SignFile RSA_SignFileA
#endif


SYSLIBEXP(DWORD) RSA_DecryptBuffer(RSA_KEY rsaKey,LPBYTE lpBufIn,DWORD dwBufSize,LPBYTE *lppBufOut);
SYSLIBEXP(DWORD) RSA_DecryptBufferFull(RSA_KEY rsaKey,LPBYTE lpBufIn,DWORD dwBufSize,LPBYTE *lppBufOut);

SYSLIBEXP(BOOL) RSA_DecryptFileW(RSA_KEY rsaKey,LPCWSTR lpFileIn,LPCWSTR lpFileOut);
SYSLIBEXP(BOOL) RSA_DecryptFileA(RSA_KEY rsaKey,LPCSTR lpFile,LPCSTR lpFileOut);

#ifdef UNICODE
#define RSA_DecryptFile RSA_DecryptFileW
#else
#define RSA_DecryptFile RSA_DecryptFileA
#endif


SYSLIBEXP(BOOL) RSA_CheckBufferSign(RSA_KEY rsaPubKey,LPBYTE lpBufIn,DWORD dwBufSize,LPBYTE lpSign);

SYSLIBEXP(BOOL) RSA_CheckFileSignW(RSA_KEY rsaPubKey,LPCWSTR lpFile,LPBYTE lpSign);
SYSLIBEXP(BOOL) RSA_CheckFileSignA(RSA_KEY rsaPubKey,LPCSTR lpFile,LPBYTE lpSign);

#ifdef UNICODE
#define RSA_CheckFileSign RSA_CheckFileSignW
#else
#define RSA_CheckFileSign RSA_CheckFileSignA
#endif

SYSLIBEXP(DWORD) RSA_DumpKey(RSA_KEY rsaKey,LPBYTE lpBuf);
SYSLIBEXP(RSA_KEY) RSA_LoadKeyFromDump(LPBYTE lpBuf,DWORD dwSize);

SYSLIBEXP(RSA_KEY) RSA_GetPublicKeyFromPrivate(RSA_KEY rsaPriv);

SYSLIBEXP(void) RSA_DestroyKey(RSA_KEY rsaKey);
SYSLIBEXP(DWORD) RSA_GetKeyLen(RSA_KEY rsaKey);
SYSLIBEXP(BOOL) RSA_IsSecretKey(RSA_KEY rsaKey);

#endif // SYSLIB_RSA_H_INCLUDED
