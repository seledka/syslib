#ifndef SYSLIB_BASE64_H_INCLUDED
#define SYSLIB_BASE64_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(DWORD) Base64_CalcSizeW(LPBYTE lpData,DWORD dwSize);
SYSLIBEXP(DWORD) Base64_CalcSizeA(LPBYTE lpData,DWORD dwSize);

#ifdef UNICODE
#define Base64_CalcSize Base64_CalcSizeW
#else
#define Base64_CalcSize Base64_CalcSizeA
#endif


SYSLIBEXP(DWORD) Base64_GetDataSizeW(LPCWSTR lpData);
SYSLIBEXP(DWORD) Base64_GetDataSizeA(LPCSTR lpData);

#ifdef UNICODE
#define Base64_GetDataSize Base64_GetDataSizeW
#else
#define Base64_GetDataSize Base64_GetDataSizeA
#endif


SYSLIBEXP(BOOL) Base64_DecodeW(LPCWSTR lpIn,LPBYTE lpOut,DWORD dwBufSize);
SYSLIBEXP(BOOL) Base64_DecodeA(LPCSTR lpIn,LPBYTE lpOut,DWORD dwBufSize);

#ifdef UNICODE
#define Base64_Decode Base64_DecodeW
#else
#define Base64_Decode Base64_DecodeA
#endif


SYSLIBEXP(LPBYTE) Base64_DecodeExW(LPCWSTR lpIn,LPDWORD lpSize);
SYSLIBEXP(LPBYTE) Base64_DecodeExA(LPCSTR lpIn,LPDWORD lpSize);

#ifdef UNICODE
#define Base64_DecodeEx Base64_DecodeExW
#else
#define Base64_DecodeEx Base64_DecodeExA
#endif

#define BASE64_FLAG_NO_LINEBREAK 1

SYSLIBEXP(DWORD) Base64_EncodeW(LPBYTE lpIn,DWORD dwSize,LPWSTR lpOut,DWORD dwBufSize,DWORD dwFlags);
SYSLIBEXP(DWORD) Base64_EncodeA(LPBYTE lpIn,DWORD dwSize,LPSTR lpOut,DWORD dwBufSize,DWORD dwFlags);

#ifdef UNICODE
#define Base64_Encode Base64_EncodeW
#else
#define Base64_Encode Base64_EncodeA
#endif


SYSLIBEXP(LPWSTR) Base64_EncodeExW(LPBYTE lpIn,DWORD dwSize,LPDWORD lpOutSize,DWORD dwFlags);
SYSLIBEXP(LPSTR) Base64_EncodeExA(LPBYTE lpIn,DWORD dwSize,LPDWORD lpOutSize,DWORD dwFlags);

#ifdef UNICODE
#define Base64_EncodeEx Base64_EncodeExW
#else
#define Base64_EncodeEx Base64_EncodeExA
#endif


SYSLIBEXP(LPSTR) Base64_EncodeFileW(LPCWSTR lpFileName,DWORD dwFlags);
SYSLIBEXP(LPSTR) Base64_EncodeFileA(LPCSTR lpFileName,DWORD dwFlags);

#ifdef UNICODE
#define Base64_EncodeFile Base64_EncodeFileW
#else
#define Base64_EncodeFile Base64_EncodeFileA
#endif


#endif // SYSLIB_BASE64_H_INCLUDED
