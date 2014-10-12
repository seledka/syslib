#ifndef SYSLIB_REGISTRY_H_INCLUDED
#define SYSLIB_REGISTRY_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(BOOL) Registry_ImportKeyW(HKEY hKey,LPCWSTR lpSubKey,LPCWSTR lpFile);
SYSLIBEXP(BOOL) Registry_ImportKeyA(HKEY hKey,LPCSTR lpSubKey,LPCSTR lpFile);

#ifdef UNICODE
#define Registry_ImportKey Registry_ImportKeyW
#else
#define Registry_ImportKey Registry_ImportKeyA
#endif


SYSLIBEXP(BOOL) Registry_ExportKeyW(HKEY hKey,LPCWSTR lpSubKey,LPCWSTR lpFile);
SYSLIBEXP(BOOL) Registry_ExportKeyA(HKEY hKey,LPCSTR lpSubKey,LPCSTR lpFile);

#ifdef UNICODE
#define Registry_ExportKey Registry_ExportKeyW
#else
#define Registry_ExportKey Registry_ExportKeyA
#endif


SYSLIBEXP(BOOL) Registry_ExportKeyExW(HKEY hKey,LPCWSTR lpSubKey,LPCWSTR lpFile,DWORD dwFlags);
SYSLIBEXP(BOOL) Registry_ExportKeyExA(HKEY hKey,LPCSTR lpSubKey,LPCSTR lpFile,DWORD dwFlags);

#ifdef UNICODE
#define Registry_ExportKeyEx Registry_ExportKeyExW
#else
#define Registry_ExportKeyEx Registry_ExportKeyExA
#endif

#endif // SYSLIB_REGISTRY_H_INCLUDED
