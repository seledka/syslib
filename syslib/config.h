#ifndef SYSLIB_CONFIG_H_INCLUDED
#define SYSLIB_CONFIG_H_INCLUDED

#include "syslib_exp.h"

typedef HANDLE HCONFIG;

SYSLIBEXP(HANDLE) BeginUpdateConfigW(LPCWSTR lpFileName,BOOL bDeleteExistingConfigs);
SYSLIBEXP(HANDLE) BeginUpdateConfigA(LPCSTR lpFileName,BOOL bDeleteExistingConfigs);

#ifdef UNICODE
#define BeginUpdateConfig BeginUpdateConfigW
#else
#define BeginUpdateConfig BeginUpdateConfigA
#endif

SYSLIBEXP(BOOL) UpdateConfigW(HANDLE hUpdate,LPCWSTR lpName,LPVOID lpData,DWORD cbData);
SYSLIBEXP(BOOL) UpdateConfigA(HANDLE hUpdate,LPCSTR lpName,LPVOID lpData,DWORD cbData);

#ifdef UNICODE
#define UpdateConfig UpdateConfigW
#else
#define UpdateConfig UpdateConfigA
#endif

SYSLIBEXP(BOOL) EndUpdateConfig(HANDLE hUpdate,BOOL bDiscard);

SYSLIBEXP(HCONFIG) FindConfigW(HINSTANCE hModule,LPCWSTR lpName);
SYSLIBEXP(HCONFIG) FindConfigA(HINSTANCE hModule,LPCSTR lpName);

#ifdef UNICODE
#define FindConfig FindConfigW
#else
#define FindConfig FindConfigA
#endif

typedef BOOL (CALLBACK* ENUMCONFNAMEPROCA)(HMODULE hModule,LPSTR lpName,LONG_PTR lParam);
typedef BOOL (CALLBACK* ENUMCONFNAMEPROCW)(HMODULE hModule,LPWSTR lpName,LONG_PTR lParam);

SYSLIBEXP(BOOL) EnumConfigNamesW(HINSTANCE hModule,ENUMCONFNAMEPROCW lpFun,LONG_PTR lParam);
SYSLIBEXP(BOOL) EnumConfigNamesA(HINSTANCE hModule,ENUMCONFNAMEPROCA lpFun,LONG_PTR lParam);

#ifdef UNICODE
#define EnumConfigNames EnumConfigNamesW
#define ENUMCONFNAMEPROC ENUMCONFNAMEPROCW
#else
#define EnumConfigNames EnumConfigNamesA
#define ENUMCONFNAMEPROC ENUMCONFNAMEPROCA
#endif

SYSLIBEXP(LPVOID) LoadConfig(HINSTANCE hModule,HCONFIG hConfig);
SYSLIBEXP(void) FreeConfig(LPVOID lpConfig);
SYSLIBEXP(DWORD) SizeofConfig(HINSTANCE hModule,HCONFIG hConfig);

SYSLIBEXP(BOOL) UpdateConfigFromFileW(HANDLE hHandle,LPCWSTR lpName,LPCWSTR lpFileName);
SYSLIBEXP(BOOL) UpdateConfigFromFileA(HANDLE hHandle,LPCSTR lpName,LPCSTR lpFileName);

#ifdef UNICODE
#define UpdateConfigFromFile UpdateConfigFromFileW
#else
#define UpdateConfigFromFile UpdateConfigFromFileA
#endif


SYSLIBEXP(BOOL) PE_ValidateFileW(LPCWSTR lpFile);
SYSLIBEXP(BOOL) PE_ValidateFileA(LPCSTR lpFile);

#ifdef UNICODE
#define PE_ValidateFile PE_ValidateFileW
#else
#define PE_ValidateFile PE_ValidateFileA
#endif

SYSLIBEXP(LPBYTE) PE_Dump(HINSTANCE hModule,LPDWORD lpdwSize);

#endif // SYSLIB_CONFIG_H_INCLUDED
