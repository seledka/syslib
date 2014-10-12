#ifndef SYSLIB_LDR_H_INCLUDED
#define SYSLIB_LDR_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(LPBYTE) ldr_GetOurAddr();
SYSLIBEXP(LPBYTE) ldr_GetImageBase(LPBYTE lpImg);
SYSLIBEXP(void) ldr_RebasePE();
SYSLIBEXP(DWORD) ldr_GetImageSize(LPBYTE lpImg);
SYSLIBEXP(BOOL) ldr_CheckPE(LPBYTE lpMem,DWORD dwMemSize);


SYSLIBEXP(HMODULE) ldr_LoadImageFromMemory(LPBYTE lpMem);
SYSLIBEXP(LPVOID) ldr_GetProcAddress(HINSTANCE hModule,LPCSTR lpProc);
SYSLIBEXP(BOOL) ldr_FreeImage(HMODULE hImage);

SYSLIBEXP(HMODULE) ldr_LoadImageFromFileW(LPCWSTR lpName);
SYSLIBEXP(HMODULE) ldr_LoadImageFromFileA(LPCSTR lpName);

#ifdef UNICODE
#define ldr_LoadImageFromFile ldr_LoadImageFromFileW
#else
#define ldr_LoadImageFromFile ldr_LoadImageFromFileA
#endif


SYSLIBEXP(BOOL) ldr_CheckFileW(LPCWSTR lpFileName);
SYSLIBEXP(BOOL) ldr_CheckFileA(LPCSTR lpFileName);

#ifdef UNICODE
#define ldr_CheckFile ldr_CheckFileW
#else
#define ldr_CheckFile ldr_CheckFileA
#endif


typedef HRSRC HMEMRESOURCE;

SYSLIBEXP(HMEMRESOURCE) ldr_FindResourceExW(HMODULE hModule,LPCWSTR lpName,LPCWSTR lpType,WORD wLang);
SYSLIBEXP(HMEMRESOURCE) ldr_FindResourceExA(HMODULE hModule,LPCSTR lpName,LPCSTR lpType,WORD wLang);

#ifdef UNICODE
#define ldr_FindResourceEx ldr_FindResourceExW
#else
#define ldr_FindResourceEx ldr_FindResourceExA
#endif


SYSLIBEXP(HMEMRESOURCE) ldr_FindResourceW(HMODULE hModule,LPCWSTR lpName,LPCWSTR lpType);
SYSLIBEXP(HMEMRESOURCE) ldr_FindResourceA(HMODULE hModule,LPCSTR lpName,LPCSTR lpType);

#ifdef UNICODE
#define ldr_FindResource ldr_FindResourceW
#else
#define ldr_FindResource ldr_FindResourceA
#endif


SYSLIBEXP(DWORD) ldr_SizeofResource(HMODULE hModule,HMEMRESOURCE hResource);
SYSLIBEXP(LPVOID) ldr_LoadResource(HMODULE hModule,HMEMRESOURCE hResource);

SYSLIBEXP(BOOL) ldr_IsModuleContainAddress(HINSTANCE hModule,LPVOID lpAddress);

SYSLIBEXP(LPVOID) ldr_GetEntryPoint(HINSTANCE hModule);

extern_C IMAGE_DOS_HEADER __ImageBase;
#define hImageBase (HINSTANCE)&__ImageBase

#endif // SYSLIB_LDR_H_INCLUDED
