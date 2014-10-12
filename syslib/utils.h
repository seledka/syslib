#ifndef SYSLIB_UTILS_H_INCLUDED
#define SYSLIB_UTILS_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(int) CompareObjects(HANDLE hObj1,HANDLE hObj2);

SYSLIBEXP(DWORD) xor128(int val);
SYSLIBEXP(DWORD) xor128_Between(int iMin,int iMax);

SYSLIBEXP(DWORD) GetRndDWORD();

SYSLIBEXP(HDESK) GetWindowDesktop(HWND hWnd);

SYSLIBEXP(BOOL) GetThreadDesktopNameW(DWORD dwThreadId,LPWSTR lpDeskName,DWORD dwSize);
SYSLIBEXP(BOOL) GetThreadDesktopNameA(DWORD dwThreadId,LPSTR lpDeskName,DWORD dwSize);

#ifdef UNICODE
#define GetThreadDesktopName GetThreadDesktopNameW
#else
#define GetThreadDesktopName GetThreadDesktopNameA
#endif

SYSLIBEXP(BOOL) DeleteDesktop(HDESK hDesk);

SYSLIBEXP(BOOL) EnumProcessWindows(DWORD dwProcessId,WNDENUMPROC lpfn,LPARAM lParam);
SYSLIBEXP(int) CountBits(DWORD64 dwValue);
SYSLIBEXP(DWORD64) ReverseBytes(DWORD64 dwValue);

SYSLIBEXP(void) GenerateUniqueWndClassNameW(LPWSTR lpWndClassName,DWORD dwWndClassNameSize);
SYSLIBEXP(void) GenerateUniqueWndClassNameA(LPSTR lpWndClassName,DWORD dwWndClassNameSize);

#ifdef UNICODE
#define GenerateUniqueWndClassName GenerateUniqueWndClassNameW
#else
#define GenerateUniqueWndClassName GenerateUniqueWndClassNameA
#endif

#define size_of(s,m) (sizeof((((s*)0)->m)))

#endif // SYSLIB_UTILS_H_INCLUDED
