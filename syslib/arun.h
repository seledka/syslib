#ifndef SYSLIB_ARUN_H_INCLUDED
#define SYSLIB_ARUN_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(BOOL) Arun_CheckStartupW(LPCWSTR lpFile);
SYSLIBEXP(BOOL) Arun_CheckStartupA(LPCSTR lpFile);

#ifdef UNICODE
#define Arun_CheckStartup Arun_CheckStartupW
#else
#define Arun_CheckStartup Arun_CheckStartupA
#endif


SYSLIBEXP(BOOL) Arun_CheckUserStartupW(LPCWSTR lpFile,PSID lpSid);
SYSLIBEXP(BOOL) Arun_CheckUserStartupA(LPCSTR lpFile,PSID lpSid);

#ifdef UNICODE
#define Arun_CheckUserStartup Arun_CheckUserStartupW
#else
#define Arun_CheckUserStartup Arun_CheckUserStartupA
#endif


SYSLIBEXP(BOOL) Arun_AppendFileW(LPCWSTR lpFile);
SYSLIBEXP(BOOL) Arun_AppendFileA(LPCSTR lpFile);

#ifdef UNICODE
#define Arun_AppendFile Arun_AppendFileW
#else
#define Arun_AppendFile Arun_AppendFileA
#endif


SYSLIBEXP(BOOL) Arun_AppendFileToUserW(LPCWSTR lpFile,PSID lpSid);
SYSLIBEXP(BOOL) Arun_AppendFileToUserA(LPCSTR lpFile,PSID lpSid);

#ifdef UNICODE
#define Arun_AppendFileToUser Arun_AppendFileToUserW
#else
#define Arun_AppendFileToUser Arun_AppendFileToUserA
#endif


SYSLIBEXP(BOOL) Arun_AppendFileToAllUsersW(LPCWSTR lpFile);
SYSLIBEXP(BOOL) Arun_AppendFileToAllUsersA(LPCSTR lpFile);

#ifdef UNICODE
#define Arun_AppendFileToAllUsers Arun_AppendFileToAllUsersW
#else
#define Arun_AppendFileToAllUsers Arun_AppendFileToAllUsersA
#endif

SYSLIBEXP(BOOL) Arun_RemoveFileW(LPCWSTR lpFile);
SYSLIBEXP(BOOL) Arun_RemoveFileA(LPCSTR lpFile);

#ifdef UNICODE
#define Arun_RemoveFile Arun_RemoveFileW
#else
#define Arun_RemoveFile Arun_RemoveFileA
#endif


SYSLIBEXP(HANDLE) Arun_ProtectMeW(LPCWSTR lpFile);
SYSLIBEXP(HANDLE) Arun_ProtectMeA(LPCSTR lpFile);

#ifdef UNICODE
#define Arun_ProtectMe Arun_ProtectMeW
#else
#define Arun_ProtectMe Arun_ProtectMeA
#endif


SYSLIBEXP(void) Arun_UnprotectMeW(LPCWSTR lpFile);
SYSLIBEXP(void) Arun_UnprotectMeA(LPCSTR lpFile);

#ifdef UNICODE
#define Arun_UnprotectMe Arun_UnprotectMeW
#else
#define Arun_UnprotectMe Arun_UnprotectMeA
#endif


SYSLIBEXP(BOOL) Arun_PauseProtection(HANDLE hProtection);
SYSLIBEXP(BOOL) Arun_ResumeProtection(HANDLE hProtection);
SYSLIBEXP(void) Arun_StopProtection(HANDLE hProtection);

#endif // SYSLIB_ARUN_H_INCLUDED
