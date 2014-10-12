#ifndef SYSLIB_THREADSGROUP_H_INCLUDED
#define SYSLIB_THREADSGROUP_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(HANDLE) ThreadsGroup_Create();
#define THREADGROUP_SAFETHREAD 1
SYSLIBEXP(BOOL) ThreadsGroup_CreateThreadEx(HANDLE hGroup,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,LPDWORD lpThreadId,LPHANDLE lpThreadHandle,DWORD dwFlags);
SYSLIBEXP(BOOL) ThreadsGroup_CreateThread(HANDLE hGroup,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,LPDWORD lpThreadId,LPHANDLE lpThreadHandle);
SYSLIBEXP(BOOL) ThreadsGroup_WaitForAllExit(HANDLE hGroup,DWORD dwTimeout);
SYSLIBEXP(void) ThreadsGroup_CloseGroup(HANDLE hGroup);
SYSLIBEXP(void) ThreadsGroup_CloseGroupAndTerminateThreads(HANDLE hGroup);
SYSLIBEXP(void) ThreadsGroup_CloseTerminatedHandles(HANDLE hGroup);
SYSLIBEXP(DWORD) ThreadsGroup_NumberOfActiveThreads(HANDLE hGroup);

#endif // SYSLIB_THREADSGROUP_H_INCLUDED
