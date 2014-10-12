#include "sys_includes.h"

#include "syslib\mem.h"
#include "safethread.h"

static DWORD WINAPI SafeThreadRoutine(SAFE_THREAD_ROUTINE *lpSafeThreadParams)
{
    DWORD dwResult=0;
    __try {
        dwResult=lpSafeThreadParams->lpRealRoutine(lpSafeThreadParams->lpParam);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    MemFree(lpSafeThreadParams);
    return dwResult;
}

SYSLIBFUNC(HANDLE) SysCreateThreadSafe(LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,DWORD dwCreationFlags,LPDWORD lpThreadId)
{
    SAFE_THREAD_ROUTINE *lpSafeThreadParams=(SAFE_THREAD_ROUTINE *)MemQuickAlloc(sizeof(SAFE_THREAD_ROUTINE));
    lpSafeThreadParams->lpParam=lpParameter;
    lpSafeThreadParams->lpRealRoutine=lpStartAddress;

    HANDLE hThread=CreateThread(lpThreadAttributes,dwStackSize,(LPTHREAD_START_ROUTINE)SafeThreadRoutine,lpSafeThreadParams,dwCreationFlags,lpThreadId);
    if (!hThread)
        MemFree(lpSafeThreadParams);
    return hThread;
}

