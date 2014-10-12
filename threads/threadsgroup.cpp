#include "sys_includes.h"

#include "syslib\criticalsections.h"
#include "syslib\mem.h"
#include "syslib\system.h"
#include "syslib\threadsgroup.h"
#include "threadsgroup.h"

SYSLIBFUNC(HANDLE) ThreadsGroup_Create()
{
    THREADS_GROUP *lpGroup=(THREADS_GROUP*)MemAlloc(sizeof(THREADS_GROUP));
    if (lpGroup)
        InitializeSafeCriticalSection(&lpGroup->csGroup);
    return (HANDLE)lpGroup;
}

SYSLIBFUNC(BOOL) ThreadsGroup_CreateThreadEx(HANDLE hGroup,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,LPDWORD lpThreadId,LPHANDLE lpThreadHandle,DWORD dwFlags)
{
    BOOL bRet=false;
    if (hGroup)
    {
        ThreadsGroup_CloseTerminatedHandles(hGroup);

        THREADS_GROUP *lpGroup=(THREADS_GROUP*)hGroup;
        EnterSafeCriticalSection(&lpGroup->csGroup);
        {
            if (lpGroup->dwCount < ARRAYSIZE(lpGroup->hThreads))
            {
                if (lpStartAddress)
                {
                    HANDLE hThread;
                    if (dwFlags & THREADGROUP_SAFETHREAD)
                        hThread=SysCreateThreadSafe(NULL,dwStackSize,lpStartAddress,lpParameter,0,lpThreadId);
                    else
                        hThread=CreateThread(NULL,dwStackSize,lpStartAddress,lpParameter,0,lpThreadId);
                    if (hThread)
                    {
                        lpGroup->hThreads[lpGroup->dwCount++]=hThread;
                        if (lpThreadHandle)
                            DuplicateHandle(GetCurrentProcess(),hThread,GetCurrentProcess(),lpThreadHandle,0,FALSE,DUPLICATE_SAME_ACCESS);
                        bRet=true;
                    }
                }
            }
        }
        LeaveSafeCriticalSection(&lpGroup->csGroup);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) ThreadsGroup_CreateThread(HANDLE hGroup,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,LPDWORD lpThreadId,LPHANDLE lpThreadHandle)
{
    return ThreadsGroup_CreateThreadEx(hGroup,dwStackSize,lpStartAddress,lpParameter,lpThreadId,lpThreadHandle,THREADGROUP_SAFETHREAD);
}

SYSLIBFUNC(BOOL) ThreadsGroup_WaitForAllExit(HANDLE hGroup,DWORD dwTimeout)
{
    BOOL bRet=false;
    if (hGroup)
    {
        THREADS_GROUP *lpGroup=(THREADS_GROUP*)hGroup;
        EnterSafeCriticalSection(&lpGroup->csGroup);
            bRet=((lpGroup->dwCount == 0) || (SysWaitForMultipleObjects(lpGroup->dwCount,lpGroup->hThreads,TRUE,dwTimeout) == WAIT_OBJECT_0));
        LeaveSafeCriticalSection(&lpGroup->csGroup);
    }
    return bRet;
}

SYSLIBFUNC(void) ThreadsGroup_CloseGroup(HANDLE hGroup)
{
    if (hGroup)
    {
        THREADS_GROUP *lpGroup=(THREADS_GROUP*)hGroup;

        EnterSafeCriticalSection(&lpGroup->csGroup);
        {
            for (DWORD i=0; i < lpGroup->dwCount; i++)
                SysCloseHandle(lpGroup->hThreads[i]);
        }
        LeaveSafeCriticalSection(&lpGroup->csGroup);

        DeleteSafeCriticalSection(&lpGroup->csGroup);

        MemFree(hGroup);
    }
    return;
}

SYSLIBFUNC(void) ThreadsGroup_CloseGroupAndTerminateThreads(HANDLE hGroup)
{
    if (hGroup)
    {
        THREADS_GROUP *lpGroup=(THREADS_GROUP*)hGroup;

        EnterSafeCriticalSection(&lpGroup->csGroup);
        {
            for (DWORD i=0; i < lpGroup->dwCount; i++)
            {
                TerminateThread(lpGroup->hThreads[i],0xDEAD);
                SysCloseHandle(lpGroup->hThreads[i]);
            }
        }
        LeaveSafeCriticalSection(&lpGroup->csGroup);

        DeleteSafeCriticalSection(&lpGroup->csGroup);

        MemFree(hGroup);
    }
    return;
}

SYSLIBFUNC(void) ThreadsGroup_CloseTerminatedHandles(HANDLE hGroup)
{
    if (hGroup)
    {
        THREADS_GROUP *lpGroup=(THREADS_GROUP*)hGroup;

        EnterSafeCriticalSection(&lpGroup->csGroup);
        {
            DWORD j=0;
            for(DWORD i=0; i < lpGroup->dwCount; i++)
            {
                if (lpGroup->hThreads[i] != NULL)
                {
                    if (WaitForSingleObject(lpGroup->hThreads[i],0) == WAIT_OBJECT_0)
                    {
                        SysCloseHandle(lpGroup->hThreads[i]);
                        lpGroup->hThreads[i]=NULL;
                    }
                    else
                    {
                        lpGroup->hThreads[j]=lpGroup->hThreads[i];
                        j++;
                    }
                }
            }
            lpGroup->dwCount=j;
        }
        LeaveSafeCriticalSection(&lpGroup->csGroup);
    }
    return;
}

SYSLIBFUNC(DWORD) ThreadsGroup_NumberOfActiveThreads(HANDLE hGroup)
{
    DWORD dwCount=0;
    if (hGroup)
    {
        THREADS_GROUP *lpGroup=(THREADS_GROUP*)hGroup;
        EnterSafeCriticalSection(&lpGroup->csGroup);
        {
            for (DWORD i=0; i < lpGroup->dwCount; i++)
            {
                if ((lpGroup->hThreads[i] != NULL) && (WaitForSingleObject(lpGroup->hThreads[i],0) == WAIT_TIMEOUT))
                    dwCount++;
            }
        }
        LeaveSafeCriticalSection(&lpGroup->csGroup);
    }
    return dwCount;
}

