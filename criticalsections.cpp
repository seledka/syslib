#include "sys_includes.h"

#include "syslib\criticalsections.h"

static bool IsSafeCriticalSectionInitialized(LPSAFE_CRITICAL_SECTION lpSafeCriticalSection)
{
    return (lpSafeCriticalSection->dwReserved0 == GetCurrentProcessId());
}

SYSLIBFUNC(BOOL) InitializeSafeCriticalSection(LPSAFE_CRITICAL_SECTION lpSafeCriticalSection)
{
    BOOL bRet=false;

    DWORD dwGLE=GetLastError();
    __try
    {
        do
        {
            if (!SYSLIB_SAFE::CheckParamWrite(lpSafeCriticalSection,sizeof(*lpSafeCriticalSection)))
                break;

            if (IsSafeCriticalSectionInitialized(lpSafeCriticalSection))
                break;

            InitializeCriticalSection(&lpSafeCriticalSection->cs);
            lpSafeCriticalSection->dwReserved0=GetCurrentProcessId();
            lpSafeCriticalSection->dwReserved1=0;
            bRet=true;
        }
        while (false);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

    SetLastError(dwGLE);
    return bRet;
}

#define SCSF_NODEADLOCK 1

static void EnterSafeCriticalSectionInt(LPSAFE_CRITICAL_SECTION lpSafeCriticalSection,DWORD dwFlags)
{
    DWORD dwGLE=GetLastError();

    __try
    {
        do
        {
            if (!SYSLIB_SAFE::CheckParamWrite(lpSafeCriticalSection,sizeof(*lpSafeCriticalSection)))
                break;

            if (!IsSafeCriticalSectionInitialized(lpSafeCriticalSection))
            {
                if (!InitializeSafeCriticalSection(lpSafeCriticalSection))
                    break;
            }

            if ((!(dwFlags & SCSF_NODEADLOCK)) || (lpSafeCriticalSection->dwReserved1 != GetCurrentThreadId()))
            {
                EnterCriticalSection(&lpSafeCriticalSection->cs);
                lpSafeCriticalSection->dwReserved1=GetCurrentThreadId();
            }
        }
        while (false);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

    SetLastError(dwGLE);
    return;
}

SYSLIBFUNC(void) EnterSafeCriticalSectionDeadlockFree(LPSAFE_CRITICAL_SECTION lpSafeCriticalSection)
{
    EnterSafeCriticalSectionInt(lpSafeCriticalSection,SCSF_NODEADLOCK);
    return;
}

SYSLIBFUNC(void) EnterSafeCriticalSection(LPSAFE_CRITICAL_SECTION lpSafeCriticalSection)
{
    EnterSafeCriticalSectionInt(lpSafeCriticalSection,0);
    return;
}

SYSLIBFUNC(BOOL) TryEnterSafeCriticalSection(LPSAFE_CRITICAL_SECTION lpSafeCriticalSection)
{
    BOOL bRet=false;

    DWORD dwGLE=GetLastError();
    __try
    {
        do
        {
            if (!SYSLIB_SAFE::CheckParamWrite(lpSafeCriticalSection,sizeof(*lpSafeCriticalSection)))
                break;

            if (!IsSafeCriticalSectionInitialized(lpSafeCriticalSection))
                InitializeSafeCriticalSection(lpSafeCriticalSection);

            if (!IsSafeCriticalSectionInitialized(lpSafeCriticalSection))
                break;

            if (!TryEnterCriticalSection(&lpSafeCriticalSection->cs))
                break;

            lpSafeCriticalSection->dwReserved1=GetCurrentThreadId();
            bRet=true;
        }
        while (false);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

    SetLastError(dwGLE);
    return bRet;
}

SYSLIBFUNC(void) LeaveSafeCriticalSection(LPSAFE_CRITICAL_SECTION lpSafeCriticalSection)
{
    DWORD dwGLE=GetLastError();
    __try
    {
        do
        {
            if (!SYSLIB_SAFE::CheckParamWrite(lpSafeCriticalSection,sizeof(*lpSafeCriticalSection)))
                break;

            if (!IsSafeCriticalSectionInitialized(lpSafeCriticalSection))
                break;

            if (lpSafeCriticalSection->dwReserved1 == GetCurrentThreadId())
                lpSafeCriticalSection->dwReserved1=0;

            LeaveCriticalSection(&lpSafeCriticalSection->cs);
        }
        while (false);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

    SetLastError(dwGLE);
    return;
}

SYSLIBFUNC(void) DeleteSafeCriticalSection(LPSAFE_CRITICAL_SECTION lpSafeCriticalSection)
{
    DWORD dwGLE=GetLastError();
    __try
    {
        do
        {
            if (!SYSLIB_SAFE::CheckParamWrite(lpSafeCriticalSection,sizeof(*lpSafeCriticalSection)))
                break;

            if (!IsSafeCriticalSectionInitialized(lpSafeCriticalSection))
                break;

            /// EnterSafeCriticalSection(lpSafeCriticalSection);

            DeleteCriticalSection(&lpSafeCriticalSection->cs);
            memset(lpSafeCriticalSection,0,sizeof(*lpSafeCriticalSection));
        }
        while (false);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

    SetLastError(dwGLE);
    return;
}

