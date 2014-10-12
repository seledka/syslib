#include "sys_includes.h"

#include "splice.h"

#include "syslib\debug.h"
#include "syslib\system.h"
#include "syslib\apihook.h"
#include "syslib\criticalsections.h"
#include "syslib\mem.h"

static PHOOK_INFO lpHooks;
static SAFE_CRITICAL_SECTION csHookApi;
static DWORD dwInit;

static bool IsInit()
{
    return (dwInit == GetCurrentProcessId());
}

static PHOOK_INFO GetHookInfo(LPVOID lpFunc,PHOOK_INFO *lppPrev=NULL)
{
    PHOOK_INFO lpCurHook=lpHooks,
               lpHook=NULL,
               lpPrev=NULL;

    while (lpCurHook)
    {
        if (lpCurHook->lpRealFunc == lpFunc)
        {
            lpHook=lpCurHook;
            break;
        }

        lpPrev=lpCurHook;
        lpCurHook=lpCurHook->lpNext;
    }

    if (lppPrev)
        *lppPrev=lpPrev;

    return lpHook;
}

static HANDLE hProtectionThread;
static bool bProtection;
static void WINAPI ProtectionThread(void*)
{
    do
    {
        Sleep(PROTECTION_SLEEP);

        EnterSafeCriticalSection(&csHookApi);
        {
            PHOOK_INFO lpHook=lpHooks;
            while (lpHook)
            {
                SYSLIB::Splice_PathFunc(lpHook);

                lpHook=lpHook->lpNext;
            }
        }
        LeaveSafeCriticalSection(&csHookApi);
    }
    while (bProtection);
    return;
}

static PTHREAD_HOOK_INFO IsThreadPresent(PHOOK_INFO lpHook,DWORD_PTR dwThreadId)
{
    PTHREAD_HOOK_INFO lpThreadHook=lpHook->lpThreads;
    while (lpThreadHook)
    {
        if (lpThreadHook->dwThreadId == dwThreadId)
            break;

        lpThreadHook=lpThreadHook->lpNext;
    }
    return lpThreadHook;
}

static void DisableHookForCallingThread(PHOOK_INFO lpHook,LPVOID lpRetAddr)
{
    PTHREAD_HOOK_INFO lpThreadHook=(PTHREAD_HOOK_INFO)MemQuickAlloc(sizeof(THREAD_HOOK_INFO));
    if (lpThreadHook)
    {
        lpThreadHook->dwThreadId=GetCurrentThreadId();
        lpThreadHook->dwRefs=1;
        lpThreadHook->lpRetAddr[0]=lpRetAddr;
        lpThreadHook->lpNext=lpHook->lpThreads;
        lpHook->lpThreads=lpThreadHook;
    }
    return;
}

static bool IsHookEnabled(PHOOK_INFO lpHook,LPVOID lpRetAddr)
{
    bool bRet=true;
    do
    {
        DWORD_PTR dwCurrentThreadId=GetCurrentThreadId();

        if (!lpHook->bHookEnabled)
        {
            bRet=false;
            if (!IsThreadPresent(lpHook,dwCurrentThreadId))
            {
                DisableHookForCallingThread(lpHook,lpRetAddr);
                break;
            }
        }

        PTHREAD_HOOK_INFO lpThreadHook=lpHook->lpThreads;
        while (lpThreadHook)
        {
            if (lpThreadHook->dwThreadId == dwCurrentThreadId)
            {
                if (lpThreadHook->dwRefs < HOOK_MAX_RECURSE)
                    lpThreadHook->lpRetAddr[lpThreadHook->dwRefs++]=lpRetAddr;
                bRet=false;
                break;
            }
            lpThreadHook=lpThreadHook->lpNext;
        }
    }
    while (false);
    return bRet;
}

static LPVOID EnableHookForCallingThreadInt(PHOOK_INFO lpHook)
{
    LPVOID lpRetAddr=NULL;
    PTHREAD_HOOK_INFO lpThreadHook=lpHook->lpThreads,
                      lpPrev=NULL;

    DWORD_PTR dwCurrentThreadId=GetCurrentThreadId();
    while (lpThreadHook)
    {
        if (lpThreadHook->dwThreadId == dwCurrentThreadId)
        {
            lpRetAddr=lpThreadHook->lpRetAddr[--lpThreadHook->dwRefs];
            if (!lpThreadHook->dwRefs)
            {
                if (lpPrev)
                    lpPrev->lpNext=lpThreadHook->lpNext;
                else
                    lpHook->lpThreads=lpThreadHook->lpNext;
                MemFree(lpThreadHook);
            }
            break;
        }

        lpPrev=lpThreadHook;
        lpThreadHook=lpThreadHook->lpNext;
    }
    return lpRetAddr;
}

namespace SYSLIB
{
    LPVOID __fastcall EnableHookForCallingThread(LPVOID lpFunc)
    {
        LPVOID lpRetAddr=NULL;
        EnterSafeCriticalSection(&csHookApi);
        {
            PHOOK_INFO lpHook=GetHookInfo(lpFunc);
            if (lpHook)
                lpRetAddr=EnableHookForCallingThreadInt(lpHook);
        }
        LeaveSafeCriticalSection(&csHookApi);
        return lpRetAddr;
    }

    // TODO (Гость#1#): цепочки перехватов
    LPVOID __fastcall GetHandlerAddress(LPVOID lpFunc,LPVOID lpRetAddr)
    {
        LPVOID lpHandler=NULL;
        EnterSafeCriticalSection(&csHookApi);
        {
            PHOOK_INFO lpHook=GetHookInfo(lpFunc);
            if (lpHook)
            {
                if (IsHookEnabled(lpHook,lpRetAddr))
                {
                    lpHandler=lpHook->lpHandler;
                    DisableHookForCallingThread(lpHook,lpRetAddr);
                }
                else
                    lpHandler=lpHook->lpBridge;
            }
        }
        LeaveSafeCriticalSection(&csHookApi);
        return lpHandler;
    }
}

static void InitAPIHook()
{
    if (IsInit())
        return;

    lpHooks=NULL;
    InitializeSafeCriticalSection(&csHookApi);
    dwInit=GetCurrentProcessId();
    bProtection=true;
    hProtectionThread=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)ProtectionThread,NULL,0,NULL);
    return;
}

static bool UnhookAPI_Int(LPVOID lpFunc)
{
    bool bRet=false;
    do
    {
        PHOOK_INFO lpPrevHook=NULL,
                   lpHook=GetHookInfo(lpFunc,&lpPrevHook);

        if (!lpHook)
        {
            bRet=true;
            break;
        }

        PTHREAD_HOOK_INFO lpThread=lpHook->lpThreads;
        while (lpThread)
        {
            if (lpThread->dwRefs)
                break;

            PTHREAD_HOOK_INFO lpNext=lpThread->lpNext;
            lpHook->lpThreads=lpNext;
            MemFree(lpThread);

            lpThread=lpNext;
        }

        if (lpHook->lpThreads)
            break;

        if (!SYSLIB::Splice_UnpathFunc(lpHook))
            break;

        if (lpPrevHook)
            lpPrevHook->lpNext=lpHook->lpNext;
        else
            lpHooks=lpHook->lpNext;

        MemFree(lpHook->lpBackup);
#ifdef _AMD64_
        SYSLIB::FreeReleayPlace(lpHook->lpBridge,JUMP_SIZE*6);
        SYSLIB::FreeReleayPlace(lpHook->lpRelay,RAX_JUMP_SIZE);
        SYSLIB::FreeReleayPlace(lpHook->lpTable,sizeof(ULONG_PTR)*MAX_JUMPS);
#else
        MemFree(lpHook->lpBridge);
#endif
        MemFree(lpHook->lpStub);

        MemFree(lpHook);

        bRet=true;
    }
    while (false);
    return bRet;
}

static LPVOID HookAPIInt(LPVOID lpFunc,LPVOID lpHandler,DWORD dwFlags)
{
    LPVOID lpBridge=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckCodePtr(lpHandler))
            break;

        PHOOK_INFO lpOldHook=GetHookInfo(lpFunc);
        if (lpOldHook)
        {
            if (!(dwFlags & APIHOOKER_REMOVE_OLD_HOOK))
            {
                lpBridge=lpOldHook->lpBridge;
                break;
            }

            if (!UnhookAPI_Int(lpFunc))
                break;
        }

        PHOOK_INFO lpHook=SYSLIB::Splice_PrepareAndPathFunc(lpFunc,lpHandler,dwFlags);
        if (!lpHook)
            break;

        if (lpHooks)
        {
            PHOOK_INFO lpCurHook=lpHooks;
            while (lpCurHook->lpNext)
                lpCurHook=lpCurHook->lpNext;

            lpCurHook->lpNext=lpHook;
        }
        else
            lpHooks=lpHook;

        lpBridge=lpHook->lpBridge;
    }
    while (false);
    return lpBridge;
}

SYSLIBFUNC(LPVOID) HookAPI_HookEx(LPVOID lpFunc,LPVOID lpHandler,DWORD dwFlags)
{
    LPVOID lpBridge=NULL;
    do
    {
        if (!IsInit())
        {
            InitAPIHook();
            if (!IsInit())
                break;
        }

        EnterSafeCriticalSection(&csHookApi);
            lpBridge=HookAPIInt(lpFunc,lpHandler,dwFlags);
        LeaveSafeCriticalSection(&csHookApi);
    }
    while (false);
    return lpBridge;
}

SYSLIBFUNC(LPVOID) HookAPI_Hook(LPVOID lpFunc,LPVOID lpHandler)
{
    return HookAPI_HookEx(lpFunc,lpHandler,0);
}

SYSLIBFUNC(BOOL) HookAPI_Enable(LPVOID lpFunc,BOOL bEnable)
{
    BOOL bRet=false;
    do
    {
        if (!IsInit())
            break;

        EnterSafeCriticalSection(&csHookApi);
        {
            PHOOK_INFO lpHook=GetHookInfo(lpFunc);
            if (lpHook)
            {
                lpHook->bHookEnabled=bEnable;
                bRet=true;
            }
        }
        LeaveSafeCriticalSection(&csHookApi);
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) HookAPI_EnableForCallingThread(LPVOID lpFunc,BOOL bEnable)
{
    BOOL bRet=false;
    do
    {
        if (!IsInit())
            break;

        EnterSafeCriticalSection(&csHookApi);
        {
            PHOOK_INFO lpHook=GetHookInfo(lpFunc);
            if (lpHook)
            {
                if (bEnable)
                {
                    PTHREAD_HOOK_INFO lpThread=IsThreadPresent(lpHook,GetCurrentThreadId());
                    if ((lpThread) && (lpThread->dwRefs == 1) && (lpThread->lpRetAddr[0] == HOOK_API_PSEUDO_RETADDR))
                    {
                        EnableHookForCallingThreadInt(lpHook);
                        bRet=true;
                    }
                }
                else
                {
                    if (!IsThreadPresent(lpHook,GetCurrentThreadId()))
                        DisableHookForCallingThread(lpHook,HOOK_API_PSEUDO_RETADDR);

                    bRet=true;
                }
            }
        }
        LeaveSafeCriticalSection(&csHookApi);
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) HookAPI_Unhook(LPVOID lpFunc)
{
    BOOL bRet=false;
    do
    {
        if (!IsInit())
            break;

        EnterSafeCriticalSection(&csHookApi);
            bRet=UnhookAPI_Int(lpFunc);
        LeaveSafeCriticalSection(&csHookApi);
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) HookAPI_UnhookAll()
{
    BOOL bRet=false;
    do
    {
        if (!IsInit())
        {
            bRet=true;
            break;
        }

        EnterSafeCriticalSection(&csHookApi);
        {
            while (lpHooks)
            {
                if (!UnhookAPI_Int(lpHooks->lpRealFunc))
                    break;
            }
        }
        LeaveSafeCriticalSection(&csHookApi);

        if (!lpHooks)
        {
            bProtection=false;
            WaitForSingleObject(hProtectionThread,INFINITE);
            SysCloseHandle(hProtectionThread);
            dwInit=0;
            bRet=true;
        }

        DeleteSafeCriticalSection(&csHookApi);
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(LPVOID) HookAPI_GetRealFunc(LPVOID lpFunc)
{
    LPVOID lpBridge=lpFunc;
    do
    {
        if (!lpFunc)
            break;

        if (!IsInit())
            break;

        EnterSafeCriticalSection(&csHookApi);
        {
            PHOOK_INFO lpCurHook=lpHooks;
            while (lpCurHook)
            {
                if (lpCurHook->lpRealFunc == lpFunc)
                {
                    lpBridge=lpCurHook->lpBridge;
                    break;
                }

                lpCurHook=lpCurHook->lpNext;
            }
        }
        LeaveSafeCriticalSection(&csHookApi);
    }
    while (false);
    return lpBridge;
}

SYSLIBFUNC(LPVOID) HookAPI_GetReturnAddress(LPVOID lpFunc)
{
    LPVOID lpRetAddr=NULL;
    do
    {
        if (!IsInit())
            break;

        EnterSafeCriticalSection(&csHookApi);
        {
            PHOOK_INFO lpCurHook=lpHooks;
            while (lpCurHook)
            {
                if (lpCurHook->lpRealFunc == lpFunc)
                {
                    DWORD_PTR dwCurrentThreadId=GetCurrentThreadId();

                    PTHREAD_HOOK_INFO lpThreadHook=lpCurHook->lpThreads;
                    while (lpThreadHook)
                    {
                        if (lpThreadHook->dwThreadId == dwCurrentThreadId)
                        {
                            if (lpThreadHook->dwRefs)
                                lpRetAddr=lpThreadHook->lpRetAddr[lpThreadHook->dwRefs-1];
                            break;
                        }
                        lpThreadHook=lpThreadHook->lpNext;
                    }
                    break;
                }

                lpCurHook=lpCurHook->lpNext;
            }
        }
        LeaveSafeCriticalSection(&csHookApi);
    }
    while (false);
    return lpRetAddr;
}

SYSLIBFUNC(void) HookAPI_UnhookModule(HMODULE hModule)
{
    do
    {
        if (!IsInit())
            break;

        if (!hModule)
            break;

        PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((ULONG_PTR)hModule+((PIMAGE_DOS_HEADER)hModule)->e_lfanew+4);
        PIMAGE_OPTIONAL_HEADER poh=(PIMAGE_OPTIONAL_HEADER)(pfh+1);

        EnterSafeCriticalSection(&csHookApi);
        {
            PHOOK_INFO lpCurHook=lpHooks;
            while (lpCurHook)
            {
                PHOOK_INFO lpNext=lpCurHook->lpNext;

                if ((ULONG_PTR)lpCurHook->lpHandler-(ULONG_PTR)hModule < poh->SizeOfImage)
                    UnhookAPI_Int(lpCurHook->lpRealFunc);

                lpCurHook=lpNext;
            }
        }
        LeaveSafeCriticalSection(&csHookApi);
    }
    while (false);
    return;
}

