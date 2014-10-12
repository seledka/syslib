#include "sys_includes.h"
#include <tlhelp32.h>

#include "wh_process.h"
#include "ldr\ldr.h"
#include "inject\inject.h"

#include "syslib\debug.h"
#include "syslib\apihook.h"
#include "syslib\hooks.h"
#include "syslib\criticalsections.h"
#include "syslib\mem.h"

static SAFE_CRITICAL_SECTION csWinHooks;
static WIN_HOOK_INFO *lpHooks;

static DWORD dwInit;
static bool IsHooked()
{
    return (dwInit == GetCurrentProcessId());
}

static bool IsHookPresent(int idHook,HOOKPROC lpfn)
{
    bool bRet=false;
    WIN_HOOK_INFO *lpHook=lpHooks;
    while (lpHook)
    {
        if ((lpHook->idHook == idHook) && (lpHook->lpfn == lpfn))
        {
            bRet=true;
            break;
        }
        lpHook=lpHook->lpNext;
    }
    return bRet;
}

static bool IsThreadHooked(WIN_HOOK_INFO *lpHook,DWORD_PTR dwThreadId)
{
    bool bRet=false;
    HOOKED_THREAD_INFO *lpThread=lpHook->lpThreads;
    while (lpThread)
    {
        if (lpThread->dwThreadId == dwThreadId)
        {
            bRet=true;
            break;
        }
        lpThread=lpThread->lpNext;
    }
    return bRet;
}

static void SetThreadWindowsHookEx(WIN_HOOK_INFO *lpHook,DWORD dwThreadId)
{
    HHOOK hHook=SetWindowsHookEx(lpHook->idHook,lpHook->lpfn,NULL,dwThreadId);
    if (hHook)
    {
        HOOKED_THREAD_INFO *lpThread=(HOOKED_THREAD_INFO*)MemAlloc(sizeof(HOOKED_THREAD_INFO));
        if (lpThread)
        {
            lpThread->dwThreadId=dwThreadId;
            lpThread->hHook=hHook;
            if (!lpHook->lpThreads)
                lpHook->lpThreads=lpThread;
            else
            {
                HOOKED_THREAD_INFO *lpCur=lpHook->lpThreads;
                while (lpCur->lpNext)
                    lpCur=lpCur->lpNext;
                lpCur->lpNext=lpThread;
            }
        }
        else
            UnhookWindowsHookEx(hHook);
    }
    return;
}

static void TryToHookThread()
{
    EnterSafeCriticalSection(&csWinHooks);
    {
        WIN_HOOK_INFO *lpHook=lpHooks;
        while (lpHook)
        {
            if (!IsThreadHooked(lpHook,GetCurrentThreadId()))
                SetThreadWindowsHookEx(lpHook,GetCurrentThreadId());

            lpHook=lpHook->lpNext;
        }
    }
    LeaveSafeCriticalSection(&csWinHooks);
    return;
}

static __DispatchMessageA *pDispatchMessageA;
static LRESULT WINAPI DispatchMessageA_handle(MSG *lpMsg)
{
    TryToHookThread();
    return pDispatchMessageA(lpMsg);
}

static __DispatchMessageW *pDispatchMessageW;
static LRESULT WINAPI DispatchMessageW_handle(MSG *lpMsg)
{
    TryToHookThread();
    return pDispatchMessageW(lpMsg);
}

static __WaitMessage *pWaitMessage;
static BOOL WINAPI WaitMessage_handle()
{
    TryToHookThread();
    return pWaitMessage();
}

SYSLIBFUNC(HPROCHOOK) SetProcessWindowsHookEx(int idHook,HOOKPROC lpfn)
{
    if (!IsHooked())
    {
        InitializeSafeCriticalSection(&csWinHooks);
        lpHooks=NULL;
        dwInit=GetCurrentProcessId();
        pDispatchMessageA=(__DispatchMessageA*)HookAPI_Hook(DispatchMessageA,DispatchMessageA_handle);
        pDispatchMessageW=(__DispatchMessageW*)HookAPI_Hook(DispatchMessageW,DispatchMessageW_handle);

        /**
            Win8 не вызывает DispatchMessage из обработчика диалоговых окон,
            поэтому хукаем и WaitMessage :(
        **/
        pWaitMessage =(__WaitMessage *)HookAPI_Hook(WaitMessage,WaitMessage_handle);
    }

    WIN_HOOK_INFO *lpHook=NULL;
    EnterSafeCriticalSection(&csWinHooks);
    {
        if (!IsHookPresent(idHook,lpfn))
        {
            lpHook=(WIN_HOOK_INFO*)MemAlloc(sizeof(WIN_HOOK_INFO));
            if (lpHook)
            {
                if (!lpHooks)
                    lpHooks=lpHook;
                else
                {
                    WIN_HOOK_INFO *lpCur=lpHooks;
                    while (lpCur->lpNext)
                        lpCur=lpCur->lpNext;

                    lpCur->lpNext=lpHook;
                }
                lpHook->idHook=idHook;
                lpHook->lpfn=lpfn;
            }
        }
    }
    LeaveSafeCriticalSection(&csWinHooks);
    return (HPROCHOOK)lpHook;
}

static void UnhookProcessWindowsHookExInt(WIN_HOOK_INFO *lpHook)
{
    HOOKED_THREAD_INFO *lpThread=lpHook->lpThreads;
    while (lpThread)
    {
        HOOKED_THREAD_INFO *lpNext=lpThread->lpNext;
        UnhookWindowsHookEx(lpThread->hHook);
        MemFree(lpThread);
        lpThread=lpNext;
    }
    return;
}

SYSLIBFUNC(BOOL) UnhookProcessWindowsHookEx(HPROCHOOK hhk)
{
    if (!IsHooked())
        return false;

    BOOL bRet=false;
    EnterSafeCriticalSection(&csWinHooks);
    {
        WIN_HOOK_INFO *lpHook=lpHooks,
                      *lpPrev=NULL;
        while (lpHook)
        {
            if (lpHook == hhk)
            {
                WIN_HOOK_INFO *lpNext=lpHook->lpNext;
                UnhookProcessWindowsHookExInt(lpHook);
                MemFree(lpHook);
                if (lpPrev)
                    lpPrev->lpNext=lpNext;
                else
                    lpHooks=lpNext;
                bRet=true;
                break;
            }
            lpPrev=lpHook;
            lpHook=lpHook->lpNext;
        }
    }
    LeaveSafeCriticalSection(&csWinHooks);

    if (!lpHooks)
        RemoveProcessWindowsHooks();
    return bRet;
}

SYSLIBFUNC(void) RemoveProcessWindowsHooks()
{
    if (!IsHooked())
        return;

    while (!HookAPI_Unhook(DispatchMessageA))
        Sleep(1);

    while (!HookAPI_Unhook(DispatchMessageW))
        Sleep(1);

    while (!HookAPI_Unhook(WaitMessage))
        Sleep(1);

    EnterSafeCriticalSection(&csWinHooks);
    {
        WIN_HOOK_INFO *lpHook=lpHooks;
        while (lpHook)
        {
            WIN_HOOK_INFO *lpNext=lpHook->lpNext;
            UnhookProcessWindowsHookExInt(lpHook);
            MemFree(lpHook);
            lpHook=lpNext;
        }
    }
    LeaveSafeCriticalSection(&csWinHooks);
    dwInit=0;
    DeleteSafeCriticalSection(&csWinHooks);
    return;
}

