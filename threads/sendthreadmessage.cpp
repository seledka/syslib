#include "sys_includes.h"

#include "sendthreadmessage.h"

#include "syslib\str.h"
#include "syslib\system.h"
#include "syslib\mem.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

static void GetEventName(TCHAR *lpName,DWORD dwThreadId,DWORD dwEventName)
{
    StrFormat(lpName,dcr_05f14c6f("%x,%x"),dwThreadId,dwEventName);
    return;
}

static void GetMappingName(TCHAR *lpName,DWORD dwThreadId,DWORD dwEventName)
{
    StrFormat(lpName,dcr_4778e322("m%x,%x"),dwThreadId,dwEventName);
    return;
}

SYSLIBFUNC(LRESULT) SendThreadMessage(DWORD dwThreadId,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
    LRESULT lRes=0;
    while (true)
    {
        TCHAR szEventName[20];
        DWORD dwEventName=GetTickCount();
        GetEventName(szEventName,dwThreadId,dwEventName);

        HANDLE hEvent=CreateEvent(NULL,true,false,szEventName);
        if (hEvent)
        {
            if (GetLastError() == ERROR_ALREADY_EXISTS)
            {
                SysCloseHandle(hEvent);
                continue;
            }

            if (SysGetThreadProcessId(dwThreadId) != GetCurrentProcessId())
            {
                SetObjectToLowIntegrity(hEvent);

                TCHAR szMappingName[20];
                GetMappingName(szMappingName,dwThreadId,dwEventName);
                HANDLE hMapping=CreateFileMapping(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,sizeof(THREAD_MSG),szMappingName);
                if (hMapping)
                {
                    if (GetLastError() == ERROR_ALREADY_EXISTS)
                    {
                        SysCloseHandle(hEvent);
                        SysCloseHandle(hMapping);
                        continue;
                    }

                    SetObjectToLowIntegrity(hMapping);
                    THREAD_MSG *lpMapping=(THREAD_MSG *)MapViewOfFile(hMapping,FILE_MAP_ALL_ACCESS,0,0,0);
                    if (lpMapping)
                    {
                        lpMapping->uMsg=uMsg;
                        lpMapping->wParam=wParam;
                        lpMapping->lParam=lParam;

                        if (PostThreadMessage(dwThreadId,TM_SYSTEMMESSAGE,REMOTE_PROCESS_MESSAGE,(LPARAM)dwEventName))
                        {
                            WaitForSingleObject(hEvent,INFINITE);
                            lRes=lpMapping->lResult;
                        }
                        UnmapViewOfFile(lpMapping);
                    }
                    SysCloseHandle(hMapping);
                }
            }
            else
            {
                THREAD_MSG tmMessage={0};
                tmMessage.uMsg=uMsg;
                tmMessage.wParam=wParam;
                tmMessage.lParam=lParam;
                tmMessage.hEvent=hEvent;

                if (PostThreadMessage(dwThreadId,TM_SYSTEMMESSAGE,SELF_PROCESS_MESSAGE,(LPARAM)&tmMessage))
                {
                    WaitForSingleObject(hEvent,INFINITE);
                    lRes=tmMessage.lResult;
                }
            }
            SysCloseHandle(hEvent);
            break;
        }
    }
    return lRes;
}

SYSLIBFUNC(BOOL) PeekThreadMessage(PMSG lpMsg)
{
    if (!SYSLIB_SAFE::CheckParamWrite(lpMsg,sizeof(lpMsg)))
        return false;

    BOOL bRet=FALSE;
    if (PeekMessage(lpMsg,(HWND)INVALID_HANDLE_VALUE,0,0,PM_REMOVE))
    {
        bRet=TRUE;
        if (lpMsg->message == TM_SYSTEMMESSAGE)
        {
            do
            {
                if (lpMsg->wParam == REMOTE_PROCESS_MESSAGE) /// Из другого процесса
                {
                    DWORD dwEventName=(DWORD)lpMsg->lParam;
                    TCHAR szEventName[20];
                    GetEventName(szEventName,GetCurrentThreadId(),dwEventName);

                    HANDLE hEvent=OpenEvent(EVENT_ALL_ACCESS,false,szEventName);
                    if (hEvent)
                    {
                        TCHAR szMappingName[20];
                        GetMappingName(szMappingName,GetCurrentThreadId(),dwEventName);

                        HANDLE hMapping=OpenFileMapping(FILE_MAP_ALL_ACCESS,false,szMappingName);
                        if (hMapping)
                        {
                            THREAD_MSG *lpThreadMsg=(THREAD_MSG *)MapViewOfFile(hMapping,FILE_MAP_ALL_ACCESS,0,0,0);
                            if (lpThreadMsg)
                            {
                                lpMsg->message=lpThreadMsg->uMsg;
                                lpMsg->wParam=lpThreadMsg->wParam;
                                lpMsg->lParam=lpThreadMsg->lParam;
                                lpMsg->time=-1;

                                THREAD_MSG_INTERNALS *lpInternals=(THREAD_MSG_INTERNALS*)MemAlloc(sizeof(THREAD_MSG_INTERNALS));
                                lpInternals->hEvent=hEvent;
                                lpInternals->hMapping=hMapping;
                                lpInternals->lpThreadMsg=lpThreadMsg;
                                lpMsg->hwnd=(HWND)lpInternals;
                                lpInternals->bRemoteProcess=true;
                                break;
                            }
                            SysCloseHandle(hMapping);
                        }
                        SysCloseHandle(hEvent);
                    }
                }
                else if (lpMsg->wParam == SELF_PROCESS_MESSAGE) /// Из нашего процесса
                {
                    THREAD_MSG *lpThreadMsg=(THREAD_MSG *)lpMsg->lParam;
                    if (lpThreadMsg)
                    {
                        lpMsg->message=lpThreadMsg->uMsg;
                        lpMsg->wParam=lpThreadMsg->wParam;
                        lpMsg->lParam=lpThreadMsg->lParam;
                        lpMsg->time=-1;

                        THREAD_MSG_INTERNALS *lpInternals=(THREAD_MSG_INTERNALS*)MemAlloc(sizeof(THREAD_MSG_INTERNALS));
                        lpInternals->hEvent=lpThreadMsg->hEvent;
                        lpInternals->lpThreadMsg=lpThreadMsg;
                        lpMsg->hwnd=(HWND)lpInternals;
                        break;
                    }
                }
            }
            while (false);
        }
    }
    return bRet;
}

SYSLIBFUNC(LRESULT) DispatchThreadMessage(const PMSG lpMsg,THREADPROC lpfnThreadProc)
{
    if (!SYSLIB_SAFE::CheckParamRead(lpMsg,sizeof(*lpMsg)))
        return 0;

    LRESULT lRes=0;
    if ((lpMsg->time == -1) && (SYSLIB_SAFE::CheckParamRead(lpMsg->hwnd,sizeof(THREAD_MSG_INTERNALS))))
    {
        if ((lpfnThreadProc) && (SYSLIB_SAFE::CheckCodePtr(lpfnThreadProc)))
            lRes=lpfnThreadProc(lpMsg->message,lpMsg->wParam,lpMsg->lParam);
        THREAD_MSG_INTERNALS *lpInternals=(THREAD_MSG_INTERNALS*)lpMsg->hwnd;
        lpInternals->lpThreadMsg->lResult=lRes;
        SetEvent(lpInternals->hEvent);
        if (lpInternals->bRemoteProcess)
        {
            SysCloseHandle(lpInternals->hEvent);
            UnmapViewOfFile(lpInternals->lpThreadMsg);
            SysCloseHandle(lpInternals->hMapping);
        }
        MemFree(lpInternals);
    }
    return lRes;
}

