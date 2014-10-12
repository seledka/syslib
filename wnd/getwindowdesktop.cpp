#include "sys_includes.h"

#include "getwnddesk.h"
#include "syslib\threadmessage.h"
#include "syslib\system.h"

static BOOL WINAPI EnumWindowsProc(HWND hWnd,LPARAM lParam)
{
    BOOL bRet=TRUE;
    HWND_TO_HDESK *lpTmp=(HWND_TO_HDESK*)lParam;
    if (lpTmp->hWnd == hWnd)
    {
        lpTmp->bFound=true;
        bRet=FALSE;
    }
    return bRet;
}

static BOOL WINAPI EnumDesktopProc(LPTSTR lpszDesktop,LPARAM lParam)
{
    BOOL bRet=TRUE;
    HDESK hDesk=OpenDesktop(lpszDesktop,0,false,GENERIC_READ);
    if (hDesk)
    {
        HWND_TO_HDESK *lpTmp=(HWND_TO_HDESK*)lParam;
        EnumDesktopWindows(hDesk,EnumWindowsProc,lParam);
        if (lpTmp->bFound)
        {
            lpTmp->hDesk=hDesk;
            bRet=FALSE;
        }
        else
            CloseDesktop(hDesk);
    }
    return bRet;
}

static LRESULT WINAPI MsgDispatcher(UINT uMsg,WPARAM wParam,LPARAM lParam)
{
    LRESULT lRes=0;
    if (uMsg == TM_GETDESK)
    {
        HWND_TO_HDESK tmp={0};
        tmp.hWnd=(HWND)lParam;
        EnumDesktops(GetProcessWindowStation(),EnumDesktopProc,(LPARAM)&tmp);
        lRes=(LRESULT)tmp.hDesk;
    }
    return lRes;
}

static void WINAPI GetWndDeskThread(HANDLE hEvent)
{
    InitThreadMessageQueue();
    SetEvent(hEvent);

    MSG msg;
    while (true)
    {
        if (PeekThreadMessage(&msg))
        {
            DispatchThreadMessage(&msg,MsgDispatcher);
            if (msg.message == TM_GETDESK)
                return;
        }
        Sleep(1);
    }
    return;
}

SYSLIBFUNC(HDESK) GetWindowDesktop(HWND hWnd)
{
    DWORD dwThread;
    HANDLE hEvent=CreateEvent(NULL,true,false,NULL);
    SysCloseHandle(CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)GetWndDeskThread,hEvent,0,&dwThread));
    WaitForSingleObject(hEvent,INFINITE);
    SysCloseHandle(hEvent);
    return (HDESK)SendThreadMessage(dwThread,TM_GETDESK,NULL,(LPARAM)hWnd);
}

