#include "sys_includes.h"

#include "syslib\systray.h"
#include "syslib\system.h"
#include "system_tray.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

static bool EnumIconsInt(HWND hWnd,_TRAY_ENUM_WND *lpParam)
{
    bool bContinue=true;
    DWORD dwCount=SendMessage(hWnd,TB_BUTTONCOUNT,NULL,NULL);

    while (dwCount)
    {
        SendMessage(hWnd,TB_GETBUTTON,dwCount,(LPARAM)lpParam->lpData);
        TNPRIVICON tnpi={0};
        if (!lpParam->b64)
        {
            TBBUTTON_X86 tbBtn={0};
            ReadProcessMemory(lpParam->hProc,lpParam->lpData,&tbBtn,sizeof(tbBtn),NULL);
#ifndef _X86_
            TNPRIVICON_X86 tnpi_x86={0};
            ReadProcessMemory(lpParam->hProc,(void*)tbBtn.dwData,&tnpi_x86,sizeof(tnpi_x86),NULL);
            tnpi.dwState=tnpi_x86.dwState;
            tnpi.hIcon=(HICON)tnpi_x86.hIcon;
            tnpi.hWnd=(HWND)tnpi_x86.hWnd;
            tnpi.uCallbackMessage=tnpi_x86.uCallbackMessage;
            tnpi.uID=tnpi_x86.uID;
            tnpi.uVersion=tnpi_x86.uVersion;
#else
            ReadProcessMemory(lpParam->hProc,(void*)tbBtn.dwData,&tnpi,sizeof(tnpi),NULL);
#endif
        }
        else
        {
            TBBUTTON_X64 tbBtn={0};
            ReadProcessMemory(lpParam->hProc,lpParam->lpData,&tbBtn,sizeof(tbBtn),NULL);
#ifdef _X86_
            TNPRIVICON_X64 tnpi_x64={0};
            ReadProcessMemory(lpParam->hProc,(void*)tbBtn.dwData,&tnpi_x64,sizeof(tnpi_x64),NULL);
            tnpi.dwState=tnpi_x64.dwState;
            tnpi.hIcon=tnpi_x64.hIcon;
            tnpi.hWnd=tnpi_x64.hWnd;
            tnpi.uCallbackMessage=tnpi_x64.uCallbackMessage;
            tnpi.uID=tnpi_x64.uID;
            tnpi.uVersion=tnpi_x64.uVersion;
#else
            ReadProcessMemory(lpParam->hProc,(void*)tbBtn.dwData,&tnpi,sizeof(tnpi),NULL);
#endif
        }

        if (!lpParam->lpEnumProc(hWnd,dwCount,&tnpi,lpParam->lpParam))
        {
            bContinue=false;
            break;
        }

        dwCount--;
    }
    return bContinue;
}

static bool EnumChilds(HWND hWnd,_TRAY_ENUM_WND *lpParam)
{
    bool bRet=true;
    do
    {
        if (IsWindow(hWnd))
        {
            TCHAR szClass[100];
            GetClassName(hWnd,szClass,ARRAYSIZE(szClass));

            if (!lstrcmpi(szClass,dcr_c6d76670("ToolbarWindow32")))
                bRet=EnumIconsInt(hWnd,lpParam);
            else
                bRet=EnumChilds(GetWindow(GetWindow(hWnd,GW_CHILD),GW_HWNDLAST),lpParam);

            if (!bRet)
                break;
        }
    }
    while (hWnd=GetWindow(hWnd,GW_HWNDPREV));
    return bRet;
}

SYSLIBFUNC(void) TrayEnumIcons(__EnumIconsProc *lpProc,LPVOID lpParam)
{
    if (!SYSLIB_SAFE::CheckCodePtr(lpProc))
        return;

    HWND hTaskbar=FindWindow(dcr_acce3ca3("Shell_TrayWnd"),NULL);
    if (hTaskbar)
    {
        hTaskbar=FindWindowEx(hTaskbar,NULL,dcr_4239d777("TrayNotifyWnd"),NULL);
        if (hTaskbar)
        {
            DWORD dwPID;
            GetWindowThreadProcessId(hTaskbar,&dwPID);
            HANDLE hProc=SysOpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ,dwPID);
            if (hProc)
            {
                void *lpData=VirtualAllocEx(hProc,NULL,sizeof(TBBUTTON_X64),MEM_COMMIT,PAGE_READWRITE);
                if (lpData)
                {
                    _TRAY_ENUM_WND tew={0};
                    tew.hProc=hProc;
                    tew.lpData=lpData;
                    tew.lpEnumProc=lpProc;
                    tew.lpParam=lpParam;

    #ifdef _X86_
                    if (SysIsWow64())
    #endif // _X86_
                        tew.b64=(SysIsWow64(hProc) == false);

                    if (EnumChilds(GetWindow(GetWindow(hTaskbar,GW_CHILD),GW_HWNDLAST),&tew))
                    {
                        hTaskbar=FindWindow(dcr_f446fc9e("NotifyIconOverflowWindow"),NULL);
                        if (hTaskbar)
                            EnumChilds(GetWindow(GetWindow(hTaskbar,GW_CHILD),GW_HWNDLAST),&tew);
                    }
                    VirtualFreeEx(hProc,lpData,0,MEM_RELEASE);
                }
                SysCloseHandle(hProc);
            }
        }
    }
    return;
}

