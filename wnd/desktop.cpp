#include "sys_includes.h"
#include <tlhelp32.h>

#include "syslib\mem.h"
#include "syslib\system.h"
#include "syslib\str.h"
#include "syslib\utils.h"

SYSLIBFUNC(BOOL) DeleteDesktop(HDESK hDesk)
{
    WCHAR szNeededDesk[MAX_PATH];
    if (!GetUserObjectInformationW(hDesk,UOI_NAME,szNeededDesk,ARRAYSIZE(szNeededDesk),NULL))
        return FALSE;

    BOOL bRet=false;

    DWORD_PTR dwLastPid=0;
    bool bRestart=true;
    while (bRestart)
    {
        bRet=true;
        bRestart=false;

        HANDLE hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
        if (hSnap != INVALID_HANDLE_VALUE)
        {
            THREADENTRY32 te32={0};
            te32.dwSize=sizeof(THREADENTRY32);
            if (Thread32First(hSnap,&te32))
            do
            {
                WCHAR szDeskName[MAX_PATH];
                if (GetThreadDesktopNameW(te32.th32ThreadID,szDeskName,ARRAYSIZE(szDeskName)))
                {
                    if (!lstrcmpiW(szNeededDesk,szDeskName))
                    {
                        if (dwLastPid != te32.th32OwnerProcessID)
                        {
                            dwLastPid=te32.th32OwnerProcessID;
                            SysTerminateProcess(dwLastPid,0);
                            bRestart=true;
                        }
                        else
                            bRet=false;

                        break;
                    }
                }
            }
            while (Thread32Next(hSnap,&te32));

            SysCloseHandle(hSnap);
        }
    }
    return bRet;
}

