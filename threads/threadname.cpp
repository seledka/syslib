#include "sys_includes.h"

#include "syslib\str.h"
#include "syslib\mem.h"

#include "threadname.h"

SYSLIBFUNC(void) SysSetThreadNameA(DWORD dwThreadId,LPCSTR lpThreadName)
{
    if ((lpThreadName) && (!SYSLIB_SAFE::CheckStrParamA(lpThreadName,0)))
        return;

    Sleep(10);
    THREADNAME_INFO Info;
    Info.dwType=0x1000;
    Info.szName=lpThreadName;
    Info.dwThreadID=dwThreadId;
    Info.dwFlags=0;

    __try {
        RaiseException(MS_VC_EXCEPTION,0,sizeof(Info)/sizeof(ULONG_PTR),(ULONG_PTR*)&Info);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

    return;
}

SYSLIBFUNC(void) SysSetThreadNameW(DWORD dwThreadId,LPCWSTR lpThreadName)
{
    LPSTR lpThreadNameA=StrUnicodeToAnsiEx(lpThreadName,0,NULL);
    SysSetThreadNameA(dwThreadId,lpThreadNameA);
    MemFree(lpThreadNameA);
    return;
}

