#include "sys_includes.h"

#include "lnk.h"
#include "reg.h"
#include "syslib\mem.h"
#include "syslib\arun.h"
#include "syslib\osenv.h"
#include "syslib\str.h"

SYSLIBFUNC(BOOL) Arun_AppendFileToUserW(LPCWSTR lpFile,PSID lpSid)
{
    BOOL bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
            break;

        if (!SYSLIB_SAFE::CheckParamRead(lpSid,sizeof(SID)))
            break;

        DWORD dwResult=(DWORD)(SYSLIB::ArunLnk_AppendFileToUserW(lpFile,lpSid) != false);
        dwResult+=(DWORD)(SYSLIB::ArunReg_AppendFileToUserW(lpFile,lpSid) != false);

        bRet=(dwResult != 0);
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) Arun_AppendFileToUserA(LPCSTR lpFile,PSID lpSid)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=Arun_AppendFileToUserW(lpFileNameW,lpSid);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(BOOL) Arun_AppendFileW(LPCWSTR lpFile)
{
    BOOL bRet=false;
    PSID lpSid;
    if (SysGetCurrentUserSID(&lpSid))
    {
        bRet=Arun_AppendFileToUserW(lpFile,lpSid);
        MemFree(lpSid);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) Arun_AppendFileA(LPCSTR lpFile)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=Arun_AppendFileW(lpFileNameW);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(BOOL) Arun_AppendFileToAllUsersW(LPCWSTR lpFile)
{
    BOOL bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
            break;

        DWORD dwResult=(DWORD)(SYSLIB::ArunLnk_AppendFileToAllUsersW(lpFile) != false);
        dwResult+=(DWORD)(SYSLIB::ArunReg_AppendFileToAllUsersW(lpFile) != false);

        bRet=(dwResult != 0);
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) Arun_AppendFileToAllUsersA(LPCSTR lpFile)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=Arun_AppendFileToAllUsersW(lpFileNameW);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(BOOL) Arun_CheckUserStartupW(LPCWSTR lpFile,PSID lpSid)
{
    BOOL bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
            break;

        if (!SYSLIB_SAFE::CheckParamRead(lpSid,sizeof(SID)))
            break;

        bRet=SYSLIB::ArunLnk_CheckUserStartupW(lpFile,lpSid);
        if (bRet)
            break;

        bRet=SYSLIB::ArunReg_CheckUserStartupW(lpFile,lpSid);
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) Arun_CheckUserStartupA(LPCSTR lpFile,PSID lpSid)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=Arun_CheckUserStartupW(lpFileNameW,lpSid);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(BOOL) Arun_CheckStartupW(LPCWSTR lpFile)
{
    BOOL bRet=false;
    PSID lpSid;
    if (SysGetCurrentUserSID(&lpSid))
    {
        bRet=Arun_CheckUserStartupW(lpFile,lpSid);
        MemFree(lpSid);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) Arun_CheckStartupA(LPCSTR lpFile)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=Arun_CheckStartupW(lpFileNameW);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(BOOL) Arun_RemoveFileW(LPCWSTR lpFile)
{
    BOOL bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
            break;

        DWORD dwResult=(SYSLIB::ArunLnk_RemoveW(lpFile) != false);
        dwResult+=(SYSLIB::ArunReg_RemoveW(lpFile) != false);

        bRet=(dwResult != 0);
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) Arun_RemoveFileA(LPCSTR lpFile)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=Arun_RemoveFileW(lpFileNameW);

    MemFree(lpFileNameW);
    return bRet;
}

