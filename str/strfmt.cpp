#include "sys_includes.h"
#include <shlwapi.h>

#include "scanf.h"
#include "wsprintf.h"
#include "strfmt.h"
#include "syslib\debug.h"
#include "syslib\mem.h"

SYSLIBFUNC(LPWSTR) StrDuplicateW(LPCWSTR lpSource,DWORD dwSize)
{
    LPWSTR lpOut=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpSource,dwSize))
            break;

        if (!dwSize)
        {
            dwSize=lstrlenW(lpSource);
            if (!dwSize)
                break;
        }

        lpOut=WCHAR_QuickAlloc(dwSize+1);
        if (!lpOut)
            break;

        lstrcpynW(lpOut,lpSource,dwSize+1);
    }
    while (false);

    return lpOut;
}

SYSLIBFUNC(LPSTR) StrDuplicateA(LPCSTR lpSource,DWORD dwSize)
{
    LPSTR lpOut=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamA(lpSource,dwSize))
            break;

        if (!dwSize)
        {
            dwSize=lstrlenA(lpSource);
            if (!dwSize)
                break;
        }

        lpOut=(char*)MemQuickAlloc(dwSize+1);
        if (!lpOut)
            break;

        lstrcpynA(lpOut,lpSource,dwSize+1);
    }
    while (false);

    return lpOut;
}

namespace SYSLIB
{
    DWORD wsprintfExW(LPWSTR *lppBuffer,DWORD dwOffset,LPCWSTR lpFormat,va_list args)
    {
        DWORD dwNewSize=0;
        do
        {
            DWORD dwBufferSize=StrFmt_FormatStringW(NULL,lpFormat,args);
            if (!dwBufferSize)
                break;

            LPWSTR lpBuffer=WCHAR_Realloc(*lppBuffer,dwBufferSize+dwOffset+1);
            if (!lpBuffer)
                break;

            dwNewSize=StrFmt_FormatStringW(lpBuffer+dwOffset,lpFormat,args);
            if (!dwNewSize)
                break;

            dwNewSize+=dwOffset;
            *lppBuffer=lpBuffer;
        }
        while (false);

        return dwNewSize;
    }

    DWORD wsprintfExA(LPSTR *lppBuffer,DWORD dwOffset,LPCSTR lpFormat,va_list args)
    {
        DWORD dwNewSize=0;
        do
        {
            DWORD dwBufferSize=StrFmt_FormatStringA(NULL,lpFormat,args);
            if (!dwBufferSize)
                break;

            LPSTR lpBuffer=(LPSTR)MemRealloc(*lppBuffer,dwBufferSize+dwOffset+1);
            if (!lpBuffer)
                break;

            dwNewSize=StrFmt_FormatStringA(lpBuffer+dwOffset,lpFormat,args);
            if (!dwNewSize)
                break;

            dwNewSize+=dwOffset;
            *lppBuffer=lpBuffer;
        }
        while (false);

        return dwNewSize;
    }
}

SYSLIBFUNC(DWORD) StrFormatW(LPWSTR lpDest,LPCWSTR lpFormat,...)
{
    DWORD dwNewSize=0;
    __try
    {
        va_list list;
        va_start(list,lpFormat);
        dwNewSize=SYSLIB::StrFmt_FormatStringW(lpDest,lpFormat,list);
        va_end(list);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

    return dwNewSize;
}

SYSLIBFUNC(DWORD) StrFormatA(LPSTR lpDest,LPCSTR lpFormat,...)
{
    DWORD dwNewSize=0;
    __try
    {
        va_list list;
        va_start(list,lpFormat);
        dwNewSize=SYSLIB::StrFmt_FormatStringA(lpDest,lpFormat,list);
        va_end(list);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

    return dwNewSize;
}

SYSLIBFUNC(DWORD) StrFormatExW(LPWSTR *lppDest,LPCWSTR lpFormat,...)
{
    if (!SYSLIB_SAFE::CheckParamWrite(lppDest,sizeof(*lppDest)))
        return 0;

    DWORD dwNewSize=0;
    __try
    {
        LPWSTR lpNewBuf=NULL;

        va_list list;
        va_start(list,lpFormat);
        dwNewSize=SYSLIB::wsprintfExW(&lpNewBuf,0,lpFormat,list);
        va_end(list);

        if (dwNewSize)
            *lppDest=lpNewBuf;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    return dwNewSize;
}

SYSLIBFUNC(DWORD) StrFormatExA(LPSTR *lppDest,LPCSTR lpFormat,...)
{
    if (!SYSLIB_SAFE::CheckParamWrite(lppDest,sizeof(*lppDest)))
        return 0;

    DWORD dwNewSize=0;
    __try
    {
        LPSTR lpNewBuf=NULL;

        va_list list;
        va_start(list,lpFormat);
        dwNewSize=SYSLIB::wsprintfExA(&lpNewBuf,0,lpFormat,list);
        va_end(list);

        if (dwNewSize)
            *lppDest=lpNewBuf;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    return dwNewSize;
}

SYSLIBFUNC(DWORD) StrCatFormatExW(LPWSTR *lppDest,DWORD dwDestSize,LPCWSTR lpFormat,...)
{
    if (!SYSLIB_SAFE::CheckParamWrite(lppDest,sizeof(*lppDest)))
        return 0;

    DWORD dwNewSize=0;
    __try
    {
        if (!dwDestSize)
            dwDestSize=lstrlenW(*lppDest);

        va_list list;
        va_start(list,lpFormat);
        dwNewSize=SYSLIB::wsprintfExW(lppDest,dwDestSize,lpFormat,list);
        va_end(list);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    return dwNewSize;
}

SYSLIBFUNC(DWORD) StrCatFormatExA(LPSTR *lppDest,DWORD dwDestSize,LPCSTR lpFormat,...)
{
    if (!SYSLIB_SAFE::CheckParamWrite(lppDest,sizeof(*lppDest)))
        return 0;

    DWORD dwNewSize=0;
    __try
    {
        if (!dwDestSize)
            dwDestSize=lstrlenA(*lppDest);

        va_list list;
        va_start(list,lpFormat);
        dwNewSize=SYSLIB::wsprintfExA(lppDest,dwDestSize,lpFormat,list);
        va_end(list);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    return dwNewSize;
}

SYSLIBFUNC(DWORD) StrCatFormatW(LPWSTR lpDest,DWORD dwDestSize,LPCWSTR lpFormat,...)
{
    DWORD dwNewSize=0;
    __try
    {
        if (!dwDestSize)
            dwDestSize=lstrlenW(lpDest);

        va_list list;
        va_start(list,lpFormat);
        WCHAR *lpStrFmt=NULL;
        dwNewSize=SYSLIB::wsprintfExW(&lpStrFmt,0,lpFormat,list);
        va_end(list);

        if (dwNewSize)
        {
            lstrcatW(lpDest,lpStrFmt);
            MemFree(lpStrFmt);
        }

        dwNewSize+=dwDestSize;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    return dwNewSize;
}

SYSLIBFUNC(DWORD) StrCatFormatA(LPSTR lpDest,DWORD dwDestSize,LPCSTR lpFormat,...)
{
    DWORD dwNewSize=0;
    __try
    {
        if (!dwDestSize)
            dwDestSize=lstrlenA(lpDest);

        va_list list;
        va_start(list,lpFormat);
        LPSTR lpStrFmt=NULL;
        dwNewSize=SYSLIB::wsprintfExA(&lpStrFmt,0,lpFormat,list);
        va_end(list);

        if (dwNewSize)
        {
            lstrcatA(lpDest,lpStrFmt);
            MemFree(lpStrFmt);
        }

        dwNewSize+=dwDestSize;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    return dwNewSize;
}

SYSLIBFUNC(DWORD) StrCatExW(LPWSTR *lppDest,LPCWSTR lpSource,DWORD dwSourceSize)
{
    if (!SYSLIB_SAFE::CheckParamWrite(lppDest,sizeof(*lppDest)))
        return 0;

    DWORD dwNewSize=0;
    __try
    {
        if (!dwSourceSize)
            dwSourceSize=lstrlenW(lpSource);

        DWORD dwPrevSize=lstrlenW(*lppDest);

        dwNewSize=dwPrevSize+dwSourceSize;

        *lppDest=WCHAR_Realloc(*lppDest,dwNewSize+1);
        if (*lppDest)
            lstrcpynW(*lppDest+dwPrevSize,lpSource,dwSourceSize+1);
        else
            dwNewSize=0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    return dwNewSize;
}

SYSLIBFUNC(DWORD) StrCatExA(LPSTR *lppDest,LPCSTR lpSource,DWORD dwSourceSize)
{
    if (!SYSLIB_SAFE::CheckParamWrite(lppDest,sizeof(*lppDest)))
        return 0;

    DWORD dwNewSize=0;
    __try
    {
        if (!dwSourceSize)
            dwSourceSize=lstrlenA(lpSource);

        DWORD dwPrevSize=lstrlenA(*lppDest);

        dwNewSize=dwPrevSize+dwSourceSize;

        *lppDest=(char*)MemRealloc(*lppDest,dwNewSize+1);
        if (*lppDest)
            lstrcpynA(*lppDest+dwPrevSize,lpSource,dwSourceSize+1);
        else
            dwNewSize=0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    return dwNewSize;
}

SYSLIBFUNC(DWORD) StrScanFormatW(LPCWSTR lpString,LPCWSTR lpFormat,...)
{
    DWORD dwParams=0;
    __try
    {
        va_list list;
        va_start(list,lpFormat);
        dwParams=SYSLIB::StrFmt_ScanStringW(lpString,lpFormat,list);
        va_end(list);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    return dwParams;
}

SYSLIBFUNC(DWORD) StrScanFormatA(LPCSTR lpString,LPCSTR lpFormat,...)
{
    DWORD dwParams=0;
    __try
    {
        va_list list;
        va_start(list,lpFormat);
        dwParams=SYSLIB::StrFmt_ScanStringA(lpString,lpFormat,list);
        va_end(list);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    return dwParams;
}

