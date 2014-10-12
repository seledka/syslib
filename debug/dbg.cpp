#include "sys_includes.h"
#include <tlhelp32.h>

#include "syslib\mem.h"
#include "syslib\system.h"
#include "syslib\str.h"
#include "str\strfmt.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

static DWORD DbgPrintIntW(LPWSTR *lppOut,LPCWSTR lpMsg,va_list args)
{
    DWORD dwSize=0;
    LPWSTR lpBuf=NULL,
           lpOut=NULL;

    __try {
        SYSLIB::wsprintfExW(&lpBuf,0,lpMsg,args);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

    WCHAR szProcName[250];
    SysProcNameByPIDW(GetCurrentProcessId(),szProcName,ARRAYSIZE(szProcName));

#ifdef _X86_
    dwSize=StrFormatExW(&lpOut,dcrW_8d6ccf45("[%s *32], %s"),szProcName,lpBuf);
#else
    dwSize=StrFormatExW(&lpOut,dcrW_3d1ec16b("[%s *64], %s"),szProcName,lpBuf);
#endif

    if (dwSize)
        *lppOut=lpOut;

    MemFree(lpBuf);
    return dwSize;
}

SYSLIBFUNC(void) dprintfW(LPCWSTR lpMsg, ...)
{
#ifdef _DEBUG
    if (!SYSLIB_SAFE::CheckStrParamW(lpMsg,0))
        return;

    DWORD dwGLE=GetLastError();

    va_list args;

    LPWSTR lpOut=NULL;
    va_start(args,lpMsg);
    DbgPrintIntW(&lpOut,lpMsg,args);
    va_end(args);

    if (lpOut)
    {
        OutputDebugStringW(lpOut);
        MemFree(lpOut);
    }

    SetLastError(dwGLE);
#endif
    return;
}

static DWORD DbgPrintIntA(LPSTR *lppOut,LPCSTR lpMsg,va_list args)
{
    DWORD dwSize=0;
    LPSTR lpBuf=NULL,
          lpOut=NULL;

    __try {
        SYSLIB::wsprintfExA(&lpBuf,0,lpMsg,args);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

    char szProcName[250];
    SysProcNameByPIDA(GetCurrentProcessId(),szProcName,ARRAYSIZE(szProcName));

#ifdef _X86_
    dwSize=StrFormatExA(&lpOut,dcrA_8d6ccf45("[%s *32], %s"),szProcName,lpBuf);
#else
    dwSize=StrFormatExA(&lpOut,dcrA_3d1ec16b("[%s *64], %s"),szProcName,lpBuf);
#endif

    if (dwSize)
        *lppOut=lpOut;

    MemFree(lpBuf);
    return dwSize;
}

SYSLIBFUNC(void) dprintfA(LPCSTR lpMsg, ...)
{
#ifdef _DEBUG
    if (!SYSLIB_SAFE::CheckStrParamA(lpMsg,0))
        return;

    DWORD dwGLE=GetLastError();

    va_list args;

    LPSTR lpOut=NULL;
    va_start(args,lpMsg);
    DbgPrintIntA(&lpOut,lpMsg,args);
    va_end(args);

    if (lpOut)
    {
        OutputDebugStringA(lpOut);
        MemFree(lpOut);
    }

    SetLastError(dwGLE);
#endif
    return;
}

SYSLIBFUNC(void) fdprintfW(LPCWSTR lpFile,LPCWSTR lpMsg, ...)
{
#ifdef _DEBUG
    DWORD dwGLE=GetLastError();

    va_list args;

    LPWSTR lpOut=NULL;
    va_start(args,lpMsg);
    DWORD dwSize=DbgPrintIntW(&lpOut,lpMsg,args);
    va_end(args);

    if (lpOut)
    {
        HANDLE hFile=CreateFileW(lpFile,GENERIC_WRITE,0,NULL,OPEN_ALWAYS,0,NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            SetFilePointer(hFile,0,NULL,FILE_END);
            DWORD tmp;
            WriteFile(hFile,lpOut,dwSize*sizeof(WCHAR),&tmp,NULL);
            SysCloseHandle(hFile);
        }
        MemFree(lpOut);
    }

    SetLastError(dwGLE);
#endif
    return;
}

SYSLIBFUNC(void) fdprintfA(LPCSTR lpFile,LPCSTR lpMsg, ...)
{
#ifdef _DEBUG
    DWORD dwGLE=GetLastError();

    va_list args;

    LPSTR lpOut=NULL;
    va_start(args,lpMsg);
    DWORD dwSize=DbgPrintIntA(&lpOut,lpMsg,args);
    va_end(args);

    if (lpOut)
    {
        HANDLE hFile=CreateFileA(lpFile,GENERIC_WRITE,0,NULL,OPEN_ALWAYS,0,NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            SetFilePointer(hFile,0,NULL,FILE_END);
            DWORD tmp;
            WriteFile(hFile,lpOut,dwSize,&tmp,NULL);
            SysCloseHandle(hFile);
        }
        MemFree(lpOut);
    }

    SetLastError(dwGLE);
#endif
    return;
}

SYSLIBFUNC(void) dprintf_wndW(HWND hWnd,LPCWSTR lpStr)
{
#ifdef _DEBUG
    DWORD dwGLE=GetLastError();

    WCHAR szClass[260],szTitle[260];
    DWORD dwStyle=0,dwExStyle=0;
    if (hWnd)
    {
        GetClassNameW(hWnd,szClass,260);
        if (!GetWindowTextW(hWnd,szTitle,260))
            lstrcpyW(szTitle,dcrW_ce4eab6f("NULL"));
        dwStyle=GetWindowLongPtr(hWnd,GWL_STYLE);
        dwExStyle=GetWindowLongPtr(hWnd,GWL_EXSTYLE);
    }
    else
    {
        lstrcpyW(szClass,dcrW_ce4eab6f("NULL"));
        lstrcpyW(szTitle,dcrW_ce4eab6f("NULL"));
    }
    dprintfW(dcrW_34498ca6("%s[%s] %X, %X, %s"),lpStr,szClass,dwStyle,dwExStyle,szTitle);

    SetLastError(dwGLE);
#endif
    return;
}

SYSLIBFUNC(void) dprintf_wndA(HWND hWnd,LPSTR lpStr)
{
#ifdef _DEBUG
    DWORD dwGLE=GetLastError();

    char szClass[260],szTitle[260];
    DWORD dwStyle=0,dwExStyle=0;
    if (hWnd)
    {
        GetClassNameA(hWnd,szClass,260);
        if (!GetWindowTextA(hWnd,szTitle,260))
            lstrcpyA(szTitle,dcrA_ce4eab6f("NULL"));
        dwStyle=GetWindowLongPtr(hWnd,GWL_STYLE);
        dwExStyle=GetWindowLongPtr(hWnd,GWL_EXSTYLE);
    }
    else
    {
        lstrcpyA(szClass,dcrA_ce4eab6f("NULL"));
        lstrcpyA(szTitle,dcrA_ce4eab6f("NULL"));
    }
    dprintfA(dcrA_34498ca6("%s[%s] %X, %X, %s"),lpStr,szClass,dwStyle,dwExStyle,szTitle);

    SetLastError(dwGLE);
#endif
    return;
}

