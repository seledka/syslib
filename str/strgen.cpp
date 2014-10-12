#include "sys_includes.h"

#include <syslib\utils.h>
#include <syslib\mem.h>
#include <syslib\str.h>

#include <syslib\strcrypt.h>
#include "str_crx.h"

static LPWSTR GenerateStrBuffer(DWORD dwFlags,LPDWORD lpSize)
{
    DWORD dwSize;
    LPWSTR lpBuf=NULL;
    if (dwFlags & STRGEN_UPPERCASE)
        dwSize=StrCatExW(&lpBuf,dcrW_d103a288("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),0);
    if (dwFlags & STRGEN_LOWERCASE)
        dwSize=StrCatExW(&lpBuf,dcrW_a34e036d("abcdefghijklmnopqrstuvwxyz"),0);
    if (dwFlags & STRGEN_DIGITS)
        dwSize=StrCatExW(&lpBuf,dcrW_70b9a121("0123456789"),0);
    if (dwFlags & STRGEN_MINUS)
        dwSize=StrCatExW(&lpBuf,dcrW_f945531f("-"),0);
    if (dwFlags & STRGEN_UNDERLINE)
        dwSize=StrCatExW(&lpBuf,dcrW_352aeb03("_"),0);
    if (dwFlags & STRGEN_SPACE)
        dwSize=StrCatExW(&lpBuf,dcrW_7ef49b98(" "),0);
    if (dwFlags & STRGEN_SPECIAL)
        dwSize=StrCatExW(&lpBuf,dcrW_594ac591("~!@#$%^&*+="),0);
    if (dwFlags & STRGEN_BRACKETS)
        dwSize=StrCatExW(&lpBuf,dcrW_72859cbb("[]{}()<>"),0);

    *lpSize=dwSize;
    return lpBuf;
}

SYSLIBFUNC(BOOL) StrGenerateW(LPWSTR lpStr,DWORD dwSize,DWORD dwFlags)
{
    BOOL bRet=false;
    do
    {
        if (!(dwFlags & (STRGEN_UPPERCASE|STRGEN_LOWERCASE|STRGEN_DIGITS|STRGEN_MINUS|STRGEN_UNDERLINE|STRGEN_SPACE|STRGEN_SPECIAL|STRGEN_BRACKETS)))
            break;

        if (dwSize <= 1)
            break;

        if (!SYSLIB_SAFE::CheckStrParamW(lpStr,dwSize))
            break;

        DWORD dwBufSize;
        LPWSTR lpBuf=GenerateStrBuffer(dwFlags,&dwBufSize);
        if (!lpBuf)
            break;

        for (int i=0; i < dwSize-1; i++)
            lpStr[i]=lpBuf[xor128(dwBufSize)];

        lpStr[dwSize-1]=0;
        MemFree(lpBuf);

        bRet=true;
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) StrGenerateA(LPSTR lpStr,DWORD dwSize,DWORD dwFlags)
{
    BOOL bRet=false;
    do
    {
        if (!(dwFlags & (STRGEN_UPPERCASE|STRGEN_LOWERCASE|STRGEN_DIGITS|STRGEN_MINUS|STRGEN_UNDERLINE|STRGEN_SPACE|STRGEN_SPECIAL|STRGEN_BRACKETS)))
            break;

        if (dwSize <= 1)
            break;

        if (!SYSLIB_SAFE::CheckStrParamA(lpStr,dwSize))
            break;

        LPWSTR lpStrW=WCHAR_QuickAlloc(dwSize);
        if (!lpStrW)
            break;

        bRet=StrGenerateW(lpStrW,dwSize,dwFlags);
        if (bRet)
            StrUnicodeToAnsi(lpStrW,0,lpStr,0);

        MemFree(lpStrW);
    }
    while (false);
    return bRet;
}

