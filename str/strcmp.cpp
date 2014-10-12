#include "sys_includes.h"
#include <shlwapi.h>

#include <syslib\str.h>
#include <syslib\mem.h>

#include "strcmp.h"

#include <syslib\strcrypt.h>
#include "str_crx.h"

static BOOL WINAPI ChrCmpW(WCHAR w1,WCHAR w2)
{
    return (w1 != w2);
}

namespace SYSLIB
{
    int StrCmpFmtExW(LPCWSTR lpStr,LPCWSTR lpMask,LPDWORD lpdwSubStrSize,WCHAR wMaskChar,bool bInsensitive)
    {
        if (!SYSLIB_SAFE::CheckParamWrite(lpdwSubStrSize,sizeof(*lpdwSubStrSize)))
            lpdwSubStrSize=NULL;

        int dwRet=0;
        __try {
            __CHRCMPW *lpChrCmp=ChrCmpW;
            if (bInsensitive)
                lpChrCmp=ChrCmpIW;

            bool bAsterix=false;
            DWORD dwStrPos=0,dwMaskPos=0,dwAsterixPos=0;
            while (lpStr[dwStrPos])
            {
                if (!lpMask[dwMaskPos])
                {
                    if (!dwMaskPos)
                    {
                        dwRet=1;
                        break;
                    }
                    else
                    {
                        if (lpMask[dwMaskPos-1] == L'*')
                            break;
                        else if (!lpChrCmp(lpStr[dwStrPos-1],lpMask[dwMaskPos-1] ))
                        {
                            dwRet=1;
                            break;
                        }
                    }
                }

                if (bAsterix)
                {
                    dwRet=1;
                    if (!lpChrCmp(lpStr[dwStrPos],lpMask[dwMaskPos]))
                    {
                        dwMaskPos++;
                        bAsterix=false;
                        dwRet=0;
                    }
                    dwStrPos++;
                }
                else
                {
                    if (lpMask[dwMaskPos] == wMaskChar)
                    {
                        dwStrPos++;
                        dwMaskPos++;
                    }
                    else if (lpMask[dwMaskPos] == L'*')
                    {
                        dwMaskPos++;
                        dwAsterixPos=dwMaskPos;
                        bAsterix=true;
                    }
                    else
                    {
                        if (!lpChrCmp(lpStr[dwStrPos],lpMask[dwMaskPos]))
                        {
                            dwStrPos++;
                            dwMaskPos++;
                        }
                        else if (dwAsterixPos)
                        {
                            dwMaskPos=dwAsterixPos;
                            bAsterix=true;
                        }
                        else
                        {
                            dwRet=1;
                            break;
                        }
                    }
                }
            }
            if ((!dwRet) && (lpdwSubStrSize))
                *lpdwSubStrSize=dwStrPos;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            dwRet=-1;
        }
        return dwRet;
    }
}

static BOOL WINAPI ChrCmpA(WORD c1,WORD c2)
{
    return (c1 != c2);
}

namespace SYSLIB
{
    int StrCmpFmtExA(LPCSTR lpStr,LPCSTR lpMask,LPDWORD lpdwSubStrSize,char cMaskChar,bool bInsensitive)
    {
        if (!SYSLIB_SAFE::CheckParamWrite(lpdwSubStrSize,sizeof(*lpdwSubStrSize)))
            lpdwSubStrSize=NULL;

        int dwRet=0;
        __try {
            __CHRCMPA *lpChrCmp=ChrCmpA;
            if (bInsensitive)
                lpChrCmp=ChrCmpIA;

            bool bAsterix=false;
            DWORD dwStrPos=0,dwMaskPos=0,dwAsterixPos=0;
            while (lpStr[dwStrPos])
            {
                if (!lpMask[dwMaskPos])
                {
                    if (!dwMaskPos)
                    {
                        dwRet=1;
                        break;
                    }
                    else
                    {
                        if (lpMask[dwMaskPos-1] == '*')
                            break;
                        else if (!lpChrCmp(lpStr[dwStrPos-1],lpMask[dwMaskPos-1] ))
                        {
                            dwRet=1;
                            break;
                        }
                    }
                }

                if (bAsterix)
                {
                    dwRet=1;
                    if (!lpChrCmp(lpStr[dwStrPos],lpMask[dwMaskPos]))
                    {
                        dwMaskPos++;
                        bAsterix=false;
                        dwRet=0;
                    }
                    dwStrPos++;
                }
                else
                {
                    if (lpMask[dwMaskPos] == cMaskChar)
                    {
                        dwStrPos++;
                        dwMaskPos++;
                    }
                    else if (lpMask[dwMaskPos] == '*')
                    {
                        dwMaskPos++;
                        dwAsterixPos=dwMaskPos;
                        bAsterix=true;
                    }
                    else
                    {
                        if (!lpChrCmp(lpStr[dwStrPos],lpMask[dwMaskPos]))
                        {
                            dwStrPos++;
                            dwMaskPos++;
                        }
                        else if (dwAsterixPos)
                        {
                            dwMaskPos=dwAsterixPos;
                            bAsterix=true;
                        }
                        else
                        {
                            dwRet=1;
                            break;
                        }
                    }
                }
            }
            if ((!dwRet) && (lpdwSubStrSize))
                *lpdwSubStrSize=dwStrPos;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            dwRet=-1;
        }
        return dwRet;
    }
}

SYSLIBFUNC(int) StrCmpIFmtW(LPCWSTR lpStr,LPCWSTR lpMask)
{
    return SYSLIB::StrCmpFmtExW(lpStr,lpMask,NULL,L'?',true);
}

SYSLIBFUNC(int) StrCmpIFmtA(LPCSTR lpStr,LPCSTR lpMask)
{
    return SYSLIB::StrCmpFmtExA(lpStr,lpMask,NULL,'?',true);
}

SYSLIBFUNC(int) StrCmpFmtW(LPCWSTR lpStr,LPCWSTR lpMask)
{
    return SYSLIB::StrCmpFmtExW(lpStr,lpMask,NULL,L'?',false);
}

SYSLIBFUNC(int) StrCmpFmtA(LPCSTR lpStr,LPCSTR lpMask)
{
    return SYSLIB::StrCmpFmtExA(lpStr,lpMask,NULL,'?',false);
}

namespace SYSLIB
{
    LPWSTR StrStrFmtExW(LPCWSTR lpStr,LPCWSTR lpMask,LPDWORD lpdwSize,WCHAR wMaskChar,bool bInsensitive)
    {
        LPWSTR lpBegin=NULL;
        do
        {
            if (!SYSLIB_SAFE::CheckStrParamW(lpStr,0))
                break;

            if (!SYSLIB_SAFE::CheckStrParamW(lpMask,0))
                break;

            if (!SYSLIB_SAFE::CheckParamWrite(lpdwSize,sizeof(*lpdwSize)))
                lpdwSize=NULL;

            LPWSTR lpTrueMask;
            if (!StrFormatExW(&lpTrueMask,dcrW_cf3df67a("%s*"),lpMask))
                break;

            DWORD dwLen=lstrlenW(lpStr);
            for (DWORD i=0; i < dwLen; i++)
            {
                int iResult=StrCmpFmtExW(&lpStr[i],lpTrueMask,lpdwSize,wMaskChar,bInsensitive);
                if (!iResult)
                {
                    lpBegin=(LPWSTR)&lpStr[i];
                    break;
                }

                if (iResult == -1)
                    break;
            }

            MemFree(lpTrueMask);
        }
        while (false);
        return lpBegin;
    }
}

SYSLIBFUNC(LPWSTR) StrStrFmtW(LPCWSTR lpStr,LPCWSTR lpMask,LPDWORD lpdwSize)
{
    return SYSLIB::StrStrFmtExW(lpStr,lpMask,lpdwSize,L'?',false);
}

SYSLIBFUNC(LPWSTR) StrStrFmtIW(LPCWSTR lpStr,LPCWSTR lpMask,LPDWORD lpdwSize)
{
    return SYSLIB::StrStrFmtExW(lpStr,lpMask,lpdwSize,L'?',true);
}

namespace SYSLIB
{
    LPSTR StrStrFmtExA(LPCSTR lpStr,LPCSTR lpMask,LPDWORD lpdwSize,char cMaskChar,bool bInsensitive)
    {
        LPSTR lpBegin=NULL;
        do
        {
            if (!SYSLIB_SAFE::CheckStrParamA(lpStr,0))
                break;

            if (!SYSLIB_SAFE::CheckStrParamA(lpMask,0))
                break;

            if (!SYSLIB_SAFE::CheckParamWrite(lpdwSize,sizeof(*lpdwSize)))
                lpdwSize=NULL;

            LPSTR lpTrueMask;
            if (!StrFormatExA(&lpTrueMask,dcrA_cf3df67a("%s*"),lpMask))
                break;

            DWORD dwLen=lstrlenA(lpStr);
            for (DWORD i=0; i < dwLen; i++)
            {
                int iResult=StrCmpFmtExA(&lpStr[i],lpTrueMask,lpdwSize,cMaskChar,bInsensitive);
                if (!iResult)
                {
                    lpBegin=(LPSTR)&lpStr[i];
                    break;
                }

                if (iResult == -1)
                    break;
            }

            MemFree(lpTrueMask);
        }
        while (false);
        return lpBegin;
    }
}

SYSLIBFUNC(LPSTR) StrStrFmtA(LPCSTR lpStr,LPCSTR lpMask,LPDWORD lpdwSize)
{
    return SYSLIB::StrStrFmtExA(lpStr,lpMask,lpdwSize,'?',false);
}

SYSLIBFUNC(LPSTR) StrStrFmtIA(LPCSTR lpStr,LPCSTR lpMask,LPDWORD lpdwSize)
{
    return SYSLIB::StrStrFmtExA(lpStr,lpMask,lpdwSize,L'?',true);
}

