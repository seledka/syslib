#include "sys_includes.h"

#include "syslib\mem.h"

#define SWP(x,y) (x^=y, y^=x, x^=y)

SYSLIBFUNC(BOOL) StrReverseW(LPCWSTR lpSource,DWORD dwSourceSize,LPWSTR lpOut)
{
    bool bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpSource,dwSourceSize))
            break;

        if (!dwSourceSize)
        {
            dwSourceSize=lstrlenW(lpSource);
            if (!dwSourceSize)
                break;
        }

        if (!SYSLIB_SAFE::CheckParamWrite(lpOut,(dwSourceSize+1)*sizeof(WCHAR)))
            break;

        if (lpSource != lpOut)
        {
            for (int i=0, j=dwSourceSize-1; j >= 0; i++, j--)
                lpOut[i]=lpSource[j];
        }
        else
        {
            LPWSTR lpEnd=lpOut+dwSourceSize;
            for (lpEnd--; lpOut < lpEnd; lpOut++, lpEnd--)
                SWP(*lpOut,*lpEnd);
        }

        lpOut[dwSourceSize]=0;

        bRet=true;
    }
    while (false);

    return bRet;
}

SYSLIBFUNC(BOOL) StrReverseA(LPCSTR lpSource,DWORD dwSourceSize,LPSTR lpOut)
{
    bool bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamA(lpSource,dwSourceSize))
            break;

        if (!dwSourceSize)
        {
            dwSourceSize=lstrlenA(lpSource);
            if (!dwSourceSize)
                break;
        }

        if (!SYSLIB_SAFE::CheckParamWrite(lpOut,dwSourceSize+1))
            break;

        if (lpSource != lpOut)
        {
            for (int i=0, j=dwSourceSize-1; j >= 0; i++, j--)
            {
                char cChr=lpSource[i];
                switch ((cChr & 0xF0) >> 4)
                {
                    case 0xF: /* U+010000-U+10FFFF: four bytes. */
                    {
                        memcpy(&lpOut[j-3],&lpSource[i],4);
                        i+=3;
                        j-=3;
                        break;
                    }
                    case 0xE: /* U+000800-U+00FFFF: three bytes. */
                    {
                        memcpy(&lpOut[j-1],&lpSource[i],3);
                        i+=2;
                        j-=2;
                        break;
                    }
                    case 0xC: /* fall-through */
                    case 0xD: /* U+000080-U+0007FF: two bytes. */
                    {
                        memcpy(&lpOut[j-1],&lpSource[i],2);
                        i++;
                        j--;
                        break;
                    }
                    default:
                    {
                        lpOut[j]=cChr;
                        break;
                    }
                }
            }
        }
        else
        {
            LPSTR lpEnd=lpOut+dwSourceSize;
            for (lpEnd--; lpOut < lpEnd; lpOut++, lpEnd--)
                SWP(*lpOut,*lpEnd);

            lpOut=(LPSTR)lpSource;
            lpEnd=lpOut+dwSourceSize;
            while (lpSource < --lpEnd)
            {
                switch ((*lpEnd & 0xF0) >> 4)
                {
                    case 0xF: /* U+010000-U+10FFFF: four bytes. */
                    {
                        SWP(*(lpEnd-0),*(lpEnd-3));
                        SWP(*(lpEnd-1),*(lpEnd-2));
                        lpEnd-=3;
                        break;
                    }
                    case 0xE: /* U+000800-U+00FFFF: three bytes. */
                    {
                        SWP(*(lpEnd-0),*(lpEnd-2));
                        lpEnd-=2;
                        break;
                    }
                    case 0xC: /* fall-through */
                    case 0xD: /* U+000080-U+0007FF: two bytes. */
                    {
                        SWP(*(lpEnd-0),*(lpEnd-1));
                        lpEnd--;
                        break;
                    }
                }
            }
        }

        bRet=true;
        lpOut[dwSourceSize]=0;
    }
    while (false);

    return bRet;
}

SYSLIBFUNC(LPWSTR) StrReverseExW(LPCWSTR lpSource,DWORD dwSourceSize)
{
    LPWSTR lpOut=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpSource,dwSourceSize))
            break;

        if (!dwSourceSize)
        {
            dwSourceSize=lstrlenW(lpSource);
            if (!dwSourceSize)
                break;
        }

        lpOut=(LPWSTR)MemQuickAlloc((dwSourceSize+1)*sizeof(WCHAR));
        if (!lpOut)
            break;

        if (StrReverseW(lpSource,dwSourceSize,lpOut))
            break;

        MemFree(lpOut);
        lpOut=NULL;
    }
    while (false);
    return lpOut;
}

SYSLIBFUNC(LPSTR) StrReverseExA(LPCSTR lpSource,DWORD dwSourceSize)
{
    LPSTR lpOut=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamA(lpSource,dwSourceSize))
            break;

        if (!dwSourceSize)
        {
            dwSourceSize=lstrlenA(lpSource);
            if (!dwSourceSize)
                break;
        }

        lpOut=(LPSTR)MemQuickAlloc(dwSourceSize+1);
        if (!lpOut)
            break;

        if (StrReverseA(lpSource,dwSourceSize,lpOut))
            break;

        MemFree(lpOut);
        lpOut=NULL;
    }
    while (false);
    return lpOut;
}

