#include "sys_includes.h"

#include "syslib\mem.h"
#include "syslib\str.h"

static DWORD GetStringSizeW(LPCWSTR *lppSource,LPCWSTR lpStrEnd)
{
    LPCWSTR lpCurEnd=*lppSource;
    DWORD dwSize=0;

    while ((lpCurEnd < lpStrEnd) && (*lpCurEnd != '\n') && (*lpCurEnd != '\r'))
        lpCurEnd++;

    dwSize=lpCurEnd-*lppSource;
    if ((lpCurEnd+1 < lpStrEnd) && (lpCurEnd[0] == '\r') && (lpCurEnd[1] == '\n'))
        lpCurEnd++;

    *lppSource=lpCurEnd+1;
    return dwSize;
}

SYSLIBFUNC(DWORD) StrSplitToStringsExW(LPCWSTR lpSource,DWORD dwSourceSize,LPWSTR **lpppStrings,DWORD dwFlags,WCHAR wSeparator)
{
    DWORD dwCount=0;
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

        LPCWSTR lpStrEnd=lpSource+dwSourceSize;
        LPWSTR *lppStrings=NULL;

        while (lpSource < lpStrEnd)
        {
            LPCWSTR lpStrStart=lpSource;
            DWORD dwStrSize;
            if (dwFlags & STRSPLIT_USE_SEPARATOR)
            {
                LPCWSTR lpCurEnd=lpSource;
                while ((lpCurEnd < lpStrEnd) && (*lpCurEnd != wSeparator))
                    lpCurEnd++;

                dwStrSize=(DWORD)(lpCurEnd-lpSource);
                lpSource=lpCurEnd+1;
            }
            else
                dwStrSize=GetStringSizeW(&lpSource,lpStrEnd);

            if (!dwStrSize)
                break;

            lppStrings=(LPWSTR *)MemRealloc(lppStrings,(dwCount+1)*sizeof(*lppStrings));
            if (!lppStrings)
            {
                dwCount=0;
                break;
            }

            lppStrings[dwCount]=StrDuplicateW(lpStrStart,dwStrSize);
            if (!lppStrings[dwCount])
            {
                MemFreeArrayOfPointers((LPVOID*)lppStrings,dwCount);
                dwCount=0;
                break;
            }

            dwCount++;
        }

        if (!dwCount)
            break;

        *lpppStrings=lppStrings;
    }
    while (false);
    return dwCount;
}

SYSLIBFUNC(DWORD) StrSplitToStringsW(LPCWSTR lpSource,DWORD dwSourceSize,LPWSTR **lpppStrings)
{
    return StrSplitToStringsExW(lpSource,dwSourceSize,lpppStrings,0,0);
}

static DWORD GetStringSizeA(LPCSTR *lppSource,LPCSTR lpStrEnd)
{
    LPCSTR lpCurEnd=*lppSource;
    DWORD dwSize=0;

    while ((lpCurEnd < lpStrEnd) && (*lpCurEnd != '\n') && (*lpCurEnd != '\r'))
        lpCurEnd++;

    dwSize=lpCurEnd-*lppSource;
    if ((lpCurEnd+1 < lpStrEnd) && (lpCurEnd[0] == '\r') && (lpCurEnd[1] == '\n'))
        lpCurEnd++;

    *lppSource=lpCurEnd+1;
    return dwSize;
}

SYSLIBFUNC(DWORD) StrSplitToStringsExA(LPCSTR lpSource,DWORD dwSourceSize,LPSTR **lpppStrings,DWORD dwFlags,char cSeparator)
{
    DWORD dwCount=0;
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

        LPCSTR lpStrEnd=lpSource+dwSourceSize;
        LPSTR *lppStrings=NULL;

        while (lpSource < lpStrEnd)
        {
            LPCSTR lpStrStart=lpSource;
            DWORD dwStrSize;
            if (dwFlags & STRSPLIT_USE_SEPARATOR)
            {
                LPCSTR lpCurEnd=lpSource;
                while ((lpCurEnd < lpStrEnd) && (*lpCurEnd != cSeparator))
                    lpCurEnd++;

                dwStrSize=(DWORD)(lpCurEnd-lpSource);
                lpSource=lpCurEnd+1;
            }
            else
                dwStrSize=GetStringSizeA(&lpSource,lpStrEnd);

            if (!dwStrSize)
                break;

            lppStrings=(LPSTR *)MemRealloc(lppStrings,(dwCount+1)*sizeof(*lppStrings));
            if (!lppStrings)
            {
                dwCount=0;
                break;
            }

            lppStrings[dwCount]=StrDuplicateA(lpStrStart,dwStrSize);
            if (!lppStrings[dwCount])
            {
                MemFreeArrayOfPointers((LPVOID*)lppStrings,dwCount);
                dwCount=0;
                break;
            }

            dwCount++;
        }

        if (!dwCount)
            break;

        *lpppStrings=lppStrings;
    }
    while (false);
    return dwCount;
}

SYSLIBFUNC(DWORD) StrSplitToStringsA(LPCSTR lpSource,DWORD dwSourceSize,LPSTR **lpppStrings)
{
    return StrSplitToStringsExA(lpSource,dwSourceSize,lpppStrings,0,0);
}

