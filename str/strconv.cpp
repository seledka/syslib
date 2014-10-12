#include "sys_includes.h"

#include "syslib\mem.h"
#include "syslib\str.h"

static DWORD UnicodeToX(DWORD codePage,LPCWSTR source,DWORD sourceSize,LPSTR dest,DWORD destSize,DWORD dwFlags=0)
{
    if (sourceSize == 0)
        sourceSize=lstrlenW(source);
    DWORD size=WideCharToMultiByte(codePage,dwFlags,source,sourceSize,dest,destSize,NULL,NULL);
    if (destSize != 0)
    {
        if (size > destSize)
            size=0;
        dest[size]=0;
    }
    return size;
}

static DWORD xToUnicode(DWORD codePage,LPCSTR source,DWORD sourceSize,LPWSTR dest,DWORD destSize,DWORD dwFlags=0)
{
    if (sourceSize == 0)
        sourceSize=lstrlenA(source);
    DWORD size=MultiByteToWideChar(codePage,0,source,sourceSize,dest,destSize);
    if (destSize != 0)
    {
        if (size > destSize)
            size=0;
        dest[size]=0;
    }
    return size;
}

SYSLIBFUNC(DWORD) StrUnicodeToAnsi(LPCWSTR lpSource,DWORD dwSourceSize,LPSTR lpDest,DWORD dwDestSize)
{
    DWORD dwRet=0;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpSource,dwSourceSize))
            break;

        if (!dwDestSize)
            dwDestSize=lstrlenW(lpSource)+1;

        if (!SYSLIB_SAFE::CheckParamWrite(lpDest,dwDestSize))
            break;

        dwRet=UnicodeToX(1251,lpSource,dwSourceSize,lpDest,dwDestSize,WC_COMPOSITECHECK);
    }
    while (false);
    return dwRet;
}

SYSLIBFUNC(LPSTR) StrUnicodeToAnsiEx(LPCWSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize)
{
    LPSTR lpOut=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamsExW(lpSource,dwSourceSize,&lpOutSize))
            break;

        if (!dwSourceSize)
        {
            dwSourceSize=lstrlenW(lpSource);
            if (!dwSourceSize)
                break;
        }

        DWORD dwRequedSize=UnicodeToX(1251,lpSource,dwSourceSize,NULL,0,WC_COMPOSITECHECK);
        if (!dwRequedSize)
            break;

        lpOut=(LPSTR)MemQuickAlloc(dwRequedSize+1);
        if (!lpOut)
            break;

        DWORD dwOutSize=StrUnicodeToAnsi(lpSource,dwSourceSize,lpOut,dwRequedSize);
        if (dwOutSize)
        {
            if (lpOutSize)
                *lpOutSize=dwOutSize;

            lpOut[dwOutSize]=0;
            break;
        }

        MemFree(lpOut);
        lpOut=NULL;
    }
    while (false);
    return lpOut;
}

SYSLIBFUNC(DWORD) StrAnsiToUnicode(LPCSTR lpSource,DWORD dwSourceSize,LPWSTR lpDest,DWORD dwDestSize)
{
    DWORD dwRet=0;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamA(lpSource,dwSourceSize))
            break;

        if (!dwDestSize)
            dwDestSize=lstrlenA(lpSource)+1;

        if (!SYSLIB_SAFE::CheckParamWrite(lpDest,dwDestSize*sizeof(WCHAR)))
            break;

        dwRet=xToUnicode(1251,lpSource,dwSourceSize,lpDest,dwDestSize);
    }
    while (false);
    return dwRet;
}

SYSLIBFUNC(LPWSTR) StrAnsiToUnicodeEx(LPCSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize)
{
    LPWSTR lpOut=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamsExA(lpSource,dwSourceSize,&lpOutSize))
            break;

        if (!dwSourceSize)
        {
            dwSourceSize=lstrlenA(lpSource);
            if (!dwSourceSize)
                break;
        }

        DWORD dwRequedSize=xToUnicode(1251,lpSource,dwSourceSize,NULL,0);
        if (!dwRequedSize)
            break;

        lpOut=WCHAR_QuickAlloc(dwRequedSize+1);
        if (!lpOut)
            break;

        DWORD dwOutSize=StrAnsiToUnicode(lpSource,dwSourceSize,lpOut,dwRequedSize);
        if (dwOutSize)
        {
            if (lpOutSize)
                *lpOutSize=dwOutSize;

            lpOut[dwOutSize]=0;
            break;
        }

        MemFree(lpOut);
        lpOut=NULL;
    }
    while (false);
    return lpOut;
}

SYSLIBFUNC(DWORD) StrAnsiToUtf8(LPCSTR lpSource,DWORD dwSourceSize,LPSTR lpDest,DWORD dwDestSize)
{
    DWORD dwRet=0;
    do
    {
        DWORD dwUniLen;
        LPWSTR lpSourceW=StrAnsiToUnicodeEx(lpSource,dwSourceSize,&dwUniLen);
        if (!lpSourceW)
            break;

        dwRet=UnicodeToX(CP_UTF8,lpSourceW,dwUniLen,lpDest,dwDestSize);
        MemFree(lpSourceW);
    }
    while (false);
    return dwRet;
}

SYSLIBFUNC(LPSTR) StrAnsiToUtf8Ex(LPCSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize)
{
    LPSTR lpOut=NULL;
    do
    {
        DWORD dwUniLen;
        LPWSTR lpSourceW=StrAnsiToUnicodeEx(lpSource,dwSourceSize,&dwUniLen);
        if (!lpSourceW)
            break;

        lpOut=StrUnicodeToUtf8Ex(lpSourceW,dwUniLen,lpOutSize);
        MemFree(lpSourceW);
    }
    while (false);
    return lpOut;
}

SYSLIBFUNC(DWORD) StrUtf8ToAnsi(LPCSTR lpSource,DWORD dwSourceSize,LPSTR lpDest,DWORD dwDestSize)
{
    DWORD dwRet=0;
    do
    {
        DWORD dwUniLen;
        LPWSTR lpSourceW=StrUtf8ToUnicodeEx(lpSource,dwSourceSize,&dwUniLen);
        if (!lpSourceW)
            break;

        dwRet=UnicodeToX(1251,lpSourceW,dwUniLen,lpDest,dwDestSize);;
        MemFree(lpSourceW);
    }
    while (false);
    return dwRet;
}

SYSLIBFUNC(LPSTR) StrUtf8ToAnsiEx(LPCSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize)
{
    LPSTR lpOut=NULL;
    do
    {
        DWORD dwUniLen;
        LPWSTR lpSourceW=StrUtf8ToUnicodeEx(lpSource,dwSourceSize,&dwUniLen);
        if (!lpSourceW)
            break;

        lpOut=StrUnicodeToAnsiEx(lpSourceW,dwUniLen,lpOutSize);
        MemFree(lpSourceW);
    }
    while (false);
    return lpOut;
}

SYSLIBFUNC(DWORD) StrUtf8ToUnicode(LPCSTR lpSource,DWORD dwSourceSize,LPWSTR lpDest,DWORD dwDestSize)
{
    DWORD dwRet=0;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamA(lpSource,dwSourceSize))
            break;

        if (!dwDestSize)
            dwDestSize=lstrlenA(lpSource)+1;

        if (!SYSLIB_SAFE::CheckParamWrite(lpDest,dwDestSize*sizeof(WCHAR)))
            break;

        dwRet=xToUnicode(CP_UTF8,lpSource,dwSourceSize,lpDest,dwDestSize);
    }
    while (false);
    return dwRet;
}

SYSLIBFUNC(LPWSTR) StrUtf8ToUnicodeEx(LPCSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize)
{
    LPWSTR lpOut=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamsExA(lpSource,dwSourceSize,&lpOutSize))
            break;

        if (!dwSourceSize)
        {
            dwSourceSize=lstrlenA(lpSource);
            if (!dwSourceSize)
                break;
        }

        DWORD dwRequedSize=xToUnicode(CP_UTF8,lpSource,dwSourceSize,NULL,0);
        if (!dwRequedSize)
            break;

        lpOut=WCHAR_QuickAlloc(dwRequedSize+1);
        if (!lpOut)
            break;

        DWORD dwOutSize=StrUtf8ToUnicode(lpSource,dwSourceSize,lpOut,dwRequedSize);
        if (dwOutSize)
        {
            if (lpOutSize)
                *lpOutSize=dwOutSize;

            lpOut[dwOutSize]=0;
            break;
        }

        MemFree(lpOut);
        lpOut=NULL;
    }
    while (false);
    return lpOut;
}

SYSLIBFUNC(DWORD) StrUnicodeToOem(LPCWSTR lpSource,DWORD dwSourceSize,LPSTR lpDest,DWORD dwDestSize)
{
    DWORD dwRet=0;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpSource,dwSourceSize))
            break;

        if (!dwDestSize)
            dwDestSize=lstrlenW(lpSource)+1;

        if (!SYSLIB_SAFE::CheckParamWrite(lpDest,dwDestSize))
            break;

        dwRet=UnicodeToX(CP_OEMCP,lpSource,dwSourceSize,lpDest,dwDestSize,WC_COMPOSITECHECK);
    }
    while (false);
    return dwRet;
}

SYSLIBFUNC(LPSTR) StrUnicodeToOemEx(LPCWSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize)
{
    LPSTR lpOut=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamsExW(lpSource,dwSourceSize,&lpOutSize))
            break;

        if (!dwSourceSize)
        {
            dwSourceSize=lstrlenW(lpSource);
            if (!dwSourceSize)
                break;
        }

        DWORD dwRequedSize=UnicodeToX(CP_OEMCP,lpSource,dwSourceSize,NULL,0,WC_COMPOSITECHECK);
        if (!dwRequedSize)
            break;

        lpOut=(LPSTR)MemQuickAlloc(dwRequedSize+1);
        if (!lpOut)
            break;

        DWORD dwOutSize=StrUnicodeToOem(lpSource,dwSourceSize,lpOut,dwRequedSize);
        if (dwOutSize)
        {
            if (lpOutSize)
                *lpOutSize=dwOutSize;

            lpOut[dwOutSize]=0;
            break;
        }

        MemFree(lpOut);
        lpOut=NULL;
    }
    while (false);
    return lpOut;
}

SYSLIBFUNC(DWORD) StrOemToUnicode(LPCSTR lpSource,DWORD dwSourceSize,LPWSTR lpDest,DWORD dwDestSize)
{
    DWORD dwRet=0;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamA(lpSource,dwSourceSize))
            break;

        if (!dwDestSize)
            dwDestSize=lstrlenA(lpSource)+1;

        if (!SYSLIB_SAFE::CheckParamWrite(lpDest,dwDestSize*sizeof(WCHAR)))
            break;

        dwRet=xToUnicode(CP_OEMCP,lpSource,dwSourceSize,lpDest,dwDestSize);
    }
    while (false);
    return dwRet;
}

SYSLIBFUNC(LPWSTR) StrOemToUnicodeEx(LPCSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize)
{
    LPWSTR lpOut=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamsExA(lpSource,dwSourceSize,&lpOutSize))
            break;

        if (!dwSourceSize)
        {
            dwSourceSize=lstrlenA(lpSource);
            if (!dwSourceSize)
                break;
        }

        DWORD dwRequedSize=xToUnicode(CP_OEMCP,lpSource,dwSourceSize,NULL,0);
        if (!dwRequedSize)
            break;

        lpOut=WCHAR_QuickAlloc(dwRequedSize+1);
        if (!lpOut)
            break;

        DWORD dwOutSize=StrOemToUnicode(lpSource,dwSourceSize,lpOut,dwRequedSize);
        if (dwOutSize)
        {
            if (lpOutSize)
                *lpOutSize=dwOutSize;

            lpOut[dwOutSize]=0;
            break;
        }

        MemFree(lpOut);
        lpOut=NULL;
    }
    while (false);
    return lpOut;
}

SYSLIBFUNC(DWORD) StrUnicodeToUtf8(LPCWSTR lpSource,DWORD dwSourceSize,LPSTR lpDest,DWORD dwDestSize)
{
    DWORD dwRet=0;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpSource,dwSourceSize))
            break;

        if (!dwDestSize)
            dwDestSize=lstrlenW(lpSource)+1;

        if (!SYSLIB_SAFE::CheckParamWrite(lpDest,dwDestSize))
            break;

        dwRet=UnicodeToX(CP_UTF8,lpSource,dwSourceSize,lpDest,dwDestSize);
    }
    while (false);
    return dwRet;
}

SYSLIBFUNC(LPSTR) StrUnicodeToUtf8Ex(LPCWSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize)
{
    LPSTR lpOut=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamsExW(lpSource,dwSourceSize,&lpOutSize))
            break;

        if (!dwSourceSize)
        {
            dwSourceSize=lstrlenW(lpSource);
            if (!dwSourceSize)
                break;
        }

        DWORD dwRequedSize=UnicodeToX(CP_UTF8,lpSource,dwSourceSize,NULL,0);
        if (!dwRequedSize)
            break;

        lpOut=(LPSTR)MemQuickAlloc(dwRequedSize+1);
        if (!lpOut)
            break;

        DWORD dwOutSize=StrUnicodeToUtf8(lpSource,dwSourceSize,lpOut,dwRequedSize);
        if (dwOutSize)
        {
            if (lpOutSize)
                *lpOutSize=dwOutSize;

            lpOut[dwOutSize]=0;
            break;
        }

        MemFree(lpOut);
        lpOut=NULL;
    }
    while (false);
    return lpOut;
}

static byte GetHexValueW(WCHAR wChr)
{
    byte bRet=0xFF;

    if ((wChr >= L'0') && (wChr <= L'9' ))
        bRet=(wChr-L'0');
    else if ((wChr >= L'a') && (wChr <= L'f'))
        bRet=(wChr-L'a')+0xA;
    else if ((wChr >= L'AA') && (wChr <= L'F'))
        bRet=(wChr-L'A')+0xA;

    return bRet;
}

SYSLIBFUNC(DWORD) StrToHexW(LPCWSTR lpStr)
{
    DWORD dwHex=0;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpStr,8))
            break;

        if ((lpStr[0] == L'0') && ((lpStr[1] == L'x') || (lpStr[1] == L'X')))
            lpStr+=2;

        for (DWORD i=0; i < 8; i++)
        {
            byte bHex=GetHexValueW(tolower(*lpStr++));
            if (bHex == 0xFF)
                break;

            dwHex=dwHex*16+bHex;
        }
    }
    while (false);
    return dwHex;
}

static byte GetHexValueA(char cChr)
{
    byte bRet=0xFF;

    if ((cChr >= '0') && (cChr <= '9' ))
        bRet=(cChr-'0');
    else if ((cChr >= 'a') && (cChr <= 'f'))
        bRet=(cChr-'a')+0xA;
    else if ((cChr >= 'A') && (cChr <= 'F'))
        bRet=(cChr-'A')+0xA;

    return bRet;
}

SYSLIBFUNC(DWORD) StrToHexA(LPCSTR lpStr)
{
    DWORD dwHex=0;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamA(lpStr,8))
            break;

        if ((lpStr[0] == '0') && ((lpStr[1] == 'x') || (lpStr[1] == 'X')))
            lpStr+=2;

        for (DWORD i=0; i < 8; i++)
        {
            byte bHex=GetHexValueA(tolower(*lpStr++));
            if (bHex == 0xFF)
                break;

            dwHex=dwHex*16+bHex;
        }
    }
    while (false);
    return dwHex;
}

SYSLIBFUNC(DWORD64) StrToHex64W(LPCWSTR lpStr)
{
    DWORD64 dwHex=0;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpStr,16))
            break;

        if ((lpStr[0] == L'0') && ((lpStr[1] == L'x') || (lpStr[1] == L'X')))
            lpStr+=2;

        for (DWORD i=0; i < 16; i++)
        {
            byte bHex=GetHexValueW(tolower(*lpStr++));
            if (bHex == 0xFF)
                break;

            dwHex=dwHex*16+bHex;
        }
    }
    while (false);
    return dwHex;
}

SYSLIBFUNC(DWORD64) StrToHex64A(LPCSTR lpStr)
{
    DWORD64 dwHex=0;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamA(lpStr,16))
            break;

        if ((lpStr[0] == '0') && ((lpStr[1] == 'x') || (lpStr[1] == 'X')))
            lpStr+=2;

        for (DWORD i=0; i < 16; i++)
        {
            byte bHex=GetHexValueA(tolower(*lpStr++));
            if (bHex == 0xFF)
                break;

            dwHex=dwHex*16+bHex;
        }
    }
    while (false);
    return dwHex;
}

static char ByteToHex(BYTE bByte)
{
    return (char)(bByte+((bByte > 0x9) ? ('A'-0xA) : '0'));
}

SYSLIBFUNC(DWORD) BinToHexW(LPBYTE lpData,DWORD dwSize,LPWSTR lpStrOut)
{
    DWORD dwStrSize=0;
    do
    {
        if (!SYSLIB_SAFE::CheckParamRead(lpData,dwSize))
            break;

        if (!SYSLIB_SAFE::CheckStrParamW(lpStrOut,(dwSize+1)*2))
            break;

        LPWSTR lpPtr=lpStrOut;
        for (DWORD i=0; i < dwSize; i++)
        {
            lpPtr[0]=ByteToHex(lpData[i] >> 0x4);
            lpPtr[1]=ByteToHex(lpData[i]  & 0xF);

            dwStrSize+=2;
            lpPtr+=2;
        }
        *lpPtr=0;
    }
    while (false);
    return dwStrSize;
}

SYSLIBFUNC(DWORD) BinToHexA(LPBYTE lpData,DWORD dwSize,LPSTR lpStrOut)
{
    DWORD dwStrSize=0;
    do
    {
        if (!SYSLIB_SAFE::CheckParamRead(lpData,dwSize))
            break;

        if (!SYSLIB_SAFE::CheckStrParamA(lpStrOut,(dwSize+1)*2))
            break;

        LPSTR lpPtr=lpStrOut;
        for (DWORD i=0; i < dwSize; i++)
        {
            lpPtr[0]=ByteToHex(lpData[i] >> 0x4);
            lpPtr[1]=ByteToHex(lpData[i]  & 0xF);

            dwStrSize+=2;
            lpPtr+=2;
        }
        *lpPtr=0;
    }
    while (false);
    return dwStrSize;
}

SYSLIBFUNC(LPWSTR) BinToHexExW(LPBYTE lpData,DWORD dwSize,LPDWORD lpdwOutSize)
{
    LPWSTR lpOutStr=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckParamRead(lpData,dwSize))
            break;

        if (!SYSLIB_SAFE::CheckParamWrite(lpdwOutSize,sizeof(*lpdwOutSize)))
            lpdwOutSize=NULL;

        lpOutStr=WCHAR_QuickAlloc((dwSize+1)*2);
        if (!lpOutStr)
            break;

        DWORD dwRealSize=BinToHexW(lpData,dwSize,lpOutStr);
        if (lpdwOutSize)
            *lpdwOutSize=dwRealSize;
    }
    while (false);
    return lpOutStr;
}

SYSLIBFUNC(LPSTR) BinToHexExA(LPBYTE lpData,DWORD dwSize,LPDWORD lpdwOutSize)
{
    LPSTR lpOutStr=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckParamRead(lpData,dwSize))
            break;

        if (!SYSLIB_SAFE::CheckParamWrite(lpdwOutSize,sizeof(*lpdwOutSize)))
            lpdwOutSize=NULL;

        lpOutStr=CHAR_QuickAlloc((dwSize+1)*2);
        if (!lpOutStr)
            break;

        DWORD dwRealSize=BinToHexA(lpData,dwSize,lpOutStr);
        if (lpdwOutSize)
            *lpdwOutSize=dwRealSize;
    }
    while (false);
    return lpOutStr;
}

SYSLIBFUNC(DWORD) HexToBinW(LPCWSTR lpStr,LPBYTE lpOut,DWORD dwSize)
{
    DWORD dwDataSize=0;
    do
    {
        if (!SYSLIB_SAFE::CheckParamWrite(lpOut,dwSize))
            break;

        if (!SYSLIB_SAFE::CheckStrParamW(lpStr,0))
            break;

        LPBYTE lpPtr=lpOut;
        bool bOddDigit=false;
        while ((*lpStr) && (dwSize))
        {
            WCHAR wChr=*lpStr++;

            if ((!wChr) && (bOddDigit == false))
                break;
            else
            {
                byte bHex=GetHexValueW(wChr);
                if (bHex == 0xFF)
                    break;

                if (bOddDigit)
                {
                    *lpPtr|=bHex;
                    lpPtr++;
                    dwSize--;
                    dwDataSize++;
                    bOddDigit=false;
                }
                else
                {
                    *lpPtr=bHex << 4;
                    bOddDigit=true;
                }
            }
        }
    }
    while (false);
    return dwDataSize;
}

SYSLIBFUNC(DWORD) HexToBinA(LPCSTR lpStr,LPBYTE lpOut,DWORD dwSize)
{
    DWORD dwDataSize=0;
    do
    {
        if (!SYSLIB_SAFE::CheckParamWrite(lpOut,dwSize))
            break;

        if (!SYSLIB_SAFE::CheckStrParamA(lpStr,0))
            break;

        LPBYTE lpPtr=lpOut;
        bool bOddDigit=false;
        while ((*lpStr) && (dwSize))
        {
            char cChr=*lpStr++;

            if ((!cChr) && (bOddDigit == false))
                break;
            else
            {
                byte bHex=GetHexValueA(cChr);
                if (bHex == 0xFF)
                    break;

                if (bOddDigit)
                {
                    *lpPtr|=bHex;
                    lpPtr++;
                    dwSize--;
                    dwDataSize++;
                    bOddDigit=false;
                }
                else
                {
                    *lpPtr=bHex << 4;
                    bOddDigit=true;
                }
            }
        }
    }
    while (false);
    return dwDataSize;
}

SYSLIBFUNC(LPBYTE) HexToBinExW(LPCWSTR lpStr,LPDWORD lpdwOutSize)
{
    LPBYTE lpData=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpStr,0))
            break;

        if (!SYSLIB_SAFE::CheckParamWrite(lpdwOutSize,sizeof(*lpdwOutSize)))
            lpdwOutSize=NULL;

        DWORD dwBufSize=lstrlenW(lpStr)/2;
        lpData=(LPBYTE)MemQuickAlloc(dwBufSize);
        if (!lpData)
            break;

        DWORD dwRealSize=HexToBinW(lpStr,lpData,dwBufSize);
        if (lpdwOutSize)
            *lpdwOutSize=dwRealSize;
    }
    while (false);
    return lpData;
}

SYSLIBFUNC(LPBYTE) HexToBinExA(LPCSTR lpStr,LPDWORD lpdwOutSize)
{
    LPBYTE lpData=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamA(lpStr,0))
            break;

        if (!SYSLIB_SAFE::CheckParamWrite(lpdwOutSize,sizeof(*lpdwOutSize)))
            lpdwOutSize=NULL;

        DWORD dwBufSize=lstrlenA(lpStr)/2;
        lpData=(LPBYTE)MemQuickAlloc(dwBufSize);
        if (!lpData)
            break;

        DWORD dwRealSize=HexToBinA(lpStr,lpData,dwBufSize);
        if (lpdwOutSize)
            *lpdwOutSize=dwRealSize;
    }
    while (false);
    return lpData;
}

