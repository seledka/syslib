#include "sys_includes.h"

#include "syslib\mem.h"
#include "syslib\net.h"
#include "syslib\str.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

static bool UrlEncoderIsGoodCharW(WCHAR wChr)
{
    bool bRet=true;
    if (((wChr < L'0') && (wChr != L'-') && (wChr != L'.')) || ((wChr < L'A') && (wChr > L'9')) || ((wChr > L'Z') && (wChr < L'a') && (wChr != L'_')) || (wChr > L'z'))
        bRet=false;
    return bRet;
}

static void ByteToWChar(byte bByte,LPWSTR lpStr)
{
    lpStr[0]=(BYTE)(bByte >> 4);
    lpStr[1]=(BYTE)(bByte & 0xF);

    lpStr[0]+=(lpStr[0] > 0x9 ? (L'A' - 0xA) : L'0');
    lpStr[1]+=(lpStr[1] > 0x9 ? (L'A' - 0xA) : L'0');
    return;
}

SYSLIBFUNC(BOOL) NetUrlEncodeBufferW(LPCWSTR lpIn,DWORD dwSize,LPWSTR lpOut,DWORD dwOutSize)
{
    BOOL bRet=false;
    do
    {
        if ((!lpIn) || (!lpOut))
            break;

        if (!dwSize)
        {
            dwSize=lstrlenW(lpIn);
            if (!dwSize)
                break;
        }

        DWORD dwRequedSize=NetUrlCalcEncodedSizeW(lpIn,dwSize);
        if (!dwRequedSize)
            break;

        if (dwRequedSize > dwOutSize)
            break;

        DWORD dwStrIdx=0;
        while (dwSize--)
        {
            WCHAR wChr=*lpIn;
            if (!UrlEncoderIsGoodCharW(wChr))
            {
                lpOut[dwStrIdx++]=L'%';
                ByteToWChar(wChr,&lpOut[dwStrIdx]);
                dwStrIdx+=2;
            }
            else
                lpOut[dwStrIdx++]=wChr;

            lpIn++;
        }

        bRet=true;
    }
    while (false);

    return bRet;
}

SYSLIBFUNC(LPWSTR) NetUrlEncodeBufferExW(LPCWSTR lpIn,DWORD dwSize,LPDWORD lpOutSize)
{
    LPWSTR lpOut=NULL;
    do
    {
        if (!lpIn)
            break;

        if (!dwSize)
        {
            dwSize=lstrlenW(lpIn);
            if (!dwSize)
                break;
        }

        DWORD dwOutSize=NetUrlCalcEncodedSizeW(lpIn,dwSize);
        if (!dwOutSize)
            break;

        lpOut=WCHAR_QuickAlloc(dwOutSize+1);
        if (lpOut)
        {
            if (NetUrlEncodeBufferW(lpIn,dwSize,lpOut,dwOutSize))
            {
                lpOut[dwOutSize]=0;
                if (lpOutSize)
                    *lpOutSize=dwOutSize;
            }
            else
            {
                MemFree(lpOut);
                lpOut=NULL;
            }
        }
    }
    while (false);

    return lpOut;
}

static bool UrlEncoderIsGoodCharA(char cChr)
{
    bool bRet=true;
    if (((cChr < '0') && (cChr != '-') && (cChr != '.')) || ((cChr < 'A') && (cChr > '9')) || ((cChr > 'Z') && (cChr < 'a') && (cChr != '_')) || (cChr > 'z'))
        bRet=false;
    return bRet;
}

static void ByteToChar(byte bByte,LPSTR lpStr)
{
    lpStr[0]=(BYTE)(bByte >> 4);
    lpStr[1]=(BYTE)(bByte & 0xF);

    lpStr[0]+=(lpStr[0] > 0x9 ? ('A' - 0xA) : '0');
    lpStr[1]+=(lpStr[1] > 0x9 ? ('A' - 0xA) : '0');
    return;
}

SYSLIBFUNC(BOOL) NetUrlEncodeBufferA(LPCSTR lpIn,DWORD dwSize,LPSTR lpOut,DWORD dwOutSize)
{
    BOOL bRet=false;
    do
    {
        if ((!lpIn) || (!lpOut))
            break;

        if (!dwSize)
        {
            dwSize=lstrlenA(lpIn);
            if (!dwSize)
                break;
        }

        DWORD dwRequedSize=NetUrlCalcEncodedSizeA(lpIn,dwSize);
        if (!dwRequedSize)
            break;

        if (dwRequedSize > dwOutSize)
            break;

        DWORD dwStrIdx=0;
        while (dwSize--)
        {
            char cChr=*lpIn;
            if (!UrlEncoderIsGoodCharA(cChr))
            {
                lpOut[dwStrIdx++]='%';
                ByteToChar(cChr,&lpOut[dwStrIdx]);
                dwStrIdx+=2;
            }
            else
                lpOut[dwStrIdx++]=cChr;

            lpIn++;
        }

        bRet=true;
    }
    while (false);

    return bRet;
}

SYSLIBFUNC(LPSTR) NetUrlEncodeBufferExA(LPCSTR lpIn,DWORD dwSize,LPDWORD lpOutSize)
{
    LPSTR lpOut=NULL;
    do
    {
        if (!lpIn)
            break;

        if (!dwSize)
        {
            dwSize=lstrlenA(lpIn);
            if (!dwSize)
                break;
        }

        DWORD dwOutSize=NetUrlCalcEncodedSizeA(lpIn,dwSize);
        if (!dwOutSize)
            break;

        lpOut=(char*)MemQuickAlloc(dwOutSize+1);
        if (lpOut)
        {
            if (NetUrlEncodeBufferA(lpIn,dwSize,lpOut,dwOutSize))
            {
                lpOut[dwOutSize]=0;
                if (lpOutSize)
                    *lpOutSize=dwOutSize;
            }
            else
            {
                MemFree(lpOut);
                lpOut=NULL;
            }
        }
    }
    while (false);

    return lpOut;
}

SYSLIBFUNC(DWORD) NetUrlCalcEncodedSizeW(LPCWSTR lpIn,DWORD dwSize)
{
    DWORD dwRequedSize=0;
    do
    {
        if (!lpIn)
            break;

        if (!dwSize)
        {
            dwSize=lstrlenW(lpIn);
            if (!dwSize)
                break;
        }

        dwRequedSize=dwSize;
        while (dwSize--)
        {
            WCHAR wChr=*lpIn++;
            if (!UrlEncoderIsGoodCharW(wChr))
                dwRequedSize+=2;
        }
    }
    while (false);

    return dwRequedSize;
}

SYSLIBFUNC(DWORD) NetUrlCalcEncodedSizeA(LPCSTR lpIn,DWORD dwSize)
{
    DWORD dwRequedSize=0;
    do
    {
        if (!lpIn)
            break;

        if (!dwSize)
        {
            dwSize=lstrlenA(lpIn);
            if (!dwSize)
                break;
        }

        dwRequedSize=dwSize;
        while (dwSize--)
        {
            char cChr=*lpIn++;
            if (!UrlEncoderIsGoodCharA(cChr))
                dwRequedSize+=2;
        }
    }
    while (false);

    return dwRequedSize;
}

static bool IsXDigitW(WCHAR wChr)
{
    bool bRet=false;
    wChr=tolower(wChr);
    if (((wChr >= L'0') && (wChr <= L'9')) ||
        ((wChr >= L'a') && (wChr <= L'f')))
        bRet=true;
    return bRet;
}

SYSLIBFUNC(BOOL) NetUrlDecodeBufferW(LPCWSTR lpIn,DWORD dwSize,LPWSTR lpOut,DWORD dwOutSize)
{
    BOOL bRet=false;
    do
    {
        if ((!lpIn) || (!lpOut))
            break;

        if (!dwSize)
        {
            dwSize=lstrlenW(lpIn);
            if (!dwSize)
                break;
        }

        DWORD dwRequedSize=NetUrlCalcDecodedSizeW(lpIn,dwSize);
        if (!dwRequedSize)
            break;

        if (dwRequedSize > dwOutSize)
            break;

        LPWSTR pIn=(LPWSTR)lpIn,
               pOut=lpOut;
        while (dwSize--)
        {
            WCHAR wChr=*pIn++;
            if ((wChr == L'%') && (IsXDigitW(pIn[0])) && (IsXDigitW(pIn[1])))
            {
                WCHAR szHex[3]={0};
                szHex[0]=pIn[0];
                szHex[1]=pIn[1];
                wChr=(WCHAR)StrToHexW(szHex);
                pIn+=2;
                dwSize-=2;
            }
            *pOut++=wChr;
        }

        bRet=true;
    }
    while (false);

    return bRet;
}

SYSLIBFUNC(LPWSTR) NetUrlDecodeBufferExW(LPCWSTR lpIn,DWORD dwSize,LPDWORD lpOutSize)
{
    LPWSTR lpOut=NULL;
    do
    {
        if (!lpIn)
            break;

        if (!dwSize)
        {
            dwSize=lstrlenW(lpIn);
            if (!dwSize)
                break;
        }

        DWORD dwOutSize=NetUrlCalcDecodedSizeW(lpIn,dwSize);
        if (!dwOutSize)
            break;

        lpOut=WCHAR_QuickAlloc(dwOutSize+1);
        if (lpOut)
        {
            if (NetUrlDecodeBufferW(lpIn,dwSize,lpOut,dwOutSize))
            {
                lpOut[dwOutSize]=0;
                if (lpOutSize)
                    *lpOutSize=dwOutSize;
            }
            else
            {
                MemFree(lpOut);
                lpOut=NULL;
            }
        }
    }
    while (false);

    return lpOut;
}

static bool IsXDigitA(char cChr)
{
    bool bRet=false;
    cChr=tolower(cChr);
    if (((cChr >= '0') && (cChr <= '9')) ||
        ((cChr >= 'a') && (cChr <= 'f')))
        bRet=true;
    return bRet;
}

SYSLIBFUNC(BOOL) NetUrlDecodeBufferA(LPCSTR lpIn,DWORD dwSize,LPSTR lpOut,DWORD dwOutSize)
{
    BOOL bRet=false;
    do
    {
        if ((!lpIn) || (!lpOut))
            break;

        if (!dwSize)
        {
            dwSize=lstrlenA(lpIn);
            if (!dwSize)
                break;
        }

        DWORD dwRequedSize=NetUrlCalcDecodedSizeA(lpIn,dwSize);
        if (!dwRequedSize)
            break;

        if (dwRequedSize > dwOutSize)
            break;

        LPSTR pIn=(LPSTR)lpIn,
              pOut=lpOut;
        while (dwSize--)
        {
            char cChr=*pIn++;
            if ((cChr == '%') && (IsXDigitA(pIn[0])) && (IsXDigitA(pIn[1])))
            {
                char szHex[3]={0};
                szHex[0]=pIn[0];
                szHex[1]=pIn[1];
                cChr=(char)StrToHexA(szHex);
                pIn+=2;
                dwSize-=2;
            }
            *pOut++=cChr;
        }

        bRet=true;
    }
    while (false);

    return bRet;
}

SYSLIBFUNC(LPSTR) NetUrlDecodeBufferExA(LPCSTR lpIn,DWORD dwSize,LPDWORD lpOutSize)
{
    LPSTR lpOut=NULL;
    do
    {
        if (!lpIn)
            break;

        if (!dwSize)
        {
            dwSize=lstrlenA(lpIn);
            if (!dwSize)
                break;
        }

        DWORD dwOutSize=NetUrlCalcDecodedSizeA(lpIn,dwSize);
        if (!dwOutSize)
            break;

        lpOut=(char*)MemQuickAlloc(dwOutSize+1);
        if (lpOut)
        {
            if (NetUrlDecodeBufferA(lpIn,dwSize,lpOut,dwOutSize))
            {
                lpOut[dwOutSize]=0;
                if (lpOutSize)
                    *lpOutSize=dwOutSize;
            }
            else
            {
                MemFree(lpOut);
                lpOut=NULL;
            }
        }
    }
    while (false);

    return lpOut;
}

SYSLIBFUNC(DWORD) NetUrlCalcDecodedSizeW(LPCWSTR lpIn,DWORD dwSize)
{
    DWORD dwRequedSize=0;
    do
    {
        if (!lpIn)
            break;

        if (!dwSize)
        {
            dwSize=lstrlenW(lpIn);
            if (!dwSize)
                break;
        }

        dwRequedSize=dwSize;
        while (dwSize--)
        {
            if ((*lpIn++ == L'%') && (IsXDigitW(lpIn[0])) && (IsXDigitW(lpIn[1])))
                lpIn+=2;
            dwRequedSize++;
        }
    }
    while (false);

    return dwRequedSize;
}

SYSLIBFUNC(DWORD) NetUrlCalcDecodedSizeA(LPCSTR lpIn,DWORD dwSize)
{
    DWORD dwRequedSize=0;
    do
    {
        if (!lpIn)
            break;

        if (!dwSize)
        {
            dwSize=lstrlenA(lpIn);
            if (!dwSize)
                break;
        }

        dwRequedSize=dwSize;
        while (dwSize--)
        {
            if ((*lpIn++ == '%') && (IsXDigitA(lpIn[0])) && (IsXDigitA(lpIn[1])))
                lpIn+=2;
            dwRequedSize++;
        }
    }
    while (false);

    return dwRequedSize;
}

