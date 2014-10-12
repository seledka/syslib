#include "sys_includes.h"
#include <wincrypt.h>
#include <shlwapi.h>

#include "syslib\debug.h"
#include "syslib\system.h"
#include "syslib\base64.h"
#include "syslib\mem.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

static DWORD Base64_DecodeIntW(LPCWSTR lpData,LPBYTE lpOut,DWORD dwBufSize)
{
    DWORD dwRealSize=0;
    __try
    {
        DWORD dwStrSize=lstrlenW(lpData);

        LPCWSTR pIn=lpData,
                lpWhiteChars=dcrW_ef8ed63a("\r\n\t ");
        LPBYTE pOut=lpOut;
        while (dwStrSize)
        {
            WCHAR szBase64Str[65]={0};
            DWORD dwBase64StrSize=0;

            while ((dwStrSize) && (dwBase64StrSize < 64))
            {
                DWORD dwCharsToSkip=StrSpnW(pIn,lpWhiteChars);
                pIn+=dwCharsToSkip;
                dwStrSize-=dwCharsToSkip;
                if (!dwStrSize)
                    break;

                szBase64Str[dwBase64StrSize++]=*pIn++;
                dwStrSize--;
            }

            if (!dwBase64StrSize)
                break;

            DWORD dwDecodedSize=dwBase64StrSize;
            if (!CryptStringToBinaryW(szBase64Str,dwBase64StrSize,CRYPT_STRING_BASE64,pOut,&dwDecodedSize,NULL,NULL))
                break;

            dwRealSize+=dwDecodedSize;
            if (pOut)
                pOut+=dwDecodedSize;
        }

        if (pOut)
            *pOut=0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    return dwRealSize;
}

static DWORD Base64_DecodeIntA(LPCSTR lpData,LPBYTE lpOut,DWORD dwBufSize)
{
    DWORD dwRealSize=0;
    __try
    {
        DWORD dwStrSize=lstrlenA(lpData);

        LPCSTR pIn=lpData,
               lpWhiteChars=dcrA_ef8ed63a("\r\n\t ");
        LPBYTE pOut=lpOut;
        while (dwStrSize)
        {
            char szBase64Str[65]={0};
            DWORD dwBase64StrSize=0;

            while ((dwStrSize) && (dwBase64StrSize < 64))
            {
                DWORD dwCharsToSkip=StrSpnA(pIn,lpWhiteChars);
                pIn+=dwCharsToSkip;
                dwStrSize-=dwCharsToSkip;
                if (!dwStrSize)
                    break;

                szBase64Str[dwBase64StrSize++]=*pIn++;
                dwStrSize--;
            }

            if (!dwBase64StrSize)
                break;

            DWORD dwDecodedSize=dwBase64StrSize;
            if (!CryptStringToBinaryA(szBase64Str,dwBase64StrSize,CRYPT_STRING_BASE64,pOut,&dwDecodedSize,NULL,NULL))
                break;

            dwRealSize+=dwDecodedSize;
            if (pOut)
                pOut+=dwDecodedSize;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    return dwRealSize;
}

SYSLIBFUNC(DWORD) Base64_GetDataSizeW(LPCWSTR lpData)
{
    return Base64_DecodeIntW(lpData,NULL,0);
}

SYSLIBFUNC(DWORD) Base64_GetDataSizeA(LPCSTR lpData)
{
    return Base64_DecodeIntA(lpData,NULL,0);
}

SYSLIBFUNC(BOOL) Base64_DecodeW(LPCWSTR lpIn,LPBYTE lpOut,DWORD dwBufSize)
{
    BOOL bRet=false;
    if (dwBufSize >= Base64_GetDataSizeW(lpIn))
        bRet=(Base64_DecodeIntW(lpIn,lpOut,dwBufSize) != 0);
    return bRet;
}

SYSLIBFUNC(BOOL) Base64_DecodeA(LPCSTR lpIn,LPBYTE lpOut,DWORD dwBufSize)
{
    BOOL bRet=false;
    if (dwBufSize >= Base64_GetDataSizeA(lpIn))
        bRet=(Base64_DecodeIntA(lpIn,lpOut,dwBufSize) != 0);
    return bRet;
}

SYSLIBFUNC(LPBYTE) Base64_DecodeExW(LPCWSTR lpIn,LPDWORD lpSize)
{
    byte *lpOut=NULL;
    if (lpIn)
    {
        DWORD dwSize=Base64_GetDataSizeW(lpIn);
        lpOut=(byte*)MemQuickAlloc(dwSize+1);
        if (lpOut)
        {
            if (!Base64_DecodeW(lpIn,lpOut,dwSize))
            {
                MemFree(lpOut);
                lpOut=NULL;
            }
            else
            {
                lpOut[dwSize]=0;
                if (lpSize)
                    *lpSize=dwSize;
            }
        }
    }
    return lpOut;
}

SYSLIBFUNC(LPBYTE) Base64_DecodeExA(LPCSTR lpIn,LPDWORD lpSize)
{
    byte *lpOut=NULL;
    if (lpIn)
    {
        DWORD dwSize=Base64_GetDataSizeA(lpIn);
        lpOut=(byte*)MemQuickAlloc(dwSize+1);
        if (lpOut)
        {
            if (!Base64_DecodeA(lpIn,lpOut,dwSize))
            {
                MemFree(lpOut);
                lpOut=NULL;
            }
            else
            {
                lpOut[dwSize]=0;
                if (lpSize)
                    *lpSize=dwSize;
            }
        }
    }
    return lpOut;
}

static DWORD Base64_PrepareEncodedBufferW(LPWSTR lpBuf,DWORD dwSize,DWORD dwFlags)
{
    DWORD dwNewSize=dwSize;
    if (dwFlags & BASE64_FLAG_NO_LINEBREAK)
    {
        LPWSTR p1=lpBuf,p2=lpBuf;
        while (dwSize)
        {
            if (*p1 != L'\n')
            {
                p1++;
                p2++;
                dwSize--;
                continue;
            }

            dwSize--;
            dwNewSize--;
            if (dwSize)
                memmove(p2,p1,dwSize*sizeof(WCHAR));
        }
        lpBuf[dwNewSize]=0;
    }
    return dwNewSize;
}

SYSLIBFUNC(DWORD) Base64_EncodeW(LPBYTE lpIn,DWORD dwSize,LPWSTR lpOut,DWORD dwBufSize,DWORD dwFlags)
{
    DWORD dwRet=dwBufSize/sizeof(WCHAR),
          dwFlg=CRYPT_STRING_BASE64;

    if (dwFlags & BASE64_FLAG_NO_LINEBREAK)
        dwFlg|=CRYPT_STRING_NOCR;

    if (!CryptBinaryToStringW(lpIn,dwSize,dwFlg,lpOut,&dwRet))
        dwRet=0;
    else
        dwRet=Base64_PrepareEncodedBufferW(lpOut,dwRet,dwFlags);
    return dwRet;
}

static DWORD Base64_PrepareEncodedBufferA(LPSTR lpBuf,DWORD dwSize,DWORD dwFlags)
{
    DWORD dwNewSize=dwSize;
    if (dwFlags & BASE64_FLAG_NO_LINEBREAK)
    {
        LPSTR p1=lpBuf,p2=lpBuf;
        while (dwSize)
        {
            if (*p1 != '\n')
            {
                p1++;
                p2++;
                dwSize--;
                continue;
            }

            dwSize--;
            dwNewSize--;
            if (dwSize)
                memmove(p2,p1+1,dwSize);
        }
        lpBuf[dwNewSize]=0;
    }
    return dwNewSize;
}

SYSLIBFUNC(DWORD) Base64_EncodeA(LPBYTE lpIn,DWORD dwSize,LPSTR lpOut,DWORD dwBufSize,DWORD dwFlags)
{
    DWORD dwRet=dwBufSize,
          dwFlg=CRYPT_STRING_BASE64;

    if (dwFlags & BASE64_FLAG_NO_LINEBREAK)
        dwFlg|=CRYPT_STRING_NOCR;

    if (!CryptBinaryToStringA(lpIn,dwSize,dwFlg,lpOut,&dwRet))
        dwRet=0;
    else
        dwRet=Base64_PrepareEncodedBufferA(lpOut,dwRet,dwFlags);
    return dwRet;
}

SYSLIBFUNC(LPWSTR) Base64_EncodeExW(LPBYTE lpIn,DWORD dwSize,LPDWORD lpOutSize,DWORD dwFlags)
{
    LPWSTR lpOut=NULL;
    if ((lpIn) && (dwSize))
    {
        DWORD dwDataSize=Base64_CalcSizeW(lpIn,dwSize);
        lpOut=(WCHAR*)MemQuickAlloc(dwDataSize+1);
        if (lpOut)
        {
            DWORD dwOutSize=Base64_EncodeW(lpIn,dwSize,lpOut,dwDataSize,dwFlags);
            if (!dwOutSize)
            {
                MemFree(lpOut);
                lpOut=NULL;
            }
            else
            {
                lpOut[dwOutSize]=0;
                if (lpOutSize)
                    *lpOutSize=dwOutSize;
            }
        }
    }
    return lpOut;
}

SYSLIBFUNC(LPSTR) Base64_EncodeExA(LPBYTE lpIn,DWORD dwSize,LPDWORD lpOutSize,DWORD dwFlags)
{
    LPSTR lpOut=NULL;
    if ((lpIn) && (dwSize))
    {
        DWORD dwDataSize=Base64_CalcSizeA(lpIn,dwSize);
        lpOut=(char*)MemQuickAlloc(dwDataSize+1);
        if (lpOut)
        {
            DWORD dwOutSize=Base64_EncodeA(lpIn,dwSize,lpOut,dwDataSize,dwFlags);
            if (!dwOutSize)
            {
                MemFree(lpOut);
                lpOut=NULL;
            }
            else
            {
                lpOut[dwOutSize]=0;
                if (lpOutSize)
                    *lpOutSize=dwOutSize;
            }
        }
    }
    return lpOut;
}

SYSLIBFUNC(DWORD) Base64_CalcSizeA(LPBYTE lpBuf,DWORD dwSize)
{
    DWORD dwOutSize=0;
    CryptBinaryToStringA(lpBuf,dwSize,CRYPT_STRING_BASE64,NULL,&dwOutSize);
    if (dwOutSize)
        dwOutSize++;
    return dwOutSize;
}

SYSLIBFUNC(DWORD) Base64_CalcSizeW(LPBYTE lpBuf,DWORD dwSize)
{
    DWORD dwOutSize=0;
    CryptBinaryToStringW(lpBuf,dwSize,CRYPT_STRING_BASE64,NULL,&dwOutSize);
    if (dwOutSize)
        dwOutSize=(dwOutSize+1)*sizeof(WCHAR);
    return dwOutSize;
}

SYSLIBFUNC(LPSTR) Base64_EncodeFileA(LPCSTR lpFileName,DWORD dwFlags)
{
    char *lpBase64=NULL;
    HANDLE hFile=CreateFileA(lpFileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwSize=GetFileSize(hFile,NULL);

        HANDLE hMapping=CreateFileMappingA(hFile,NULL,PAGE_READONLY,0,0,NULL);
        if (hMapping)
        {
            LPVOID lpMapping=MapViewOfFile(hMapping,FILE_MAP_READ,0,0,0);
            if (lpMapping)
            {
                lpBase64=Base64_EncodeExA((byte*)lpMapping,dwSize,NULL,dwFlags);
                UnmapViewOfFile(lpMapping);
            }
            SysCloseHandle(hMapping);
        }
        SysCloseHandle(hFile);
    }
    return lpBase64;
}

SYSLIBFUNC(LPSTR) Base64_EncodeFileW(LPCWSTR lpFileName,DWORD dwFlags)
{
    char *lpBase64=NULL;
    HANDLE hFile=CreateFileW(lpFileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwSize=GetFileSize(hFile,NULL);

        HANDLE hMapping=CreateFileMappingW(hFile,NULL,PAGE_READONLY,0,0,NULL);
        if (hMapping)
        {
            LPVOID lpMapping=MapViewOfFile(hMapping,FILE_MAP_READ,0,0,0);
            if (lpMapping)
            {
                lpBase64=Base64_EncodeExA((byte*)lpMapping,dwSize,NULL,dwFlags);
                UnmapViewOfFile(lpMapping);
            }
            SysCloseHandle(hMapping);
        }
        SysCloseHandle(hFile);
    }
    return lpBase64;
}

