#include "sys_includes.h"
#include <shlwapi.h>

#include "syslib\utils.h"
#include "syslib\mem.h"
#include "syslib\files.h"
#include "syslib\system.h"
#include "syslib\str.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

namespace SYSLIB
{
    bool PathCombineW(LPWSTR lpDest,LPCWSTR lpDir,LPCWSTR lpFile);
    bool PathCombineA(LPSTR lpDest,LPCSTR lpDir,LPCSTR lpFile);
};

SYSLIBFUNC(LPWSTR) GetTmpFileNameW(LPCWSTR lpPrefix,LPCWSTR lpExt)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpPrefix,MAX_PATH))
        lpPrefix=NULL;

    if (!SYSLIB_SAFE::CheckStrParamW(lpExt,MAX_PATH))
        lpExt=NULL;

    WCHAR *lpBuf=NULL,szTmpDir[MAX_PATH];
    if (GetTempPathW(ARRAYSIZE(szTmpDir),szTmpDir))
    {
        if (!lpPrefix)
            lpPrefix=dcrW_f1785c76("tmp");
        WCHAR szTmpFile[MAX_PATH];
        if (GetTempFileNameW(szTmpDir,lpPrefix,0,szTmpFile))
        {
            RemoveFileW(szTmpFile);
            if (lpExt)
            {
                WCHAR *p=szTmpFile+lstrlenW(szTmpFile);
                while (*p != L'.')
                    p--;

                if (lpExt[0] != L'.')
                    p++;

                lstrcpyW(p,lpExt);
            }
            lpBuf=StrDuplicateW(szTmpFile,0);
        }
    }
    return lpBuf;
}

SYSLIBFUNC(LPSTR) GetTmpFileNameA(LPCSTR lpPrefix,LPCSTR lpExt)
{
    if (!SYSLIB_SAFE::CheckStrParamA(lpPrefix,MAX_PATH))
        lpPrefix=NULL;

    if (!SYSLIB_SAFE::CheckStrParamA(lpExt,MAX_PATH))
        lpExt=NULL;

    char *lpBuf=NULL,szTmpDir[MAX_PATH];
    if (GetTempPathA(ARRAYSIZE(szTmpDir),szTmpDir))
    {
        if (!lpPrefix)
            lpPrefix=dcrA_f1785c76("tmp");
        char szTmpFile[MAX_PATH];
        if (GetTempFileNameA(szTmpDir,lpPrefix,0,szTmpFile))
        {
            RemoveFileA(szTmpFile);
            if (lpExt)
            {
                char *p=szTmpFile+lstrlenA(szTmpFile);
                while (*p != '.')
                    p--;

                if (lpExt[0] != '.')
                    p++;

                lstrcpyA(p,lpExt);
            }
            lpBuf=StrDuplicateA(szTmpFile,0);
        }
    }
    return lpBuf;
}

SYSLIBFUNC(BOOL) RemoveFileW(LPCWSTR lpFile)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
        return false;

    BOOL bRet=false;
    int dwCount=0;
    SetFileAttributesW(lpFile,FILE_ATTRIBUTE_NORMAL);
    do
    {
        Sleep(1);
        bRet=(DeleteFileW(lpFile) != FALSE);
        if ((bRet) || (dwCount++ > 20))
            break;
    }
    while (GetLastError() != ERROR_FILE_NOT_FOUND);
    return bRet;
}

SYSLIBFUNC(BOOL) RemoveFileA(LPCSTR lpFile)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=RemoveFileW(lpFileNameW);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(BOOL) WipeFileW(LPCWSTR lpFile)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
        return false;

    BOOL bRet=false;
    HANDLE hFile=CreateFileW(lpFile,GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwTmpBufSize=1024*4,
              *lpTmpBuf=(DWORD*)MemQuickAlloc(dwTmpBufSize);
        if (lpTmpBuf)
        {
            LARGE_INTEGER liFileSize={0};
            if (GetFileSizeEx(hFile,&liFileSize))
            {
                for (DWORD i=0; i < dwTmpBufSize/sizeof(DWORD); i++)
                    lpTmpBuf[i]=GetRndDWORD();

                for (int i=0; i < 35; i++)
                {
                    SetFilePointer(hFile,0,0,FILE_BEGIN);

                    for (LONGLONG liSize=0; liSize < liFileSize.QuadPart;)
                    {
                        DWORD dwSize=min(liFileSize.QuadPart-liSize,dwTmpBufSize),
                              tmp;
                        WriteFile(hFile,lpTmpBuf,dwSize,&tmp,NULL);
                        liSize+=dwSize;
                    }

                    FlushFileBuffers(hFile);
                }
                bRet=true;
            }
            MemFree(lpTmpBuf);
        }
        SysCloseHandle(hFile);

        if (bRet)
            bRet=RemoveFileW(lpFile);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) WipeFileA(LPCSTR lpFile)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=WipeFileW(lpFileNameW);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(BOOL) WipeFilePartialW(LPCWSTR lpFile)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
        return false;

    BOOL bRet=false;
    HANDLE hFile=CreateFileW(lpFile,GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        LARGE_INTEGER liFileSize={0};
        if (GetFileSizeEx(hFile,&liFileSize))
        {
            DWORD dwTmpBufSize=1024*4;
            dwTmpBufSize=min(liFileSize.QuadPart,dwTmpBufSize);

            byte *lpTmpBuf=(byte*)MemQuickAlloc(dwTmpBufSize);
            if (lpTmpBuf)
            {
                    for (int i=0; i < 35; i++)
                    {
                        for (DWORD i=0; i < dwTmpBufSize; i++)
                            lpTmpBuf[i]=(byte)xor128(0xFF);

                        SetFilePointer(hFile,0,0,FILE_BEGIN);

                        DWORD tmp;
                        WriteFile(hFile,lpTmpBuf,dwTmpBufSize,&tmp,NULL);
                        FlushFileBuffers(hFile);
                    }
                    bRet=true;
                MemFree(lpTmpBuf);
                }
        }
        SysCloseHandle(hFile);

        if (bRet)
            bRet=RemoveFileW(lpFile);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) WipeFilePartialA(LPCSTR lpFile)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=WipeFilePartialW(lpFileNameW);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(BOOL) IsFileExistsW(LPCWSTR lpFile)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
        return false;

    return (GetFileAttributesW(lpFile) != INVALID_FILE_ATTRIBUTES);
}

SYSLIBFUNC(BOOL) IsFileExistsA(LPCSTR lpFile)
{
    if (!SYSLIB_SAFE::CheckStrParamA(lpFile,MAX_PATH))
        return false;

    return (GetFileAttributesA(lpFile) != INVALID_FILE_ATTRIBUTES);
}

SYSLIBFUNC(void) CopyFileNameWithoutExtensionW(LPCWSTR lpFullPath,LPWSTR lpOutBuf)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFullPath,MAX_PATH))
        return;

    LPCWSTR lpFileName=PathFindFileNameW(lpFullPath),p;
    DWORD dwLen=lstrlenW(lpFileName);
    p=lpFileName+dwLen;
    for (; ((*p != L'.') && (dwLen)); p--, dwLen--) ;

    if (SYSLIB_SAFE::CheckParamWrite(lpOutBuf,dwLen*sizeof(WCHAR)))
    {
        memcpy(lpOutBuf,lpFileName,dwLen*sizeof(WCHAR));
        lpOutBuf[dwLen]=0;
    }
    return;
}

SYSLIBFUNC(void) CopyFileNameWithoutExtensionA(LPCSTR lpFullPath,LPSTR lpOutBuf)
{
    if (!SYSLIB_SAFE::CheckStrParamA(lpFullPath,MAX_PATH))
        return;

    LPCSTR lpFileName=PathFindFileNameA(lpFullPath),p;
    DWORD dwLen=lstrlenA(lpFileName);
    p=lpFileName+dwLen;
    for (; ((*p != '.') && (dwLen)); p--, dwLen--) ;

    if (SYSLIB_SAFE::CheckParamWrite(lpOutBuf,dwLen*sizeof(char)))
    {
        memcpy(lpOutBuf,lpFileName,dwLen*sizeof(char));
        lpOutBuf[dwLen]=0;
    }
    return;
}

static bool RemoveFilesProcW(LPWSTR lpPath,PFILE_INFOW lpFileInfo,LPVOID lpData)
{
    WCHAR szFilePath[MAX_PATH];
    if (SYSLIB::PathCombineW(szFilePath,lpPath,lpFileInfo->wfd.cFileName))
        RemoveFileW(szFilePath);
    return true;
}

SYSLIBFUNC(void) RemoveFilesByMaskW(LPCWSTR lpPath,LPCWSTR lpMask)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpPath,MAX_PATH))
        return;

    if (!SYSLIB_SAFE::CheckStrParamW(lpMask,MAX_PATH))
        return;

    FindFilesW(lpPath,&lpMask,1,FFF_SEARCH_FILES,(FINDFILEPROCW*)RemoveFilesProcW,NULL,0,0);
    return;
}

static bool RemoveFilesProcA(LPSTR lpPath,PFILE_INFOA lpFileInfo,LPVOID lpData)
{
    char szFilePath[MAX_PATH];
    if (SYSLIB::PathCombineA(szFilePath,lpPath,lpFileInfo->wfd.cFileName))
        RemoveFileA(szFilePath);
    return true;
}

SYSLIBFUNC(void) RemoveFilesByMaskA(LPCSTR lpPath,LPCSTR lpMask)
{
    if (!SYSLIB_SAFE::CheckStrParamA(lpPath,MAX_PATH))
        return;

    if (!SYSLIB_SAFE::CheckStrParamA(lpMask,MAX_PATH))
        return;

    FindFilesA(lpPath,&lpMask,1,FFF_SEARCH_FILES,(FINDFILEPROCA*)RemoveFilesProcA,NULL,0,0);
    return;
}

