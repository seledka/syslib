#include "sys_includes.h"
#include <shlwapi.h>
#include "syslib\file_container.h"
#include "syslib\str.h"
#include "syslib\mem.h"
#include "syslib\system.h"
#include "syslib\files.h"
#include "syslib\chksum.h"
#include "syslib\rc4.h"
#include "syslib\time.h"

#include "aplib.h"

#include "file_container.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

namespace SYSLIB
{
    bool PathCombineW(LPWSTR lpDest,LPCWSTR lpDir,LPCWSTR lpFile);
};

static bool FileCont_CheckHandle(PFILE_CONT_HANDLE lpHandle)
{
    bool bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckParamWrite(lpHandle,sizeof(*lpHandle)))
            break;

        if (lpHandle->dwHandleMagic != FILE_CONT_HANDLE_MAGIC)
            break;

        bRet=true;
    }
    while (false);
    return bRet;
}

static PFILE_CONT_HANDLE FileCont_CreateHandle()
{
    PFILE_CONT_HANDLE lpHandle=(PFILE_CONT_HANDLE)MemAlloc(sizeof(*lpHandle));
    if (lpHandle)
    {
        lpHandle->dwHandleMagic=FILE_CONT_HANDLE_MAGIC;
        InitializeCriticalSection(&lpHandle->csContainer);
    }
    return lpHandle;
}

SYSLIBFUNC(HANDLE) FileCont_CreateW(LPCWSTR lpContainerFile,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpContainerFile,0))
        return NULL;

    if (!SYSLIB_SAFE::CheckStrParamA(lpPassword,dwPasswordLen))
    {
        lpPassword=NULL;
        dwPasswordLen=0;
    }

    PFILE_CONT_HANDLE lpHandle=NULL;
    HANDLE hFile=CreateFileW(lpContainerFile,GENERIC_READ|GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        lpHandle=FileCont_CreateHandle();
        if (lpHandle)
        {
            lpHandle->hContFile=hFile;
            lpHandle->lpPassword=StrDuplicateA(lpPassword,dwPasswordLen);
            lpHandle->dwPasswordLen=dwPasswordLen;
        }
        else
        {
            SysCloseHandle(hFile);
            RemoveFileW(lpContainerFile);
        }
    }
    return (HANDLE)lpHandle;
}

SYSLIBFUNC(HANDLE) FileCont_CreateA(LPCSTR lpContainerFile,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    LPWSTR lpContainerFileW=StrAnsiToUnicodeEx(lpContainerFile,0,NULL);
    HANDLE hCont=FileCont_CreateW(lpContainerFileW,lpPassword,dwPasswordLen);
    MemFree(lpContainerFileW);
    return hCont;
}

SYSLIBFUNC(BOOL) FileCont_AddFileW(HANDLE hCont,LPCWSTR lpSourceFile,LPCWSTR lpDestFile,BOOL bCompress,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    return FileCont_AddFileExW(hCont,lpSourceFile,lpDestFile,bCompress,0,lpPassword,dwPasswordLen);
}

SYSLIBFUNC(BOOL) FileCont_AddFileA(HANDLE hCont,LPCSTR lpSourceFile,LPCSTR lpDestFile,BOOL bCompress,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    return FileCont_AddFileExA(hCont,lpSourceFile,lpDestFile,bCompress,0,lpPassword,dwPasswordLen);
}

static bool FileCont_IsFilePresent(PFILE_CONT_HANDLE lpContainer,LPCSTR lpDestFile)
{
    bool bRet=false;
    PFILE_CONT_FILES_LIST lpFile=lpContainer->lpFiles;
    while (lpFile)
    {
        if (!StrCmpNIA(lpFile->lpFile->szFileName,lpDestFile,lpFile->lpFile->dwFileNameSize))
        {
            bRet=true;
            break;
        }

        lpFile=lpFile->lpNext;
    }
    return bRet;
}

static bool FileCont_AddFileInt(PFILE_CONT_HANDLE lpContainer,LPBYTE lpData,DWORD dwDataSize,LPCSTR lpFileName,DWORD dwFlags,DWORD dwFileTime,BOOL bCompress,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!SYSLIB_SAFE::CheckParamRead(lpData,dwDataSize))
        return false;

    if (!SYSLIB_SAFE::CheckStrParamA(lpPassword,dwPasswordLen))
    {
        lpPassword=NULL;
        dwPasswordLen=0;
    }

    bool bRet=false;
    if (!FileCont_IsFilePresent(lpContainer,lpFileName))
    {
        PFILE_CONT_FILES_LIST lpNewFile=(PFILE_CONT_FILES_LIST)MemAlloc(sizeof(*lpNewFile));
        if (lpNewFile)
        {
            DWORD dwFileNameSize=lstrlenA(lpFileName),
                  dwNeededDataSize=(bCompress) ? aP_max_packed_size(dwDataSize) : dwDataSize;

            lpNewFile->lpFile=(PFILE_CONT_FILE_INFO)MemQuickAlloc(dwNeededDataSize+sizeof(*lpNewFile->lpFile)+dwFileNameSize);
            if (lpNewFile->lpFile)
            {
                if (lpContainer->lpFiles)
                {
                    PFILE_CONT_FILES_LIST lpLastFile=lpContainer->lpFiles;
                    while (lpLastFile->lpNext)
                        lpLastFile=lpLastFile->lpNext;

                    lpLastFile->lpNext=lpNewFile;
                }
                else
                    lpContainer->lpFiles=lpNewFile;

                lpNewFile->lpFile->dwFileHdrMagic=FILE_CONT_FILE_HDR_MAGIC;
                lpNewFile->lpFile->dwFileTime=dwFileTime;
                lpNewFile->lpFile->dwRealFileSize=dwDataSize;
                lpNewFile->lpFile->dwFileCheckSum=MurmurHash3(lpData,dwDataSize);
                lpNewFile->lpFile->dwFileNameSize=dwFileNameSize;
                lpNewFile->lpFile->dwFlags=0;

                lstrcpyA(lpNewFile->lpFile->szFileName,lpFileName);

                LPBYTE lpDataPtr=lpNewFile->lpFile->bFileBody+dwFileNameSize;
                if (bCompress)
                {
                    LPBYTE lpWorkMem=(LPBYTE)MemQuickAlloc(aP_workmem_size(dwDataSize));
                    lpNewFile->lpFile->dwCompressedFileSize=aPsafe_pack(lpData,lpDataPtr,dwDataSize,lpWorkMem,NULL,NULL);
                    MemFree(lpWorkMem);

                    lpNewFile->lpFile->dwFlags|=FILE_FLAG_COMPRESSED;
                }
                else
                {
                    lpNewFile->lpFile->dwCompressedFileSize=dwDataSize;
                    memcpy(lpDataPtr,lpData,dwDataSize);
                }

                if (!(dwFlags & FILECONT_NO_CRYPT))
                {
                    LPCSTR lpRealPassword=NULL;
                    DWORD dwRealPasswordLen=0;

                    if (lpPassword)
                    {
                        lpRealPassword=lpPassword;
                        dwRealPasswordLen=dwPasswordLen;
                    }
                    else if (lpContainer->lpPassword)
                    {
                        lpRealPassword=lpContainer->lpPassword;
                        dwRealPasswordLen=lpContainer->dwPasswordLen;
                    }

                    if (lpRealPassword)
                    {
                        rc4Full(lpRealPassword,dwRealPasswordLen,lpDataPtr,lpNewFile->lpFile->dwCompressedFileSize);
                        lpNewFile->lpFile->dwFlags|=FILE_FLAG_ENCRYPTED;
                    }
                }

                if ((!lpContainer->bInMem) && (!lpContainer->bReadOnly))
                {
                    SetFilePointer(lpContainer->hContFile,0,NULL,FILE_END);
                    DWORD dwWritten,
                          dwNewFileSize=sizeof(*lpNewFile->lpFile)+dwFileNameSize+lpNewFile->lpFile->dwCompressedFileSize;
                    bRet=((WriteFile(lpContainer->hContFile,lpNewFile->lpFile,dwNewFileSize,&dwWritten,NULL) != FALSE) && (dwWritten == dwNewFileSize));
                }
                else
                    bRet=true;
            }
            else
                MemFree(lpNewFile);
        }
    }
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_AddFileExW(HANDLE hCont,LPCWSTR lpSourceFile,LPCWSTR lpDestFile,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    if (!SYSLIB_SAFE::CheckStrParamW(lpDestFile,0))
    {
        lpDestFile=lpSourceFile;
        if (!SYSLIB_SAFE::CheckStrParamW(lpDestFile,0))
            return FALSE;

        LPCWSTR lpPtr=lpDestFile+lstrlenW(lpDestFile);
        while ((lpPtr != lpDestFile) && (*(lpPtr-1) != L'\\'))
            lpPtr--;

        lpDestFile=lpPtr;
    }

    PFILE_CONT_HANDLE lpContainer=(PFILE_CONT_HANDLE)hCont;

    BOOL bRet=false;
    EnterCriticalSection(&lpContainer->csContainer);
    {
        LPSTR lpDestFileUtf8=StrUnicodeToUtf8Ex(lpDestFile,0,NULL);
        if (lpDestFileUtf8)
        {
            HANDLE hFile=CreateFileW(lpSourceFile,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,NULL,NULL,NULL);
                if (hMapping)
                {
                    LPBYTE lpMap=(LPBYTE)MapViewOfFile(hMapping,FILE_MAP_READ,NULL,NULL,NULL);
                    if (lpMap)
                    {
                        FILETIME ftCreate;
                        GetFileTime(hFile,&ftCreate,NULL,NULL);
                        LARGE_INTEGER liTime={ftCreate.dwLowDateTime,ftCreate.dwHighDateTime};
                        DWORD dwTime;
                        RtlTimeToSecondsSince1980(&liTime,&dwTime);
                        bRet=FileCont_AddFileInt(lpContainer,lpMap,GetFileSize(hFile,NULL),lpDestFileUtf8,dwFlags,dwTime,bCompress,lpPassword,dwPasswordLen);
                        UnmapViewOfFile(lpMap);
                    }
                    SysCloseHandle(hMapping);
                }
                SysCloseHandle(hFile);
            }
            MemFree(lpDestFileUtf8);
        }
    }
    LeaveCriticalSection(&lpContainer->csContainer);
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_AddFileExA(HANDLE hCont,LPCSTR lpSourceFile,LPCSTR lpDestFile,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    LPWSTR lpSourceFileW=StrAnsiToUnicodeEx(lpSourceFile,0,NULL),
           lpDestFileW=StrAnsiToUnicodeEx(lpDestFile,0,NULL);

    BOOL bRet=FileCont_AddFileExW(hCont,lpSourceFileW,lpDestFileW,bCompress,dwFlags,lpPassword,dwPasswordLen);

    MemFree(lpSourceFileW);
    MemFree(lpDestFileW);
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_AddFromMemoryW(HANDLE hCont,LPVOID lpMem,DWORD dwSize,LPCWSTR lpFileName,BOOL bCompress,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    return FileCont_AddFromMemoryExW(hCont,lpMem,dwSize,lpFileName,bCompress,0,lpPassword,dwPasswordLen);
}

SYSLIBFUNC(BOOL) FileCont_AddFromMemoryA(HANDLE hCont,LPVOID lpMem,DWORD dwSize,LPCSTR lpFileName,BOOL bCompress,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    return FileCont_AddFromMemoryExA(hCont,lpMem,dwSize,lpFileName,bCompress,0,lpPassword,dwPasswordLen);
}

SYSLIBFUNC(BOOL) FileCont_AddFromMemoryExW(HANDLE hCont,LPVOID lpMem,DWORD dwSize,LPCWSTR lpFileName,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    PFILE_CONT_HANDLE lpContainer=(PFILE_CONT_HANDLE)hCont;

    BOOL bRet=false;
    EnterCriticalSection(&lpContainer->csContainer);
    {
        LPSTR lpFileNameUtf8=StrUnicodeToUtf8Ex(lpFileName,0,NULL);
        if (lpFileNameUtf8)
        {
            bRet=FileCont_AddFileInt(lpContainer,(LPBYTE)lpMem,dwSize,lpFileNameUtf8,dwFlags,Now(),bCompress,lpPassword,dwPasswordLen);
            MemFree(lpFileNameUtf8);
        }
    }
    LeaveCriticalSection(&lpContainer->csContainer);
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_AddFromMemoryExA(HANDLE hCont,LPVOID lpMem,DWORD dwSize,LPCSTR lpFileName,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFileName,0,NULL);

    BOOL bRet=FileCont_AddFromMemoryExW(hCont,lpMem,dwSize,lpFileNameW,bCompress,dwFlags,lpPassword,dwPasswordLen);

    MemFree(lpFileNameW);
    return bRet;
}

static bool CreateFromFolderProc(LPWSTR lpPath,PFILE_INFOW lpFileInfo,PCFF_STRUCT lpData)
{
    bool bRet=false;
    WCHAR szFilePath[MAX_PATH];
    if (SYSLIB::PathCombineW(szFilePath,lpPath,lpFileInfo->wfd.cFileName))
    {
        if (IsFileExistsW(szFilePath))
        {
            LPSTR lpDestFileUtf8=StrUnicodeToUtf8Ex(&szFilePath[lpData->dwPathOffset],0,NULL);
            if (lpDestFileUtf8)
            {
                HANDLE hFile=CreateFileW(szFilePath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
                if (hFile != INVALID_HANDLE_VALUE)
                {
                    HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,NULL,NULL,NULL);
                    if (hMapping)
                    {
                        LPBYTE lpMap=(LPBYTE)MapViewOfFile(hMapping,FILE_MAP_READ,NULL,NULL,NULL);
                        if (lpMap)
                        {
                            FILETIME ftCreate;
                            GetFileTime(hFile,&ftCreate,NULL,NULL);
                            LARGE_INTEGER liTime={ftCreate.dwLowDateTime,ftCreate.dwHighDateTime};
                            DWORD dwTime;
                            RtlTimeToSecondsSince1980(&liTime,&dwTime);
                            bRet=FileCont_AddFileInt(lpData->lpContainer,lpMap,GetFileSize(hFile,NULL),lpDestFileUtf8,lpData->dwFlags,dwTime,lpData->bCompress,lpData->lpPassword,lpData->dwPasswordLen);
                            if (bRet)
                                lpData->dwFilesCount++;
                            UnmapViewOfFile(lpMap);
                        }
                        SysCloseHandle(hMapping);
                    }
                    SysCloseHandle(hFile);
                }
                MemFree(lpDestFileUtf8);
            }
        }
    }

    if ((bRet) && (lpData->bDelete))
        RemoveFileW(szFilePath);

    return true;
}

SYSLIBFUNC(BOOL) FileCont_AddFolderW(HANDLE hCont,LPCWSTR lpSourceFolder,LPCWSTR *lppFileMask,DWORD dwFileMaskCount,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    WCHAR szCurrentDirectory[MAX_PATH];
    if (!SYSLIB_SAFE::CheckStrParamW(lpSourceFolder,0))
    {
        GetCurrentDirectoryW(ARRAYSIZE(szCurrentDirectory),szCurrentDirectory);
        lpSourceFolder=szCurrentDirectory;
    }

    PFILE_CONT_HANDLE lpContainer=(PFILE_CONT_HANDLE)hCont;

    BOOL bRet=false;
    EnterCriticalSection(&lpContainer->csContainer);
    {
        CFF_STRUCT cff={0};
        cff.lpContainer=lpContainer;
        cff.bDelete=dwFlags & CFF_DELETE ? true : false;
        cff.dwPathOffset=lstrlenW(lpSourceFolder);
        cff.dwFlags=dwFlags;
        cff.bCompress=bCompress;
        cff.lpPassword=lpPassword;
        cff.dwPasswordLen=dwPasswordLen;

        if ((cff.dwPathOffset > 0) && (lpSourceFolder[cff.dwPathOffset-1] != L'\\'))
            cff.dwPathOffset++;

        FindFilesW(lpSourceFolder,lppFileMask,dwFileMaskCount,(dwFlags & CFF_RECURSE ? FFF_RECURSIVE : 0) | FFF_SEARCH_FILES,(FINDFILEPROCW*)CreateFromFolderProc,&cff,0,0);
        bRet=(cff.dwFilesCount > 0);
    }
    LeaveCriticalSection(&lpContainer->csContainer);
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_AddFolderA(HANDLE hCont,LPCSTR lpSourceFolder,LPCSTR *lppFileMask,DWORD dwFileMaskCount,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    LPWSTR lpSourceFolderW=StrAnsiToUnicodeEx(lpSourceFolder,0,NULL),
           *lppFileMaskW=(LPWSTR*)MemQuickAlloc(dwFileMaskCount*sizeof(LPWSTR));

    for (DWORD i=0; i < dwFileMaskCount; i++)
        lppFileMaskW[i]=StrAnsiToUnicodeEx(lppFileMask[i],0,NULL);

    BOOL bRet=FileCont_AddFolderW(hCont,lpSourceFolderW,(LPCWSTR*)lppFileMaskW,dwFileMaskCount,bCompress,dwFlags,lpPassword,dwPasswordLen);

    MemFree(lpSourceFolderW);
    MemFreeArrayOfPointers((LPVOID*)lppFileMaskW,dwFileMaskCount);
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_CreateFromFolderW(LPCWSTR lpContainerFile,LPCWSTR lpSourceFolder,LPCWSTR *lppFileMask,DWORD dwFileMaskCount,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen,BOOL bCompress)
{
    BOOL bRet=false;
    HANDLE hCont=FileCont_CreateW(lpContainerFile,lpPassword,dwPasswordLen);
    if (hCont)
    {
        bRet=FileCont_AddFolderW(hCont,lpSourceFolder,lppFileMask,dwFileMaskCount,bCompress,dwFlags,NULL,0);
        FileCont_Close(hCont);

        if (!bRet)
            RemoveFileW(lpContainerFile);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_CreateFromFolderA(LPCSTR lpContainerFile,LPCSTR lpSourceFolder,LPCSTR *lppFileMask,DWORD dwFileMaskCount,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen,BOOL bCompress)
{
    LPWSTR lpContainerFileW=StrAnsiToUnicodeEx(lpContainerFile,0,NULL),
           lpSourceFolderW=StrAnsiToUnicodeEx(lpSourceFolder,0,NULL),
           *lppFileMaskW=(LPWSTR*)MemQuickAlloc(dwFileMaskCount*sizeof(LPWSTR));

    for (DWORD i=0; i < dwFileMaskCount; i++)
        lppFileMaskW[i]=StrAnsiToUnicodeEx(lppFileMask[i],0,NULL);

    BOOL bRet=FileCont_CreateFromFolderW(lpContainerFileW,lpSourceFolderW,(LPCWSTR*)lppFileMaskW,dwFileMaskCount,dwFlags,lpPassword,dwPasswordLen,bCompress);

    MemFree(lpSourceFolderW);
    MemFreeArrayOfPointers((LPVOID*)lppFileMaskW,dwFileMaskCount);
    return bRet;
}

static bool FileCont_ReadContainer(PFILE_CONT_HANDLE lpHandle,LPBYTE lpData,DWORD dwDataSize)
{
    PFILE_CONT_FILES_LIST lpLastFile=NULL;

    while (dwDataSize >= sizeof(FILE_CONT_FILE_INFO))
    {
        PFILE_CONT_FILE_INFO lpFile=(PFILE_CONT_FILE_INFO)lpData;
        if (lpFile->dwFileHdrMagic != FILE_CONT_FILE_HDR_MAGIC)
            break;

        DWORD dwTotalFileSize=lpFile->dwFileNameSize+lpFile->dwCompressedFileSize+sizeof(*lpFile);
        if (dwDataSize < dwTotalFileSize)
            break;

        PFILE_CONT_FILE_INFO lpNewFile=(PFILE_CONT_FILE_INFO)MemCopyEx(lpFile,dwTotalFileSize);
        if (!lpNewFile)
            break;

        if (!lpLastFile)
            lpLastFile=lpHandle->lpFiles=(PFILE_CONT_FILES_LIST)MemAlloc(sizeof(*lpLastFile));
        else
        {
            lpLastFile->lpNext=(PFILE_CONT_FILES_LIST)MemAlloc(sizeof(*lpLastFile));
            lpLastFile=lpLastFile->lpNext;
        }

        lpLastFile->lpFile=lpNewFile;

        dwDataSize-=dwTotalFileSize;
        lpData+=dwTotalFileSize;
    }
    return (lpHandle->lpFiles != NULL);
}

SYSLIBFUNC(HANDLE) FileCont_OpenW(LPCWSTR lpContainerFile,LPCSTR lpPassword,DWORD dwPasswordLen,BOOL bReadOnly,BOOL bContInMem,DWORD dwFileSize)
{
    PFILE_CONT_HANDLE lpHandle=NULL;

    if (!SYSLIB_SAFE::CheckStrParamA(lpPassword,dwPasswordLen))
    {
        lpPassword=NULL;
        dwPasswordLen=0;
    }

    if (bContInMem)
    {
        if (!SYSLIB_SAFE::CheckParamRead((LPVOID)lpContainerFile,dwFileSize))
            return NULL;

        lpHandle=FileCont_CreateHandle();
        if (lpHandle)
        {
            lpHandle->bInMem=true;
            lpHandle->lpPassword=StrDuplicateA(lpPassword,dwPasswordLen);
            lpHandle->dwPasswordLen=dwPasswordLen;

            if (!FileCont_ReadContainer(lpHandle,(LPBYTE)lpContainerFile,dwFileSize))
            {
                MemFree(lpHandle->lpPassword);
                MemFree(lpHandle);
                lpHandle=NULL;
            }
        }
    }
    else
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpContainerFile,0))
            return NULL;

        HANDLE hFile=CreateFileW(lpContainerFile,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            lpHandle=FileCont_CreateHandle();
            if (lpHandle)
            {
                lpHandle->hContFile=hFile;
                lpHandle->lpPassword=StrDuplicateA(lpPassword,dwPasswordLen);
                lpHandle->dwPasswordLen=dwPasswordLen;

                bool bRet=false;
                HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,NULL,NULL,NULL);
                if (hMapping)
                {
                    LPBYTE lpMap=(LPBYTE)MapViewOfFile(hMapping,FILE_MAP_READ,NULL,NULL,NULL);
                    if (lpMap)
                    {
                        bRet=FileCont_ReadContainer(lpHandle,lpMap,GetFileSize(hFile,NULL));
                        if (bRet)
                            lpHandle->bReadOnly=bReadOnly;
                        UnmapViewOfFile(lpMap);
                    }
                    SysCloseHandle(hMapping);
                }

                if (!bRet)
                {
                    MemFree(lpHandle->lpPassword);
                    MemFree(lpHandle);
                    lpHandle=NULL;
                    SysCloseHandle(hFile);
                }
            }
            else
                SysCloseHandle(hFile);
        }
    }
    return (HANDLE)lpHandle;
}

SYSLIBFUNC(HANDLE) FileCont_OpenA(LPCSTR lpContainerFile,LPCSTR lpPassword,DWORD dwPasswordLen,BOOL bReadOnly,BOOL bContInMem,DWORD dwFileSize)
{
    HANDLE hCont=NULL;
    if (bContInMem)
        hCont=FileCont_OpenW((LPCWSTR)lpContainerFile,lpPassword,dwPasswordLen,bReadOnly,bContInMem,dwFileSize);
    else
    {
        LPWSTR lpContainerFileW=StrAnsiToUnicodeEx(lpContainerFile,0,NULL);
        hCont=FileCont_OpenW(lpContainerFileW,lpPassword,dwPasswordLen,bReadOnly,bContInMem,dwFileSize);
        MemFree(lpContainerFileW);
    }
    return hCont;
}

static bool FileCont_GetFileInt(PFILE_CONT_HANDLE lpContainer,PFILE_CONT_FILE_INFO lpFile,LPBYTE *lppMem,LPDWORD lpdwSize,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    bool bRet=false;

    if (!SYSLIB_SAFE::CheckStrParamA(lpPassword,dwPasswordLen))
    {
        lpPassword=NULL;
        dwPasswordLen=0;
    }

    int dwNewSize=0;
    LPBYTE lpData=NULL,lpSourceDataPtr=lpFile->bFileBody+lpFile->dwFileNameSize;
    do
    {
        if (lpFile->dwFlags & FILE_FLAG_ENCRYPTED)
        {
            LPCSTR lpRealPassword=NULL;
            DWORD dwRealPasswordLen=0;

            if (lpPassword)
            {
                lpRealPassword=lpPassword;
                dwRealPasswordLen=dwPasswordLen;
            }
            else if (lpContainer->lpPassword)
            {
                lpRealPassword=lpContainer->lpPassword;
                dwRealPasswordLen=lpContainer->dwPasswordLen;
            }

            if (!lpRealPassword)
                break;

            lpData=rc4FullEx(lpRealPassword,dwRealPasswordLen,lpSourceDataPtr,lpFile->dwCompressedFileSize);
        }
        else
            lpData=(LPBYTE)MemCopyEx(lpSourceDataPtr,lpFile->dwCompressedFileSize);

        dwNewSize=lpFile->dwCompressedFileSize;

        if (!lpData)
            break;

        if (lpFile->dwFlags & FILE_FLAG_COMPRESSED)
        {
            dwNewSize=aPsafe_get_orig_size(lpData);
            if (dwNewSize == APLIB_ERROR)
                break;

            LPBYTE lpNewData=(LPBYTE)MemQuickAlloc(dwNewSize);
            if (!lpNewData)
                break;

            bRet=(aPsafe_depack(lpData,lpFile->dwCompressedFileSize,lpNewData,dwNewSize) == dwNewSize);
            MemFree(lpData);
            lpData=lpNewData;
            break;
        }

        bRet=true;
    }
    while (false);

    if (bRet)
    {
        if (MurmurHash3(lpData,dwNewSize) == lpFile->dwFileCheckSum)
        {
            *lppMem=lpData;
            *lpdwSize=dwNewSize;
        }
        else
        {
            MemFree(lpData);
            bRet=false;
        }
    }

    return bRet;
}

static bool FileCont_ExtractFileInt(PFILE_CONT_HANDLE lpContainer,PFILE_CONT_FILE_INFO lpFile,LPCWSTR lpFullFileName,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    bool bRet=false;
    DWORD dwSize;
    LPBYTE lpMem;
    if (FileCont_GetFileInt(lpContainer,lpFile,&lpMem,&dwSize,lpPassword,dwPasswordLen))
    {
        HANDLE hFile=CreateFileW(lpFullFileName,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            DWORD tmp;
            WriteFile(hFile,lpMem,dwSize,&tmp,NULL);

            LARGE_INTEGER liTime;
            RtlSecondsSince1980ToTime(lpFile->dwFileTime,&liTime);

            FILETIME ftTime={liTime.u.LowPart,liTime.u.HighPart};
            SetFileTime(hFile,&ftTime,&ftTime,&ftTime);

            SysCloseHandle(hFile);

            bRet=true;
        }
        MemFree(lpMem);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_ExtractFileW(HANDLE hCont,LPCWSTR lpPath,LPCWSTR lpFileName,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    if (!SYSLIB_SAFE::CheckStrParamW(lpFileName,0))
        return FALSE;

    WCHAR szCurrentDirectory[MAX_PATH];
    if (!SYSLIB_SAFE::CheckStrParamW(lpPath,0))
    {
        GetCurrentDirectoryW(ARRAYSIZE(szCurrentDirectory),szCurrentDirectory);
        lpPath=szCurrentDirectory;
    }

    BOOL bRet=false;

    PFILE_CONT_HANDLE lpContainer=(PFILE_CONT_HANDLE)hCont;

    EnterCriticalSection(&lpContainer->csContainer);
    {
        LPSTR lpFileNameUtf8=StrUnicodeToUtf8Ex(lpFileName,0,NULL);
        if (lpFileNameUtf8)
        {
            PFILE_CONT_FILES_LIST lpFile=lpContainer->lpFiles;
            while (lpFile)
            {
                if (!StrCmpNIA(lpFile->lpFile->szFileName,lpFileNameUtf8,lpFile->lpFile->dwFileNameSize))
                {
                    LPWSTR lpFullPath;
                    DWORD dwStrSize=StrFormatExW(&lpFullPath,dcrW_4f072b6d("%s\\%s"),lpPath,lpFileName);
                    if (dwStrSize)
                    {
                        LPWSTR lpPathPtr=lpFullPath+dwStrSize;
                        while (*lpPathPtr != L'\\')
                            lpPathPtr--;

                        *lpPathPtr=0;
                        CreateDirectoryTree(lpFullPath);
                        *lpPathPtr=L'\\';

                        bRet=FileCont_ExtractFileInt(lpContainer,lpFile->lpFile,lpFullPath,lpPassword,dwPasswordLen);
                        MemFree(lpFullPath);
                    }
                    break;
                }

                lpFile=lpFile->lpNext;
            }
            MemFree(lpFileNameUtf8);
        }
    }
    LeaveCriticalSection(&lpContainer->csContainer);
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_ExtractFileA(HANDLE hCont,LPCSTR lpPath,LPCSTR lpFileName,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    LPWSTR lpPathW=StrAnsiToUnicodeEx(lpPath,0,NULL),
           lpFileNameW=StrAnsiToUnicodeEx(lpFileName,0,NULL);

    BOOL bRet=FileCont_ExtractFileW(hCont,lpPathW,lpFileNameW,lpPassword,dwPasswordLen);

    MemFree(lpPathW);
    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_ExtractFilesW(HANDLE hCont,LPCWSTR lpPath)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    BOOL bRet=false;

    WCHAR szCurrentDirectory[MAX_PATH];
    if (!SYSLIB_SAFE::CheckStrParamW(lpPath,0))
    {
        GetCurrentDirectoryW(ARRAYSIZE(szCurrentDirectory),szCurrentDirectory);
        lpPath=szCurrentDirectory;
    }

    PFILE_CONT_HANDLE lpContainer=(PFILE_CONT_HANDLE)hCont;

    EnterCriticalSection(&lpContainer->csContainer);
    {
        PFILE_CONT_FILES_LIST lpFile=lpContainer->lpFiles;
        while (lpFile)
        {
            LPWSTR lpFileNameW=StrUtf8ToUnicodeEx(lpFile->lpFile->szFileName,lpFile->lpFile->dwFileNameSize,NULL);
            if (lpFileNameW)
            {
                LPWSTR lpFullPath;
                DWORD dwStrSize=StrFormatExW(&lpFullPath,dcrW_4f072b6d("%s\\%s"),lpPath,lpFileNameW);
                if (dwStrSize)
                {
                    LPWSTR lpPathPtr=lpFullPath+dwStrSize;
                    while (*lpPathPtr != L'\\')
                        lpPathPtr--;

                    *lpPathPtr=0;
                    CreateDirectoryTree(lpFullPath);
                    *lpPathPtr=L'\\';

                    if (FileCont_ExtractFileInt(lpContainer,lpFile->lpFile,lpFullPath,NULL,0))
                        bRet=true;
                    MemFree(lpFullPath);
                }

                MemFree(lpFileNameW);
            }

            lpFile=lpFile->lpNext;
        }
    }
    LeaveCriticalSection(&lpContainer->csContainer);
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_ExtractFilesA(HANDLE hCont,LPCSTR lpPath)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    LPWSTR lpPathW=StrAnsiToUnicodeEx(lpPath,0,NULL);

    BOOL bRet=FileCont_ExtractFilesW(hCont,lpPathW);

    MemFree(lpPathW);
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_GetFileW(HANDLE hCont,LPCWSTR lpFileName,LPBYTE *lppMem,LPDWORD lpdwSize,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    PFILE_CONT_HANDLE lpContainer=(PFILE_CONT_HANDLE)hCont;

    BOOL bRet=false;
    EnterCriticalSection(&lpContainer->csContainer);
    {
        LPSTR lpFileNameUtf8=StrUnicodeToUtf8Ex(lpFileName,0,NULL);
        if (lpFileNameUtf8)
        {
            PFILE_CONT_FILES_LIST lpFile=lpContainer->lpFiles;
            while (lpFile)
            {
                if (!StrCmpNIA(lpFile->lpFile->szFileName,lpFileNameUtf8,lpFile->lpFile->dwFileNameSize))
                {
                    bRet=FileCont_GetFileInt(lpContainer,lpFile->lpFile,lppMem,lpdwSize,lpPassword,dwPasswordLen);
                    break;
                }

                lpFile=lpFile->lpNext;
            }
            MemFree(lpFileNameUtf8);
        }
    }
    LeaveCriticalSection(&lpContainer->csContainer);
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_GetFileA(HANDLE hCont,LPCSTR lpFileName,LPBYTE *lppMem,LPDWORD lpdwSize,LPCSTR lpPassword,DWORD dwPasswordLen)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFileName,0,NULL);

    BOOL bRet=FileCont_GetFileW(hCont,lpFileNameW,lppMem,lpdwSize,lpPassword,dwPasswordLen);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_EnumFilesW(HANDLE hCont,CONTENUMNAMESCALLBACKW *lpCallback)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    /// !!!
    return FALSE;
}

SYSLIBFUNC(BOOL) FileCont_EnumFilesA(HANDLE hCont,CONTENUMNAMESCALLBACKA *lpCallback)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    /// !!!
    return FALSE;
}

SYSLIBFUNC(BOOL) FileCont_GetFileInfoW(HANDLE hCont,LPCWSTR lpFileName,PFILE_IN_CONT_INFO lpInfo)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    if (!SYSLIB_SAFE::CheckParamWrite(lpInfo,sizeof(*lpInfo)))
        return FALSE;

    PFILE_CONT_HANDLE lpContainer=(PFILE_CONT_HANDLE)hCont;

    BOOL bRet=false;
    EnterCriticalSection(&lpContainer->csContainer);
    {
        LPSTR lpFileNameUtf8=StrUnicodeToUtf8Ex(lpFileName,0,NULL);
        if (lpFileNameUtf8)
        {
            PFILE_CONT_FILES_LIST lpFile=lpContainer->lpFiles;
            while (lpFile)
            {
                if (!StrCmpNIA(lpFile->lpFile->szFileName,lpFileNameUtf8,lpFile->lpFile->dwFileNameSize))
                {
                    lpInfo->dwCompressedSize=lpFile->lpFile->dwCompressedFileSize;
                    lpInfo->dwDecompressedSize=lpFile->lpFile->dwRealFileSize;
                    lpInfo->dwDosDate=lpFile->lpFile->dwFileTime;
                    lpInfo->dwChecksum=lpFile->lpFile->dwFileCheckSum;
                    bRet=true;
                    break;
                }

                lpFile=lpFile->lpNext;
            }
            MemFree(lpFileNameUtf8);
        }
    }
    LeaveCriticalSection(&lpContainer->csContainer);
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_GetFileInfoA(HANDLE hCont,LPCSTR lpFileName,PFILE_IN_CONT_INFO lpInfo)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFileName,0,NULL);

    BOOL bRet=FileCont_GetFileInfoW(hCont,lpFileNameW,lpInfo);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_DeleteFileW(HANDLE hCont,LPCWSTR lpFileName)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    PFILE_CONT_HANDLE lpContainer=(PFILE_CONT_HANDLE)hCont;

    BOOL bRet=false;
    EnterCriticalSection(&lpContainer->csContainer);
    {
        LPSTR lpFileNameUtf8=StrUnicodeToUtf8Ex(lpFileName,0,NULL);
        if (lpFileNameUtf8)
        {
            DWORD dwFilePointer=0;
            PFILE_CONT_FILES_LIST lpFile=lpContainer->lpFiles,lpPrevFile=NULL;
            while (lpFile)
            {
                if (!StrCmpNIA(lpFile->lpFile->szFileName,lpFileNameUtf8,lpFile->lpFile->dwFileNameSize))
                {
                    PFILE_CONT_FILES_LIST lpNext=lpFile->lpNext;
                    if (lpPrevFile)
                        lpPrevFile->lpNext=lpNext;
                    else
                        lpContainer->lpFiles=lpNext;

                    MemFree(lpFile->lpFile);
                    MemFree(lpFile);

                    if ((!lpContainer->bInMem) && (!lpContainer->bReadOnly))
                    {
                        SetFilePointer(lpContainer->hContFile,dwFilePointer,NULL,FILE_BEGIN);
                        SetEndOfFile(lpContainer->hContFile);

                        while (lpNext)
                        {
                            DWORD tmp;
                            WriteFile(lpContainer->hContFile,lpNext->lpFile,sizeof(*lpNext->lpFile)+lpNext->lpFile->dwFileNameSize+lpNext->lpFile->dwCompressedFileSize,&tmp,NULL);
                            lpNext=lpNext->lpNext;
                        }
                    }

                    bRet=true;
                    break;
                }

                dwFilePointer+=sizeof(*lpFile->lpFile)+lpFile->lpFile->dwFileNameSize+lpFile->lpFile->dwCompressedFileSize;
                lpPrevFile=lpFile;
                lpFile=lpFile->lpNext;
            }
            MemFree(lpFileNameUtf8);
        }
    }
    LeaveCriticalSection(&lpContainer->csContainer);
    return bRet;
}

SYSLIBFUNC(BOOL) FileCont_DeleteFileA(HANDLE hCont,LPCSTR lpFileName)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return FALSE;

    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFileName,0,NULL);

    BOOL bRet=FileCont_DeleteFileW(hCont,lpFileNameW);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(DWORD) FileCont_GetRealSize(HANDLE hCont)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return 0;

    PFILE_CONT_HANDLE lpContainer=(PFILE_CONT_HANDLE)hCont;

    DWORD dwRealSize=0;
    EnterCriticalSection(&lpContainer->csContainer);
    {
        PFILE_CONT_FILES_LIST lpFile=lpContainer->lpFiles;
        while (lpFile)
        {
            dwRealSize+=sizeof(*lpFile->lpFile)+lpFile->lpFile->dwFileNameSize+lpFile->lpFile->dwCompressedFileSize;

            lpFile=lpFile->lpNext;
        }
    }
    LeaveCriticalSection(&lpContainer->csContainer);
    return dwRealSize;
}

SYSLIBFUNC(void) FileCont_Close(HANDLE hCont)
{
    if (!FileCont_CheckHandle((PFILE_CONT_HANDLE)hCont))
        return;

    PFILE_CONT_HANDLE lpContainer=(PFILE_CONT_HANDLE)hCont;
    EnterCriticalSection(&lpContainer->csContainer);
    {
        if (!lpContainer->bInMem)
        {
            if (!lpContainer->bReadOnly)
                FlushFileBuffers(lpContainer->hContFile);

            SysCloseHandle(lpContainer->hContFile);
            lpContainer->hContFile=INVALID_HANDLE_VALUE;
        }

        MemFree(lpContainer->lpPassword);

        PFILE_CONT_FILES_LIST lpFile=lpContainer->lpFiles;
        while (lpFile)
        {
            PFILE_CONT_FILES_LIST lpNext=lpFile->lpNext;

            MemFree(lpFile->lpFile);
            MemFree(lpFile);

            lpFile=lpNext;
        }
    }
    LeaveCriticalSection(&lpContainer->csContainer);

    DeleteCriticalSection(&lpContainer->csContainer);
    MemFree(lpContainer);
    return;
}

