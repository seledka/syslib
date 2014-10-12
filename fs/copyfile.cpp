#include "sys_includes.h"

#include "syslib\mem.h"
#include "syslib\system.h"
#include "syslib\str.h"

static bool CopyLoop(HANDLE hSourceFile,HANDLE hDestFile,LARGE_INTEGER liSourceFileSize)
{
    bool bRet=false;
    bool bEndOfFileFound=false;
    byte *lpBuffer=(byte*)VirtualAlloc(NULL,0x10000,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (lpBuffer)
    {
        IO_STATUS_BLOCK IoStatusBlock;
        LARGE_INTEGER BytesCopied={0};
        NTSTATUS ErrCode=STATUS_SUCCESS;
        while ((!bEndOfFileFound) && (NT_SUCCESS(ErrCode)))
        {
            ErrCode=ZwReadFile(hSourceFile,NULL,NULL,NULL,&IoStatusBlock,lpBuffer,0x10000,NULL,NULL);
            if (NT_SUCCESS(ErrCode))
            {
                ErrCode=ZwWriteFile(hDestFile,NULL,NULL,NULL,&IoStatusBlock,lpBuffer,IoStatusBlock.Information,NULL,NULL);
                if (NT_SUCCESS(ErrCode))
                    BytesCopied.QuadPart+=IoStatusBlock.Information;
            }
            else if (ErrCode == STATUS_END_OF_FILE)
             {
                bEndOfFileFound=bRet=true;
                ErrCode=STATUS_SUCCESS;
             }
        }
        VirtualFree(lpBuffer,0,MEM_RELEASE);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) CopyFileAndFlushBuffersW(LPCWSTR lpExistingFileName,LPCWSTR lpNewFileName,BOOL bFailIfExists)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpExistingFileName,MAX_PATH))
        return false;

    if (!SYSLIB_SAFE::CheckStrParamW(lpNewFileName,MAX_PATH))
        return false;

    BOOL bRet=false;
    HANDLE hSourceFile=CreateFileW(lpExistingFileName,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_NO_BUFFERING,NULL);
    if (hSourceFile != INVALID_HANDLE_VALUE)
    {
        IO_STATUS_BLOCK IoStatusBlock;
        FILE_STANDARD_INFORMATION FileStandard;
        FILE_BASIC_INFORMATION FileBasic;
        if (NT_SUCCESS(ZwQueryInformationFile(hSourceFile,&IoStatusBlock,&FileStandard,sizeof(FILE_STANDARD_INFORMATION),FileStandardInformation)))
        {
            if (NT_SUCCESS(ZwQueryInformationFile(hSourceFile,&IoStatusBlock,&FileBasic,sizeof(FILE_BASIC_INFORMATION),FileBasicInformation)))
            {
                HANDLE hDestFile=CreateFileW(lpNewFileName,GENERIC_WRITE,FILE_SHARE_WRITE,NULL,bFailIfExists ? CREATE_NEW : CREATE_ALWAYS,FileBasic.FileAttributes,NULL);
                if (hDestFile != INVALID_HANDLE_VALUE)
                {
                    bRet=CopyLoop(hSourceFile,hDestFile,FileStandard.EndOfFile);
                    if (bRet)
                    {
                        SetFileTime(hDestFile,(FILETIME*)&FileBasic.CreationTime,
                                              (FILETIME*)&FileBasic.LastAccessTime,
                                              (FILETIME*)&FileBasic.LastWriteTime);
                        FlushFileBuffers(hDestFile);
                    }
                    SysCloseHandle(hDestFile);
                    if (!bRet)
                    {
                        SetFileAttributesW(lpNewFileName,FILE_ATTRIBUTE_NORMAL);
                        DeleteFileW(lpNewFileName);
                    }
                }
            }
            SysCloseHandle(hSourceFile);
        }
    }
    return bRet;
}

SYSLIBFUNC(BOOL) CopyFileAndFlushBuffersA(LPCSTR lpExistingFileName,LPCSTR lpNewFileName,BOOL bFailIfExists)
{
    LPWSTR lpExistingFileNameW=StrAnsiToUnicodeEx(lpExistingFileName,0,NULL),
           lpNewFileNameW=StrAnsiToUnicodeEx(lpNewFileName,0,NULL);

    BOOL bRet=CopyFileAndFlushBuffersW(lpExistingFileNameW,lpNewFileNameW,bFailIfExists);

    MemFree(lpExistingFileNameW);
    MemFree(lpNewFileNameW);
    return bRet;
}

