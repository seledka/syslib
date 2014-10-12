#include "sys_includes.h"
#include <lmaccess.h>
#include <userenv.h>
#include <lm.h>
#include <sddl.h>
#include <shlwapi.h>
#include <shlobj.h>

#include "syslib\str.h"
#include "syslib\system.h"
#include "syslib\osenv.h"
#include "syslib\mem.h"
#include "osenv.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"


SYSLIBFUNC(void) GetUserDirA(LPSTR lpOut)
{
    if (SYSLIB_SAFE::CheckParamWrite(lpOut,MAX_PATH*sizeof(char)))
        SHGetFolderPathA(NULL,CSIDL_APPDATA,NULL,SHGFP_TYPE_CURRENT,lpOut);
    return;
}

SYSLIBFUNC(void) GetUserDirW(LPWSTR lpOut)
{
     if (SYSLIB_SAFE::CheckParamWrite(lpOut,MAX_PATH*sizeof(WCHAR)))
        SHGetFolderPathW(NULL,CSIDL_APPDATA,NULL,SHGFP_TYPE_CURRENT,lpOut);
    return;
}

SYSLIBFUNC(BOOL) GetUserProfileDirectoryBySidW(PSID lpSid,LPWSTR lpBuffer)
{
    if (!SYSLIB_SAFE::CheckParamWrite(lpBuffer,MAX_PATH*sizeof(WCHAR)))
        return false;

    if (!SYSLIB_SAFE::CheckParamRead(lpSid,sizeof(SID)))
        return false;

    BOOL bRet=false;
    LPWSTR lpSidStr;
    if (ConvertSidToStringSidW(lpSid,&lpSidStr))
    {
        WCHAR szRegPath[MAX_PATH];
        StrFormatW(szRegPath,dcrW_8ca953ba("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%s"),lpSidStr);

        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,szRegPath,0,KEY_READ|KEY_WOW64_64KEY,&hKey) == ERROR_SUCCESS)
        {
            WCHAR szRegValue[MAX_PATH];
            DWORD dwLen=sizeof(szRegValue);
            if (RegQueryValueEx(hKey,dcrW_7256d408("ProfileImagePath"),NULL,NULL,(byte*)szRegValue,&dwLen) == ERROR_SUCCESS)
            {
                PathUnquoteSpacesW(szRegValue);
                DWORD dwSize=ExpandEnvironmentStringsW(szRegValue,lpBuffer,MAX_PATH);
                bRet=((dwSize > 0) && (dwSize <= MAX_PATH));
            }
            RegCloseKey(hKey);
        }
        LocalFree(lpSidStr);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) GetUserProfileDirectoryBySidA(PSID lpSid,LPSTR lpBuffer)
{
    BOOL bRet=false;
    WCHAR szDir[MAX_PATH];
    bRet=GetUserProfileDirectoryBySidW(lpSid,szDir);
    if (bRet)
        StrUnicodeToAnsi(szDir,0,lpBuffer,0);
    return bRet;
}

static void EnumUserProfileDirsInt(ENUMUSERPROFILEDIRSINT *lpEupf)
{
    NET_API_STATUS dwStatus;
    do
    {
        DWORD dwHandle=0,
              dwReaded=0,
              dwTotal=0;
        USER_INFO_0 *lpBuf0=NULL;
        dwStatus=NetUserEnum(NULL,0,FILTER_NORMAL_ACCOUNT,(byte **)&lpBuf0,MAX_PREFERRED_LENGTH,&dwReaded,&dwTotal,&dwHandle);
        if (((dwStatus == NERR_Success) || (dwStatus == ERROR_MORE_DATA)) && (lpBuf0))
        {
            for (DWORD i=0; i < dwReaded; i++)
            {
                USER_INFO_23 *lpBuf23=NULL;
                if ((NetUserGetInfo(NULL,lpBuf0[i].usri0_name,23,(byte **)&lpBuf23) == NERR_Success) && (lpBuf23))
                {
                    if (lpEupf->bUnicode)
                    {
                        WCHAR szDirW[MAX_PATH];
                        if (GetUserProfileDirectoryBySidW(lpBuf23->usri23_user_sid,szDirW))
                        {
                            if (lpEupf->bParam)
                            {
                                if (lpEupf->lpCallbackParam((char*)szDirW,lpEupf->lpParam))
                                {
                                    dwStatus=0;
                                    break;
                                }
                            }
                            else
                            {
                                if (lpEupf->lpCallback((char*)szDirW))
                                {
                                    dwStatus=0;
                                    break;
                                }
                            }
                        }
                    }
                    else
                    {
                        char szDirA[MAX_PATH];
                        if (GetUserProfileDirectoryBySidA(lpBuf23->usri23_user_sid,szDirA))
                        {
                            if (lpEupf->bParam)
                            {
                                if (lpEupf->lpCallbackParam(szDirA,lpEupf->lpParam))
                                {
                                    dwStatus=0;
                                    break;
                                }
                            }
                            else
                            {
                                if (lpEupf->lpCallback(szDirA))
                                {
                                    dwStatus=0;
                                    break;
                                }
                            }
                        }
                    }
                    NetApiBufferFree(lpBuf23);
                }
            }
            NetApiBufferFree(lpBuf0);
        }
    }
    while (dwStatus == ERROR_MORE_DATA);
    return;
}

SYSLIBFUNC(void) EnumUserProfileDirsA(ENUMUSERPROFILEDIRSCALLBACKA *lpCallback)
{
    if (!SYSLIB_SAFE::CheckCodePtr(lpCallback))
        return;

    ENUMUSERPROFILEDIRSINT eupf={0};
    eupf.lpCallback=lpCallback;
    EnumUserProfileDirsInt(&eupf);
    return;
}

SYSLIBFUNC(void) EnumUserProfileDirsW(ENUMUSERPROFILEDIRSCALLBACKW *lpCallback)
{
    if (!SYSLIB_SAFE::CheckCodePtr(lpCallback))
        return;

    ENUMUSERPROFILEDIRSINT eupf={0};
    eupf.bUnicode=true;
    eupf.lpCallback=(ENUMUSERPROFILEDIRSCALLBACKA*)lpCallback;
    EnumUserProfileDirsInt(&eupf);
    return;
}

SYSLIBFUNC(void) EnumUserProfileDirsParamA(ENUMUSERPROFILEDIRSCALLBACKPARAMA *lpCallback,LPVOID lpParam)
{
    if (!SYSLIB_SAFE::CheckCodePtr(lpCallback))
        return;

    ENUMUSERPROFILEDIRSINT eupf={0};
    eupf.bParam=true;
    eupf.lpParam=lpParam;
    eupf.lpCallbackParam=lpCallback;
    EnumUserProfileDirsInt(&eupf);
    return;
}

SYSLIBFUNC(void) EnumUserProfileDirsParamW(ENUMUSERPROFILEDIRSCALLBACKPARAMW *lpCallback,LPVOID lpParam)
{
    if (!SYSLIB_SAFE::CheckCodePtr(lpCallback))
        return;

    ENUMUSERPROFILEDIRSINT eupf={0};
    eupf.bUnicode=true;
    eupf.bParam=true;
    eupf.lpParam=lpParam;
    eupf.lpCallbackParam=(ENUMUSERPROFILEDIRSCALLBACKPARAMA*)lpCallback;
    EnumUserProfileDirsInt(&eupf);
    return;
}

static void EnumProfilesInt(ENUMUSERPROFILESINT *lpEnum)
{
    NET_API_STATUS dwStatus=-1;
    do
    {
        DWORD dwHandle=0,
              dwReaded=0,
              dwTotal=0;
        USER_INFO_0 *lpBuf0=NULL;
        dwStatus=NetUserEnum(NULL,0,FILTER_NORMAL_ACCOUNT,(byte **)&lpBuf0,MAX_PREFERRED_LENGTH,&dwReaded,&dwTotal,&dwHandle);
        if (((dwStatus == NERR_Success) || (dwStatus == ERROR_MORE_DATA)) && (lpBuf0))
        {
            for (DWORD i=0; i < dwReaded; i++)
            {
                USER_INFO_23 *lpBuf23=NULL;
                if ((NetUserGetInfo(NULL,lpBuf0[i].usri0_name,23,(byte **)&lpBuf23) == NERR_Success) && (lpBuf23))
                {
                    if (!lpEnum->bParam)
                    {
                        if (lpEnum->lpCallback(lpBuf23->usri23_user_sid))
                            dwStatus=-1;
                    }
                    else
                    {
                        if (lpEnum->lpCallbackParam(lpBuf23->usri23_user_sid,lpEnum->lpParam))
                            dwStatus=-1;
                    }
                    NetApiBufferFree(lpBuf23);
                }
                if (dwStatus == -1)
                    break;
            }
            NetApiBufferFree(lpBuf0);
        }
    }
    while (dwStatus == ERROR_MORE_DATA);
    return;
}

SYSLIBFUNC(void) EnumUserProfiles(ENUMUSERPROFILESCALLBACK *lpCallback)
{
    if (!SYSLIB_SAFE::CheckCodePtr(lpCallback))
        return;

    ENUMUSERPROFILESINT eupEnum={0};
    eupEnum.lpCallback=lpCallback;
    EnumProfilesInt(&eupEnum);
    return;
}

SYSLIBFUNC(void) EnumUserProfilesParam(ENUMUSERPROFILESCALLBACKPARAM *lpCallback,LPVOID lpParam)
{
    if (!SYSLIB_SAFE::CheckCodePtr(lpCallback))
        return;

    ENUMUSERPROFILESINT eupEnum={0};
    eupEnum.bParam=true;
    eupEnum.lpParam=lpParam;
    eupEnum.lpCallbackParam=lpCallback;
    EnumProfilesInt(&eupEnum);
    return;
}

SYSLIBFUNC(BOOL) GetUserFolderPostfixW(int nFolder,LPWSTR lpBuffer)
{
    BOOL bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckParamWrite(lpBuffer,MAX_PATH*sizeof(WCHAR)))
            break;

        WCHAR szDefaultUserRoot[MAX_PATH];
        if (!SHGetFolderPathW(NULL,CSIDL_PROFILE,(HANDLE)-1,SHGFP_TYPE_DEFAULT,szDefaultUserRoot) == S_OK)
            break;

        WCHAR szDefaultUserDir[MAX_PATH];
        if (!SHGetFolderPathW(NULL,nFolder,(HANDLE)-1,SHGFP_TYPE_DEFAULT,szDefaultUserDir) == S_OK)
            break;

        DWORD dwSize=lstrlenW(szDefaultUserRoot);
        if (StrCmpNIW(szDefaultUserRoot,szDefaultUserDir,dwSize))
            break;

        lstrcpyW(lpBuffer,szDefaultUserDir+dwSize+1);
        bRet=true;
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) GetUserFolderPostfixA(int nFolder,LPSTR lpBuffer)
{
    BOOL bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckParamWrite(lpBuffer,MAX_PATH))
            break;

        char szDefaultUserRoot[MAX_PATH];
        if (!SHGetFolderPathA(NULL,CSIDL_PROFILE,(HANDLE)-1,SHGFP_TYPE_DEFAULT,szDefaultUserRoot) == S_OK)
            break;

        char szDefaultUserDir[MAX_PATH];
        if (!SHGetFolderPathA(NULL,nFolder,(HANDLE)-1,SHGFP_TYPE_DEFAULT,szDefaultUserDir) == S_OK)
            break;

        DWORD dwSize=lstrlenA(szDefaultUserRoot);
        if (StrCmpNIA(szDefaultUserRoot,szDefaultUserDir,dwSize))
            break;

        lstrcpyA(lpBuffer,szDefaultUserDir+dwSize+1);
        bRet=true;
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) GetUserStartupDirectoryBySidW(PSID lpSid,LPWSTR lpBuffer)
{
    BOOL bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckParamRead(lpSid,sizeof(SID)))
            break;

        if (!SYSLIB_SAFE::CheckStrParamW(lpBuffer,MAX_PATH))
            break;

        WCHAR szStartupPostfix[MAX_PATH];
        if (!GetUserFolderPostfixW(CSIDL_STARTUP,szStartupPostfix))
            break;

        WCHAR szDir[MAX_PATH];
        if (!GetUserProfileDirectoryBySidW(lpSid,szDir))
            break;

        StrFormatW(lpBuffer,dcrW_4f072b6d("%s\\%s"),szDir,szStartupPostfix);
        bRet=true;
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) GetUserStartupDirectoryBySidA(PSID lpSid,LPSTR lpBuffer)
{
    BOOL bRet=false;
    WCHAR szDir[MAX_PATH];
    bRet=GetUserStartupDirectoryBySidW(lpSid,szDir);
    if (bRet)
        StrUnicodeToAnsi(szDir,0,lpBuffer,0);
    return bRet;
}

SYSLIBFUNC(BOOL) SysGetCurrentUserSID(PSID *lppSid)
{
    BOOL bRet=false;

    HANDLE hToken=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckParamWrite(lppSid,sizeof(PSID)))
            break;

        if (!OpenProcessToken(GetCurrentProcess(),TOKEN_READ|TOKEN_QUERY,&hToken))
            break;

	    DWORD dwSize=0;
	    GetTokenInformation(hToken,TokenUser,NULL,0,&dwSize);
	    if (!dwSize)
            break;

	    LPBYTE lpBuf=(LPBYTE)MemAlloc(dwSize);
        if (GetTokenInformation(hToken,TokenUser,lpBuf,dwSize,&dwSize))
        {
            *lppSid=(PSID)MemCopyEx(((PTOKEN_USER)lpBuf)->User.Sid,GetLengthSid(((PTOKEN_USER)lpBuf)->User.Sid));
            bRet=true;
        }
        MemFree(lpBuf);
    }
    while (false);

    if (hToken)
        SysCloseHandle(hToken);

    return bRet;
}

SYSLIBFUNC(BOOL) SysGetSystemDirectoryW(LPWSTR lpBuffer,DWORD dwSize)
{
    if (!SYSLIB_SAFE::CheckParamWrite(lpBuffer,dwSize*sizeof(WCHAR)))
        return false;

#ifdef _X86_
    if (SysIsWindows64())
        return (GetSystemWow64DirectoryW(lpBuffer,dwSize) != 0);
    else
#endif
        return (GetSystemDirectoryW(lpBuffer,dwSize) != 0);
}

SYSLIBFUNC(BOOL) SysGetSystemDirectoryA(LPSTR lpBuffer,DWORD dwSize)
{
    WCHAR szBufW[MAX_PATH];
    BOOL bRet=SysGetSystemDirectoryW(szBufW,ARRAYSIZE(szBufW));
    if (bRet)
        StrUnicodeToAnsi(szBufW,0,lpBuffer,0);
    return bRet;
}

SYSLIBFUNC(LPWSTR) SysExpandEnvironmentStringsExW(LPCWSTR lpEnvStr)
{
    LPWSTR lpRes=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpEnvStr,MAX_PATH))
            break;

        DWORD dwNeededBytes=ExpandEnvironmentStringsW(lpEnvStr,NULL,0);
        if (!dwNeededBytes)
            break;

        lpRes=WCHAR_QuickAlloc(dwNeededBytes);
        if (!lpRes)
            break;

        ExpandEnvironmentStringsW(lpEnvStr,lpRes,dwNeededBytes);
    }
    while (false);
    return lpRes;
}

SYSLIBFUNC(LPSTR) SysExpandEnvironmentStringsExA(LPCSTR lpEnvStr)
{
    LPSTR lpRes=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamA(lpEnvStr,MAX_PATH))
            break;

        DWORD dwNeededBytes=ExpandEnvironmentStringsA(lpEnvStr,NULL,0);
        if (!dwNeededBytes)
            break;

        lpRes=(LPSTR)MemQuickAlloc(dwNeededBytes);
        if (!lpRes)
            break;

        ExpandEnvironmentStringsA(lpEnvStr,lpRes,dwNeededBytes);
    }
    while (false);
    return lpRes;
}

static void GetInstalledProgramsInt(HKEY hKey,LPWSTR *lppExistingProgramList)
{
    DWORD dwIndex=0;
    LONG lRet;
    TCHAR szSubKeyName[MAX_PATH];
    DWORD cbName=MAX_PATH;
    while ((lRet=RegEnumKeyEx(hKey,dwIndex,szSubKeyName,&cbName,NULL,NULL,NULL,NULL)) != ERROR_NO_MORE_ITEMS)
    {
        if (lRet == ERROR_SUCCESS)
        {
            HKEY hItem;
            if (RegOpenKeyEx(hKey,szSubKeyName,0,KEY_READ,&hItem) != ERROR_SUCCESS)
                continue;

            WCHAR szDisplayName[MAX_PATH];
            DWORD dwSize=sizeof(szDisplayName);
            DWORD dwType;
            if (RegQueryValueExW(hItem,dcrW_60d9dea2("DisplayName"),NULL,&dwType,(LPBYTE)&szDisplayName,&dwSize) == ERROR_SUCCESS)
            {
                if (*lppExistingProgramList)
                    StrCatFormatExW(lppExistingProgramList,0,dcrW_9061f095("\r\n%s"),szDisplayName);
                else
                    StrCatExW(lppExistingProgramList,szDisplayName,dwSize);
            }

            RegCloseKey(hItem);
        }
        dwIndex++;
        cbName=MAX_PATH;
    }
    return;
}

SYSLIBFUNC(LPCWSTR) GetInstalledProgramsW()
{
    LPWSTR lpList=NULL;
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,dcr_9483347d("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),0,KEY_READ|KEY_WOW64_64KEY,&hKey) == ERROR_SUCCESS)
    {
        GetInstalledProgramsInt(hKey,&lpList);
        RegCloseKey(hKey);
    }

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,dcr_ae625ea9("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),0,KEY_READ|KEY_WOW64_64KEY,&hKey) == ERROR_SUCCESS)
    {
        GetInstalledProgramsInt(hKey,&lpList);
        RegCloseKey(hKey);
    }
    return (LPCWSTR)lpList;
}

SYSLIBFUNC(LPCSTR) GetInstalledProgramsA()
{
    LPCSTR lpListA=NULL;
    LPWSTR lpListW=(LPWSTR)GetInstalledProgramsW();
    if (lpListW)
    {
        lpListA=StrUnicodeToAnsiEx(lpListW,0,NULL);
        MemFree(lpListW);
    }
    return lpListA;
}

SYSLIBFUNC(FS_TYPE) SysGetVolomeFSW(LPCWSTR lpPath)
{
    UINT uPrev=SetErrorMode(SEM_FAILCRITICALERRORS);

    FS_TYPE dwRet=UNKNOWN;
    WCHAR szFS[30],
          szVolume[4];
    StrFormatW(szVolume,dcrW_6b9f89f5("%c:\\"),lpPath[0]);
    if (GetVolumeInformationW(szVolume,NULL,0,NULL,NULL,NULL,szFS,ARRAYSIZE(szFS)))
    {
        if (!StrCmpNIW(szFS,dcrW_97d2fb4f("FAT"),3))
            dwRet=FAT;
        else if (!StrCmpNIW(szFS,dcrW_f2e49b5c("exFAT"),5))
            dwRet=FAT;
        else if (!StrCmpNIW(szFS,dcrW_a909b98e("NTFS"),4))
            dwRet=NTFS;
    }

    SetErrorMode(uPrev);
    return dwRet;
}

SYSLIBFUNC(FS_TYPE) SysGetVolomeFSA(LPCSTR lpPath)
{
    UINT uPrev=SetErrorMode(SEM_FAILCRITICALERRORS);

    FS_TYPE dwRet=UNKNOWN;
    char szFS[30],
         szVolume[4];
    StrFormatA(szVolume,dcrA_6b9f89f5("%c:\\"),lpPath[0]);
    if (GetVolumeInformationA(szVolume,NULL,0,NULL,NULL,NULL,szFS,ARRAYSIZE(szFS)))
    {
        if (!StrCmpNIA(szFS,dcrA_97d2fb4f("FAT"),3))
            dwRet=FAT;
        else if (!StrCmpNIA(szFS,dcrA_f2e49b5c("exFAT"),5))
            dwRet=FAT;
        else if (!StrCmpNIA(szFS,dcrA_a909b98e("NTFS"),4))
            dwRet=NTFS;
    }

    SetErrorMode(uPrev);
    return dwRet;
}

SYSLIBFUNC(LPWSTR) SysFindRecycleBinW(LPCWSTR lpPath)
{
    LPWSTR lpRecycledBin=NULL;

    bool bNTFS=(SysGetVolomeFSW(lpPath) == NTFS);

    PSID lpUser;
    SysGetCurrentUserSID(&lpUser);

    OSVERSIONINFO ver;
    ver.dwOSVersionInfoSize=sizeof(ver);
    GetVersionEx(&ver);

    if (ver.dwMajorVersion <= 5) /// XP
    {
        if (bNTFS)
        {
            LPWSTR lpSidStr;
            if (ConvertSidToStringSidW(lpUser,&lpSidStr))
            {
                StrFormatExW(&lpRecycledBin,dcrW_c4b6b0c3("%c:\\Recycler\\%s\\"),lpPath[0],lpSidStr);
                LocalFree(lpSidStr);
            }
        }
        else
            StrFormatExW(&lpRecycledBin,dcrW_74592a87("%c:\\RECYCLED\\"),lpPath[0]);
    }
    else /// Vista+
    {
        if (bNTFS)
        {
            LPWSTR lpSidStr;
            if (ConvertSidToStringSidW(lpUser,&lpSidStr))
            {
                StrFormatExW(&lpRecycledBin,dcrW_baf82c58("%c:\\$Recycle.bin\\%s\\"),lpPath[0],lpSidStr);
                LocalFree(lpSidStr);
            }
        }
        else
            StrFormatExW(&lpRecycledBin,dcrW_23516010("%c:\\$RECYCLE.BIN\\"),lpPath[0]);
    }

    MemFree(lpUser);

    return lpRecycledBin;
}

SYSLIBFUNC(LPSTR) SysFindRecycleBinA(LPCSTR lpPath)
{
    LPSTR lpRecycledBin=NULL;
    LPWSTR lpPathW=StrAnsiToUnicodeEx(lpPath,0,NULL);
    if (lpPathW)
    {
        LPWSTR lpRecycledBinW=SysFindRecycleBinW(lpPathW);
        if (lpRecycledBinW)
        {
            lpRecycledBin=StrUnicodeToAnsiEx(lpRecycledBinW,0,NULL);
            MemFree(lpRecycledBinW);
        }
        MemFree(lpPathW);
    }

    return lpRecycledBin;
}

SYSLIBFUNC(BOOL) CreateCurrentUserEnvironmentBlock(LPVOID *lppEnvironment,BOOL bInherit)
{
    HANDLE hTokenDup=NULL;
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(),TOKEN_DUPLICATE|TOKEN_QUERY,&hToken))
    {
        DuplicateTokenEx(hToken,MAXIMUM_ALLOWED,NULL,SecurityImpersonation,TokenPrimary,&hTokenDup);
        SysCloseHandle(hToken);
    }

    BOOL bRet=CreateEnvironmentBlock(lppEnvironment,hTokenDup,bInherit);
    SysCloseHandle(hTokenDup);
    return bRet;
}

