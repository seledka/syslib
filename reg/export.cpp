#include "sys_includes.h"
#include "reg.h"

#include "syslib\files.h"
#include "syslib\debug.h"
#include "syslib\system.h"
#include "syslib\str.h"
#include "syslib\mem.h"

// TODO (Гость#1#): сжатие, шифрование, флаги
// TODO (Гость#1#): сохранять сначала во временный файл

static bool ExportKey(HKEY hKey,LPCWSTR lpSubKey,HANDLE hFile,DWORD dwDeepLevel,DWORD dwFlags)
{
    bool bRet=false;
    HKEY hCurKey;
    if (RegOpenKeyEx(hKey,lpSubKey,0,KEY_READ,&hCurKey) == ERROR_SUCCESS)
    {
		DWORD dwLongestSubkeyNameLen,dwLongestValueNameLen,dwLongestDataLen;
		if (RegQueryInfoKeyW(hCurKey,NULL,NULL,NULL,NULL,&dwLongestSubkeyNameLen,NULL,NULL,&dwLongestValueNameLen,&dwLongestDataLen,NULL,NULL) == ERROR_SUCCESS)
        {
			dwLongestValueNameLen++;
            WCHAR *lpName=WCHAR_QuickAlloc(dwLongestValueNameLen);
            if (lpName)
            {
                dwLongestDataLen++;
                byte *lpData=(byte*)MemQuickAlloc(dwLongestDataLen);
                if (lpData)
                {
                    if (lpSubKey)
                    {
                        DWORD tmp;
                        REG_ITEM riKey={0};
                        riKey.dwItemMagic=REG_ITEM_FMT_MAGIC;
                        riKey.dwType=REG_NONE;
                        riKey.dwNameSize=lstrlenW(lpSubKey);
                        riKey.dwDeepLevel=dwDeepLevel;
                        WriteFile(hFile,&riKey,sizeof(riKey),&tmp,NULL);
                        WriteFile(hFile,lpSubKey,riKey.dwNameSize*sizeof(WCHAR),&tmp,NULL);
                    }

                    for (int i=0; ; i++)
                    {
                        DWORD tmp;
                        REG_ITEM riVal={0};
                        riVal.dwItemMagic=REG_ITEM_FMT_MAGIC;
                        riVal.dwNameSize=dwLongestValueNameLen;
                        riVal.dwItemSize=dwLongestDataLen;
                        riVal.dwDeepLevel=dwDeepLevel;

                        DWORD dwRet=RegEnumValueW(hCurKey,i,lpName,&riVal.dwNameSize,NULL,&riVal.dwType,lpData,&riVal.dwItemSize);
                        if (dwRet != ERROR_SUCCESS)
                        {
                            if (dwRet == ERROR_NO_MORE_ITEMS)
                                bRet=true;
                            else if (dwRet == ERROR_MORE_DATA)
                            {
                                i--;
                                dwLongestDataLen=riVal.dwItemSize;
                                lpData=(byte*)MemRealloc(lpData,dwLongestDataLen);
                                if (lpData)
                                    continue;
                            }

                            break;
                        }

                        WriteFile(hFile,&riVal,sizeof(riVal),&tmp,NULL);
                        WriteFile(hFile,lpName,riVal.dwNameSize*sizeof(WCHAR),&tmp,NULL);
                        WriteFile(hFile,lpData,riVal.dwItemSize,&tmp,NULL);
                    }

                    if (bRet)
                    {
                        dwLongestSubkeyNameLen++;
                        WCHAR *lpSubKeyName=WCHAR_QuickAlloc(dwLongestSubkeyNameLen);
                        if (lpSubKeyName)
                        {
                            for (int i=0; ; i++)
                            {
                                DWORD dwRet=RegEnumKey(hCurKey,i,lpSubKeyName,dwLongestSubkeyNameLen);
                                if (dwRet != ERROR_SUCCESS)
                                {
                                    if (dwRet == ERROR_MORE_DATA)
                                    {
                                        i--;
                                        dwLongestSubkeyNameLen*=2;
                                        lpData=(byte*)MemRealloc(lpData,dwLongestSubkeyNameLen*sizeof(WCHAR));
                                        if (lpData)
                                            continue;
                                    }
                                    else if (dwRet != ERROR_NO_MORE_ITEMS)
                                        bRet=false;

                                    break;
                                }

                                if (!ExportKey(hCurKey,lpSubKeyName,hFile,dwDeepLevel+1,dwFlags))
                                    break;
                            }
                            MemFree(lpSubKeyName);
                        }
                    }

                    MemFree(lpData);
                }
                MemFree(lpName);
            }
		}
        RegCloseKey(hCurKey);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) Registry_ExportKeyExW(HKEY hKey,LPCWSTR lpSubKey,LPCWSTR lpFile,DWORD dwFlags)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
        return false;

    if (lpSubKey)
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpSubKey,0))
            lpSubKey=NULL;
    }

    BOOL bRet=false;
    if (hKey)
    {
        HANDLE hFile=CreateFileW(lpFile,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            REG_FILE_FMT_HDR hdr;
            hdr.dwFileMagic=REG_FILE_FMT_MAGIC;
            hdr.wVersion=REG_CUR_VERSION;
            hdr.dwFlags=dwFlags;
            DWORD tmp;
            WriteFile(hFile,&hdr,sizeof(hdr),&tmp,NULL);

            HKEY hCurKey;
            if (RegOpenKeyEx(hKey,lpSubKey,0,KEY_READ,&hCurKey) == ERROR_SUCCESS)
            {
                if (ExportKey(hCurKey,NULL,hFile,0,dwFlags))
                {
                    REG_ITEM riLastElement={0};
                    riLastElement.dwItemMagic=REG_ITEM_FMT_MAGIC;
                    WriteFile(hFile,&riLastElement,sizeof(riLastElement),&tmp,NULL);
                    FlushFileBuffers(hFile);

                    bRet=true;
                }
                RegCloseKey(hCurKey);
            }
            SysCloseHandle(hFile);

            if (!bRet)
                RemoveFileW(lpFile);
        }
    }
    return bRet;
}

SYSLIBFUNC(BOOL) Registry_ExportKeyExA(HKEY hKey,LPCSTR lpSubKey,LPCSTR lpFile,DWORD dwFlags)
{
    LPWSTR lpSubKeyW=StrAnsiToUnicodeEx(lpSubKey,0,NULL),
           lpFileW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=Registry_ExportKeyExW(hKey,lpSubKeyW,lpFileW,dwFlags);

    MemFree(lpSubKeyW);
    MemFree(lpFileW);
    return bRet;
}

SYSLIBFUNC(BOOL) Registry_ExportKeyW(HKEY hKey,LPCWSTR lpSubKey,LPCWSTR lpFile)
{
    return Registry_ExportKeyExW(hKey,lpSubKey,lpFile,0);
}

SYSLIBFUNC(BOOL) Registry_ExportKeyA(HKEY hKey,LPCSTR lpSubKey,LPCSTR lpFile)
{
    return Registry_ExportKeyExA(hKey,lpSubKey,lpFile,0);
}

