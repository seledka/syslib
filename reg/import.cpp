#include "sys_includes.h"
#include "reg.h"

#include "syslib\debug.h"
#include "syslib\system.h"
#include "syslib\str.h"
#include "syslib\mem.h"

// TODO (Гость#1#): распаковка, дешифровка, флаги
// TODO (Гость#1#): обработка предыдущих версий формата

static bool ImportKey(HKEY hKey,LPCWSTR lpSubKey,HANDLE hFile,DWORD *lpSize,DWORD dwDeepLevel,DWORD dwFlags)
{
    bool bRet=false;
    HKEY hCurKey;

    DWORD dwRet;
    if (lpSubKey)
        dwRet=RegCreateKeyExW(hKey,lpSubKey,NULL,NULL,0,KEY_WRITE|KEY_READ,NULL,&hCurKey,NULL);
    else
        dwRet=RegOpenKeyExW(hKey,lpSubKey,0,KEY_WRITE|KEY_READ,&hCurKey);

    if (dwRet == ERROR_SUCCESS)
    {
        DWORD dwLongestValueNameLen=0,dwLongestDataLen=0;

        WCHAR *lpName=NULL;
        byte *lpData=NULL;

        while (*lpSize)
        {
            DWORD dwRead;
            REG_ITEM riValue;
            if ((!ReadFile(hFile,&riValue,sizeof(riValue),&dwRead,NULL)) || (dwRead != sizeof(riValue)))
                break;

            if (riValue.dwItemMagic != REG_ITEM_FMT_MAGIC)
                break;

            *lpSize-=dwRead;
            if (!*lpSize)
            {
                if ((!riValue.dwItemSize) && (!riValue.dwNameSize))
                    bRet=true;
                break;
            }

            if ((riValue.dwDeepLevel < dwDeepLevel) || ((riValue.dwType == REG_NONE) && (riValue.dwDeepLevel <= dwDeepLevel)))
            {
                *lpSize+=dwRead;
                SetFilePointer(hFile,-sizeof(riValue),NULL,FILE_CURRENT);
                bRet=true;
                break;
            }

            if (riValue.dwNameSize)
            {
                if (riValue.dwNameSize+1 > dwLongestValueNameLen)
                {
                    lpName=(WCHAR*)MemRealloc(lpName,(riValue.dwNameSize+1)*sizeof(WCHAR));
                    if (!lpName)
                        break;
                    dwLongestValueNameLen=riValue.dwNameSize+1;
                }

                if ((!ReadFile(hFile,lpName,riValue.dwNameSize*sizeof(WCHAR),&dwRead,NULL)) || (dwRead != (riValue.dwNameSize*sizeof(WCHAR))))
                    break;

                lpName[riValue.dwNameSize]=0;
                *lpSize-=dwRead;
            }

            if (riValue.dwItemSize)
            {
                if (riValue.dwItemSize > dwLongestDataLen)
                {
                    lpData=(byte*)MemRealloc(lpData,riValue.dwItemSize);
                    if (!lpData)
                        break;
                    dwLongestDataLen=riValue.dwItemSize;
                }

                if ((!ReadFile(hFile,lpData,riValue.dwItemSize,&dwRead,NULL)) || (dwRead != riValue.dwItemSize))
                    break;

                *lpSize-=dwRead;
            }

            if (riValue.dwType == REG_NONE)
            {
                if (riValue.dwDeepLevel > dwDeepLevel)
                {
                    if (!ImportKey(hCurKey,lpName,hFile,lpSize,dwDeepLevel+1,dwFlags))
                        break;
                }
            }
            else
            {
                if (RegSetValueExW(hCurKey,lpName,NULL,riValue.dwType,lpData,riValue.dwItemSize) != ERROR_SUCCESS)
                    break;
            }
        }

        MemFree(lpName);
        MemFree(lpData);

        RegCloseKey(hCurKey);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) Registry_ImportKeyW(HKEY hKey,LPCWSTR lpSubKey,LPCWSTR lpFile)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
        return false;

    if (lpSubKey)
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpSubKey,0))
            lpSubKey=NULL;
    }

    BOOL bRet=false;
    if ((lpFile) && (hKey))
    {
        HANDLE hFile=CreateFileW(lpFile,GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            DWORD dwSize=GetFileSize(hFile,NULL);
            REG_FILE_FMT_HDR hdr;
            if (dwSize >= sizeof(hdr))
            {
                DWORD dwRead;
                if ((ReadFile(hFile,&hdr,sizeof(hdr),&dwRead,NULL)) && (dwRead == sizeof(hdr)))
                {
                    if ((hdr.dwFileMagic == REG_FILE_FMT_MAGIC) && (hdr.wVersion == REG_CUR_VERSION))
                    {
                        dwSize-=sizeof(hdr);
                        bRet=ImportKey(hKey,lpSubKey,hFile,&dwSize,0,hdr.dwFlags);
                    }
                }
            }
            SysCloseHandle(hFile);
        }
    }
    return bRet;
}

SYSLIBFUNC(BOOL) Registry_ImportKeyA(HKEY hKey,LPCSTR lpSubKey,LPCSTR lpFile)
{
    LPWSTR lpSubKeyW=StrAnsiToUnicodeEx(lpSubKey,0,NULL),
           lpFileW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=Registry_ImportKeyW(hKey,lpSubKeyW,lpFileW);

    MemFree(lpSubKeyW);
    MemFree(lpFileW);
    return bRet;
}

