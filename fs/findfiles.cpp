#include "sys_includes.h"

#include <shlwapi.h>

#include "syslib\files.h"

namespace SYSLIB
{
    bool PathCombineA(LPSTR lpDest,LPCSTR lpDir,LPCSTR lpFile)
    {
        LPCSTR p=lpFile;
        if (p)
        {
            while ((*p == '\\') || (*p == '/'))
                p++;
        }
        return (::PathCombineA(lpDest,lpDir,p) != NULL);
    }

    bool IsDotsNameA(LPSTR lpName)
    {
      return ((lpName) && (*lpName == '.') && ((!lpName[1]) || ((lpName[1] == '.') && (!lpName[2])))) ? true : false;
    }
}

SYSLIBFUNC(void) FindFilesA(LPCSTR lpPath,LPCSTR *lppFileMasks,DWORD dwFileMasksCount,DWORD dwFlags,FINDFILEPROCA *lpFindFileProc,LPVOID lpData,DWORD dwSubfolderDelay,DWORD dwFoundedDelay)
{
    do
    {
        if (!dwFileMasksCount)
            break;

        if (!SYSLIB_SAFE::CheckStrParamA(lpPath,MAX_PATH))
            break;

        if (!SYSLIB_SAFE::CheckParamRead(lppFileMasks,dwFileMasksCount*sizeof(*lppFileMasks)))
            break;

        if (!SYSLIB_SAFE::CheckCodePtr(lpFindFileProc))
            break;

        char szCurPath[MAX_PATH];
        if (!SYSLIB::PathCombineA(szCurPath,lpPath,"*"))
            break;

        FILE_INFOA fiInfo={0};
        fiInfo.bFirstFileInDir=true;
        HANDLE hHandle=FindFirstFileA(szCurPath,&fiInfo.wfd);
        if (hHandle == INVALID_HANDLE_VALUE)
            break;

        do
        {
            if (SYSLIB::IsDotsNameA(fiInfo.wfd.cFileName))
                continue;

            if (((fiInfo.wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (dwFlags & FFF_SEARCH_FOLDERS)) || ((!(fiInfo.wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) && (dwFlags & FFF_SEARCH_FILES)))
            {
                bool bContinue=true;
                for (DWORD i=0; i < dwFileMasksCount; i++)
                {
                    if (PathMatchSpecA(fiInfo.wfd.cFileName,lppFileMasks[i]))
                    {
                        if (!lpFindFileProc(lpPath,&fiInfo,lpData))
                        {
                            fiInfo.bFirstFileInDir=false;
                            bContinue=false;
                            break;
                        }

                        if (dwFoundedDelay)
                            Sleep(dwFoundedDelay);
                        break;
                    }
                }
                if (!bContinue)
                    break;
            }

            if ((fiInfo.wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (dwFlags & FFF_RECURSIVE))
            {
                if (SYSLIB::PathCombineA(szCurPath,lpPath,fiInfo.wfd.cFileName))
                {
                    if (dwSubfolderDelay)
                        Sleep(dwSubfolderDelay);
                    FindFilesA(szCurPath,lppFileMasks,dwFileMasksCount,dwFlags,lpFindFileProc,lpData,dwSubfolderDelay,dwFoundedDelay);
                }
            }
        }
        while (FindNextFileA(hHandle,&fiInfo.wfd));
        FindClose(hHandle);
    }
    while (false);
    return;
}

namespace SYSLIB
{
    bool PathCombineW(LPWSTR lpDest,LPCWSTR lpDir,LPCWSTR lpFile)
    {
        LPCWSTR p=lpFile;
        if (p)
        {
            while ((*p == L'\\') || (*p == L'/'))
                p++;
        }
        return (::PathCombineW(lpDest,lpDir,p) != NULL);
    }

    bool IsDotsNameW(LPWSTR lpName)
    {
      return ((lpName) && (*lpName == L'.') && ((!lpName[1]) || ((lpName[1] == L'.') && (!lpName[2])))) ? true : false;
    }
}

SYSLIBFUNC(void) FindFilesW(LPCWSTR lpPath,LPCWSTR *lppFileMasks,DWORD dwFileMasksCount,DWORD dwFlags,FINDFILEPROCW *lpFindFileProc,LPVOID lpData,DWORD dwSubfolderDelay,DWORD dwFoundedDelay)
{
    do
    {
        if (!dwFileMasksCount)
            break;

        if (!SYSLIB_SAFE::CheckStrParamW(lpPath,MAX_PATH))
            break;

        if (!SYSLIB_SAFE::CheckParamRead(lppFileMasks,dwFileMasksCount*sizeof(*lppFileMasks)))
            break;

        if (!SYSLIB_SAFE::CheckCodePtr(lpFindFileProc))
            break;

        WCHAR szCurPath[MAX_PATH];
        if (!SYSLIB::PathCombineW(szCurPath,lpPath,L"*"))
            break;

        FILE_INFOW fiInfo={0};
        fiInfo.bFirstFileInDir=true;
        HANDLE hHandle=FindFirstFileW(szCurPath,&fiInfo.wfd);
        if (hHandle == INVALID_HANDLE_VALUE)
            break;

        do
        {
            if (SYSLIB::IsDotsNameW(fiInfo.wfd.cFileName))
                continue;

            if (((fiInfo.wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (dwFlags & FFF_SEARCH_FOLDERS)) || ((!(fiInfo.wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) && (dwFlags & FFF_SEARCH_FILES)))
            {
                bool bContinue=true;
                for (DWORD i=0; i < dwFileMasksCount; i++)
                {
                    if (PathMatchSpecW(fiInfo.wfd.cFileName,lppFileMasks[i]))
                    {
                        if (!lpFindFileProc(lpPath,&fiInfo,lpData))
                        {
                            fiInfo.bFirstFileInDir=false;
                            bContinue=false;
                            break;
                        }

                        if (dwFoundedDelay)
                            Sleep(dwFoundedDelay);
                        break;
                    }
                }
                if (!bContinue)
                    break;
            }

            if ((fiInfo.wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (dwFlags & FFF_RECURSIVE))
            {
                if (SYSLIB::PathCombineW(szCurPath,lpPath,fiInfo.wfd.cFileName))
                {
                    if (dwSubfolderDelay)
                        Sleep(dwSubfolderDelay);
                    FindFilesW(szCurPath,lppFileMasks,dwFileMasksCount,dwFlags,lpFindFileProc,lpData,dwSubfolderDelay,dwFoundedDelay);
                }
            }
        }
        while (FindNextFileW(hHandle,&fiInfo.wfd));
        FindClose(hHandle);
    }
    while (false);
    return;
}

