#include "sys_includes.h"
#include <shlwapi.h>

#include "hooks\splice.h"
#include "findfiles.h"

#include "syslib\debug.h"
#include "syslib\files.h"
#include "syslib\mem.h"
#include "syslib\str.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

SYSLIBFUNC(BOOL) CreateDirectoryTreeW(LPCWSTR lpPath)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpPath,MAX_PATH))
        return false;

    BOOL bRet=false;
    LPWSTR p=PathSkipRootW(lpPath);
    if (!p)
        p=(LPWSTR)lpPath;

    for (;; p++)
    {
        if ((*p == L'\\') || (*p == L'/') || (!*p))
        {
            WCHAR wOld=*p;
            *p=0;

            DWORD dwAttr=GetFileAttributesW(lpPath);
            if (dwAttr == INVALID_FILE_ATTRIBUTES)
            {
                if (CreateDirectoryW(lpPath,0) == FALSE)
                    break;
            }
            else if (!(dwAttr & FILE_ATTRIBUTE_DIRECTORY))
                break;

            if (!wOld)
            {
                bRet=true;
                break;
            }

            *p=wOld;
        }
    }
    return bRet;
}

SYSLIBFUNC(BOOL) CreateDirectoryTreeA(LPCSTR lpPath)
{
    LPWSTR lpPathW=StrAnsiToUnicodeEx(lpPath,0,NULL);

    BOOL bRet=CreateDirectoryTreeW(lpPathW);

    MemFree(lpPathW);
    return bRet;
}

SYSLIBFUNC(BOOL) CopyDirectoryW(LPCWSTR lpExistingDir,LPCWSTR lpNewDir)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpExistingDir,MAX_PATH))
        return false;

    if (!SYSLIB_SAFE::CheckStrParamW(lpNewDir,MAX_PATH))
        return false;

    BOOL bRet=false;
    CreateDirectory(lpNewDir,NULL);

    WCHAR szMask[MAX_PATH];
    StrFormatW(szMask,dcrW_f66abb03("%s\\*"),lpExistingDir);
    WIN32_FIND_DATAW wfd;
    HANDLE hFind=FindFirstFile(szMask,&wfd);
    if (hFind)
    {
        do
        {
            if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                if (!SYSLIB::IsDotsNameW(wfd.cFileName))
                {
                    WCHAR szIn[MAX_PATH];
                    StrFormatW(szIn,dcrW_7d96f09c("%s\\%s\\"),lpExistingDir,wfd.cFileName);

                    WCHAR szOut[MAX_PATH];
                    StrFormatW(szOut,dcrW_7d96f09c("%s\\%s\\"),lpNewDir,wfd.cFileName);

                    bRet=CopyDirectoryW(szIn,szOut);
                }
            }
            else
            {
                WCHAR szIn[MAX_PATH];
                StrFormatW(szIn,dcrW_4f072b6d("%s\\%s"),lpExistingDir,wfd.cFileName);

                WCHAR szOut[MAX_PATH];
                StrFormatW(szOut,dcrW_4f072b6d("%s\\%s"),lpNewDir,wfd.cFileName);

                bRet=CopyFileW(szIn,szOut,true);
            }
        }
        while (FindNextFileW(hFind,&wfd));

        FindClose(hFind);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) CopyDirectoryA(LPCSTR lpExistingDir,LPCSTR lpNewDir)
{
    LPWSTR lpExistingDirW=StrAnsiToUnicodeEx(lpExistingDir,0,NULL),
           lpNewDirW=StrAnsiToUnicodeEx(lpNewDir,0,NULL);

    BOOL bRet=CopyDirectoryW(lpExistingDirW,lpNewDirW);

    MemFree(lpExistingDirW);
    MemFree(lpNewDirW);
    return bRet;
}

SYSLIBFUNC(BOOL) RemoveDirectoryTreeW(LPCWSTR lpDir)
{
    BOOL bRet=false;
    if (SYSLIB_SAFE::CheckStrParamW(lpDir,MAX_PATH))
    {
        WIN32_FIND_DATAW fd;

        WCHAR stPath[MAX_PATH];
        StrFormatW(stPath,dcrW_f66abb03("%s\\*"),lpDir);

        HANDLE hFind=FindFirstFileW(stPath,&fd);
        if (hFind != INVALID_HANDLE_VALUE)
        {
            bRet=true;
            do
            {
                if (SYSLIB::IsDotsNameW(fd.cFileName))
                    continue;

                StrFormatW(stPath,dcrW_4f072b6d("%s\\%s"),lpDir,fd.cFileName);

                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    bRet=RemoveDirectoryTreeW(stPath);
                else
                    bRet=RemoveFileW(stPath);
            }
            while (FindNextFileW(hFind,&fd));
            FindClose(hFind);
        }
        if (bRet)
            bRet=(RemoveDirectoryW(lpDir) != FALSE);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) RemoveDirectoryTreeA(LPCSTR lpDir)
{
    LPWSTR lpDirW=StrAnsiToUnicodeEx(lpDir,0,NULL);

    BOOL bRet=RemoveDirectoryTreeW(lpDirW);

    MemFree(lpDirW);
    return bRet;
}

SYSLIBFUNC(LARGE_INTEGER) GetDirectorySizeW(LPCWSTR lpDir)
{
    LARGE_INTEGER liSize={0};
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpDir,MAX_PATH))
            break;

        WCHAR szCurPath[MAX_PATH];
        if (!SYSLIB::PathCombineW(szCurPath,lpDir,L"*"))
            break;

        WIN32_FIND_DATAW fdData={0};
        HANDLE hFind=FindFirstFileW(szCurPath,&fdData);
        if (hFind == INVALID_HANDLE_VALUE)
            break;

		do
		{
            if (SYSLIB::IsDotsNameW(fdData.cFileName))
                continue;

			if (fdData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
                if (SYSLIB::PathCombineW(szCurPath,lpDir,fdData.cFileName))
                    liSize.QuadPart+=(GetDirectorySizeW(szCurPath)).QuadPart;
			}
			else
				liSize.QuadPart+=MAKEDWORDLONG(fdData.nFileSizeLow,fdData.nFileSizeHigh);
		}
		while (FindNextFileW(hFind,&fdData));

		FindClose(hFind);
    }
    while (false);

	return liSize;
}

SYSLIBFUNC(LARGE_INTEGER) GetDirectorySizeA(LPCSTR lpDir)
{
    LPWSTR lpDirW=StrAnsiToUnicodeEx(lpDir,0,NULL);

    LARGE_INTEGER liSize=GetDirectorySizeW(lpDirW);

    MemFree(lpDirW);
    return liSize;
}


