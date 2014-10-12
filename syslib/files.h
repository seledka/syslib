#ifndef SYSLIB_FILES_H_INCLUDED
#define SYSLIB_FILES_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(BOOL) CopyFileAndFlushBuffersW(LPCWSTR lpExistingFileName,LPCWSTR lpNewFileName,BOOL bFailIfExists);
SYSLIBEXP(BOOL) CopyFileAndFlushBuffersA(LPCSTR lpExistingFileName,LPCSTR lpNewFileName,BOOL bFailIfExists);

#ifdef UNICODE
#define CopyFileAndFlushBuffers CopyFileAndFlushBuffersW
#else
#define CopyFileAndFlushBuffers CopyFileAndFlushBuffersA
#endif


SYSLIBEXP(LPWSTR) GetTmpFileNameW(LPCWSTR lpPrefix,LPCWSTR lpExt);
SYSLIBEXP(LPSTR) GetTmpFileNameA(LPCSTR lpPrefix,LPCSTR lpExt);

#ifdef UNICODE
#define GetTmpFileName GetTmpFileNameW
#else
#define GetTmpFileName GetTmpFileNameA
#endif


SYSLIBEXP(BOOL) RemoveFileW(LPCWSTR lpFile);
SYSLIBEXP(BOOL) RemoveFileA(LPCSTR lpFile);

#ifdef UNICODE
#define RemoveFile RemoveFileW
#else
#define RemoveFile RemoveFileA
#endif


SYSLIBEXP(BOOL) WipeFileW(LPCWSTR lpFile);
SYSLIBEXP(BOOL) WipeFileA(LPCSTR lpFile);

#ifdef UNICODE
#define WipeFile WipeFileW
#else
#define WipeFile WipeFileA
#endif


SYSLIBEXP(BOOL) WipeFilePartialW(LPCWSTR lpFile);
SYSLIBEXP(BOOL) WipeFilePartialA(LPCSTR lpFile);

#ifdef UNICODE
#define WipeFilePartial WipeFilePartialW
#else
#define WipeFilePartial WipeFilePartialA
#endif


SYSLIBEXP(BOOL) IsFileExistsW(LPCWSTR lpFile);
SYSLIBEXP(BOOL) IsFileExistsA(LPCSTR lpFile);

#ifdef UNICODE
#define IsFileExists IsFileExistsW
#else
#define IsFileExists IsFileExistsA
#endif


#define FFF_RECURSIVE 1
#define FFF_SEARCH_FOLDERS 2
#define FFF_SEARCH_FILES 4

typedef struct
{
    BOOL bFirstFileInDir;
    WIN32_FIND_DATAW wfd;
} FILE_INFOW, *PFILE_INFOW;

typedef BOOL (__cdecl FINDFILEPROCW)(LPCWSTR lpPath,PFILE_INFOW lpFileInfo,LPVOID lpData);
SYSLIBEXP(void) FindFilesW(LPCWSTR lpPath,LPCWSTR *lppFileMasks,DWORD dwFileMasksCount,DWORD dwFlags,FINDFILEPROCW *lpFindFileProc,LPVOID lpData,DWORD dwSubfolderDelay,DWORD dwFoundedDelay);

typedef struct
{
    BOOL bFirstFileInDir;
    WIN32_FIND_DATAA wfd;
} FILE_INFOA, *PFILE_INFOA;

typedef BOOL (__cdecl FINDFILEPROCA)(LPCSTR lpPath,PFILE_INFOA lpFileInfo,LPVOID lpData);
SYSLIBEXP(void) FindFilesA(LPCSTR lpPath,LPCSTR *lppFileMasks,DWORD dwFileMasksCount,DWORD dwFlags,FINDFILEPROCA *lpFindFileProc,LPVOID lpData,DWORD dwSubfolderDelay,DWORD dwFoundedDelay);

#ifdef UNICODE
#define FILE_INFO FILE_INFOW
#define PFILE_INFO PFILE_INFOW
#define FINDFILEPROC FINDFILEPROCW
#define FindFiles FindFilesW
#else
#define FILE_INFO FILE_INFOA
#define PFILE_INFO PFILE_INFOA
#define FINDFILEPROC FINDFILEPROCA
#define FindFiles FindFilesA
#endif

SYSLIBEXP(BOOL) CopyDirectoryW(LPCWSTR lpExistingDir,LPCWSTR lpNewDir);
SYSLIBEXP(BOOL) CopyDirectoryA(LPCSTR lpExistingDir,LPCSTR lpNewDir);

#ifdef UNICODE
#define CopyDirectory CopyDirectoryW
#else
#define CopyDirectory CopyDirectoryA
#endif


SYSLIBEXP(BOOL) CreateDirectoryTreeW(LPCWSTR lpPath);
SYSLIBEXP(BOOL) CreateDirectoryTreeA(LPCSTR lpPath);

#ifdef UNICODE
#define CreateDirectoryTree CreateDirectoryTreeW
#else
#define CreateDirectoryTree CreateDirectoryTreeA
#endif


SYSLIBEXP(BOOL) CopyFileTimeW(LPCWSTR lpFrom,LPCWSTR lpTo);
SYSLIBEXP(BOOL) CopyFileTimeA(LPCSTR lpFrom,LPCSTR lpTo);

#ifdef UNICODE
#define CopyFileTime CopyFileTimeW
#else
#define CopyFileTime CopyFileTimeA
#endif


SYSLIBEXP(BOOL) MaskAsFileW(LPCWSTR lpFrom,LPCWSTR lpTo);
SYSLIBEXP(BOOL) MaskAsFileA(LPCSTR lpFrom,LPCSTR lpTo);

#ifdef UNICODE
#define MaskAsFile MaskAsFileW
#else
#define MaskAsFile MaskAsFileA
#endif


SYSLIBEXP(void) CopyFileNameWithoutExtensionW(LPCWSTR lpFullPath,LPWSTR lpOutBuf);
SYSLIBEXP(void) CopyFileNameWithoutExtensionA(LPCSTR lpFullPath,LPSTR lpOutBuf);

#ifdef UNICODE
#define CopyFileNameWithoutExtension CopyFileNameWithoutExtensionW
#else
#define CopyFileNameWithoutExtension CopyFileNameWithoutExtensionA
#endif


SYSLIBEXP(BOOL) RemoveDirectoryTreeW(LPCWSTR lpDir);
SYSLIBEXP(BOOL) RemoveDirectoryTreeA(LPCSTR lpDir);

#ifdef UNICODE
#define RemoveDirectoryTree RemoveDirectoryTreeW
#else
#define RemoveDirectoryTree RemoveDirectoryTreeA
#endif


SYSLIBEXP(LARGE_INTEGER) GetDirectorySizeW(LPCWSTR lpDir);
SYSLIBEXP(LARGE_INTEGER) GetDirectorySizeA(LPCSTR lpDir);

#ifdef UNICODE
#define GetDirectorySize GetDirectorySizeW
#else
#define GetDirectorySize GetDirectorySizeA
#endif


SYSLIBEXP(void) RemoveFilesByMaskW(LPCWSTR lpPath,LPCWSTR lpMask);
SYSLIBEXP(void) RemoveFilesByMaskA(LPCSTR lpPath,LPCSTR lpMask);

#ifdef UNICODE
#define RemoveFilesByMask RemoveFilesByMaskW
#else
#define RemoveFilesByMask RemoveFilesByMaskA
#endif


#define B 1
#define KB B*1024
#define MB KB*1024

#endif // SYSLIB_FILES_H_INCLUDED
