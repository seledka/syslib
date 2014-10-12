#ifndef SYSLIB_FILE_CONTAINER_H_INCLUDED
#define SYSLIB_FILE_CONTAINER_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(HANDLE) FileCont_CreateW(LPCWSTR lpContainerFile,LPCSTR lpPassword,DWORD dwPasswordLen);
SYSLIBEXP(HANDLE) FileCont_CreateA(LPCSTR lpContainerFile,LPCSTR lpPassword,DWORD dwPasswordLen);

#ifdef  _UNICODE
#define FileCont_Create FileCont_CreateW
#else
#define FileCont_Create FileCont_CreateA
#endif

#ifdef __cplusplus
SYSLIBEXP(BOOL) FileCont_AddFileW(HANDLE hCont,LPCWSTR lpSourceFile,LPCWSTR lpDestFile,BOOL bCompress,LPCSTR lpPassword=NULL,DWORD dwPasswordLen=0);
SYSLIBEXP(BOOL) FileCont_AddFileA(HANDLE hCont,LPCSTR lpSourceFile,LPCSTR lpDestFile,BOOL bCompress,LPCSTR lpPassword=NULL,DWORD dwPasswordLen=0);
#else
SYSLIBEXP(BOOL) FileCont_AddFileW(HANDLE hCont,LPCWSTR lpSourceFile,LPCWSTR lpDestFile,BOOL bCompress,LPCSTR lpPassword,DWORD dwPasswordLen);
SYSLIBEXP(BOOL) FileCont_AddFileA(HANDLE hCont,LPCSTR lpSourceFile,LPCSTR lpDestFile,BOOL bCompress,LPCSTR lpPassword,DWORD dwPasswordLen);
#endif

#ifdef _UNICODE
#define FileCont_AddFile FileCont_AddFileW
#else
#define FileCont_AddFile FileCont_AddFileA
#endif


#define FILECONT_NO_CRYPT 4

#ifdef __cplusplus
SYSLIBEXP(BOOL) FileCont_AddFileExW(HANDLE hCont,LPCWSTR lpSourceFile,LPCWSTR lpDestFile,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword=NULL,DWORD dwPasswordLen=0);
SYSLIBEXP(BOOL) FileCont_AddFileExA(HANDLE hCont,LPCSTR lpSourceFile,LPCSTR lpDestFile,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword=NULL,DWORD dwPasswordLen=0);
#else
SYSLIBEXP(BOOL) FileCont_AddFileExW(HANDLE hCont,LPCWSTR lpSourceFile,LPCWSTR lpDestFile,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen);
SYSLIBEXP(BOOL) FileCont_AddFileExA(HANDLE hCont,LPCSTR lpSourceFile,LPCSTR lpDestFile,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen);
#endif

#ifdef _UNICODE
#define FileCont_AddFileEx FileCont_AddFileExW
#else
#define FileCont_AddFileEx FileCont_AddFileExA
#endif


#ifdef __cplusplus
SYSLIBEXP(BOOL) FileCont_AddFromMemoryW(HANDLE hCont,LPVOID lpMem,DWORD dwSize,LPCWSTR lpFileName,BOOL bCompress,LPCSTR lpPassword=NULL,DWORD dwPasswordLen=0);
SYSLIBEXP(BOOL) FileCont_AddFromMemoryA(HANDLE hCont,LPVOID lpMem,DWORD dwSize,LPCSTR lpFileName,BOOL bCompress,LPCSTR lpPassword=NULL,DWORD dwPasswordLen=0);
#else
SYSLIBEXP(BOOL) FileCont_AddFromMemoryW(HANDLE hCont,LPVOID lpMem,DWORD dwSize,LPCWSTR lpFileName,BOOL bCompress,LPCSTR lpPassword,DWORD dwPasswordLen);
SYSLIBEXP(BOOL) FileCont_AddFromMemoryA(HANDLE hCont,LPVOID lpMem,DWORD dwSize,LPCSTR lpFileName,BOOL bCompress,LPCSTR lpPassword,DWORD dwPasswordLen);
#endif

#ifdef _UNICODE
#define FileCont_AddFromMemory FileCont_AddFromMemoryW
#else
#define FileCont_AddFromMemory FileCont_AddFromMemoryA
#endif


#ifdef __cplusplus
SYSLIBEXP(BOOL) FileCont_AddFromMemoryExW(HANDLE hCont,LPVOID lpMem,DWORD dwSize,LPCWSTR lpFileName,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword=NULL,DWORD dwPasswordLen=0);
SYSLIBEXP(BOOL) FileCont_AddFromMemoryExA(HANDLE hCont,LPVOID lpMem,DWORD dwSize,LPCSTR lpFileName,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword=NULL,DWORD dwPasswordLen=0);
#else
SYSLIBEXP(BOOL) FileCont_AddFromMemoryExW(HANDLE hCont,LPVOID lpMem,DWORD dwSize,LPCWSTR lpFileName,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen);
SYSLIBEXP(BOOL) FileCont_AddFromMemoryExA(HANDLE hCont,LPVOID lpMem,DWORD dwSize,LPCSTR lpFileName,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen);
#endif

#ifdef _UNICODE
#define FileCont_AddFromMemoryEx FileCont_AddFromMemoryExW
#else
#define FileCont_AddFromMemoryEx FileCont_AddFromMemoryExA
#endif


#define CFF_RECURSE 1
#define CFF_DELETE 2

#ifdef __cplusplus
SYSLIBEXP(BOOL) FileCont_AddFolderW(HANDLE hCont,LPCWSTR lpSourceFolder,LPCWSTR *lppFileMask,DWORD dwFileMaskCount,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword=NULL,DWORD dwPasswordLen=0);
SYSLIBEXP(BOOL) FileCont_AddFolderA(HANDLE hCont,LPCSTR lpSourceFolder,LPCSTR *lppFileMask,DWORD dwFileMaskCount,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword=NULL,DWORD dwPasswordLen=0);
#else
SYSLIBEXP(BOOL) FileCont_AddFolderW(HANDLE hCont,LPCWSTR lpSourceFolder,LPCWSTR *lppFileMask,DWORD dwFileMaskCount,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen);
SYSLIBEXP(BOOL) FileCont_AddFolderA(HANDLE hCont,LPCSTR lpSourceFolder,LPCSTR *lppFileMask,DWORD dwFileMaskCount,BOOL bCompress,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen);
#endif

#ifdef _UNICODE
#define FileCont_CompressFolder FileCont_CompressFolderW
#else
#define FileCont_CompressFolder FileCont_CompressFolderA
#endif


SYSLIBEXP(BOOL) FileCont_CreateFromFolderW(LPCWSTR lpContainerFile,LPCWSTR lpSourceFolder,LPCWSTR *lppFileMask,DWORD dwFileMaskCount,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen,BOOL bCompress);
SYSLIBEXP(BOOL) FileCont_CreateFromFolderA(LPCSTR lpContainerFile,LPCSTR lpSourceFolder,LPCSTR *lppFileMask,DWORD dwFileMaskCount,DWORD dwFlags,LPCSTR lpPassword,DWORD dwPasswordLen,BOOL bCompress);

#ifdef _UNICODE
#define FileCont_CreateFromFolder FileCont_CreateFromFolderW
#else
#define FileCont_CreateFromFolder FileCont_CreateFromFolderA
#endif


typedef struct _FILE_IN_CONT_INFO
{
    DWORD dwChecksum;
    DWORD dwDosDate;
    ULONGLONG dwCompressedSize;
    ULONGLONG dwDecompressedSize;
} FILE_IN_CONT_INFO, *PFILE_IN_CONT_INFO;

typedef BOOL WINAPI CONTENUMNAMESCALLBACKW(LPCWSTR lpstrFile,const PFILE_IN_CONT_INFO lpInfo);
typedef BOOL WINAPI CONTENUMNAMESCALLBACKA(LPCSTR lpstrFile,const PFILE_IN_CONT_INFO lpInfo);

#ifdef __cplusplus
SYSLIBEXP(HANDLE) FileCont_OpenW(LPCWSTR lpContainerFile,LPCSTR lpPassword,DWORD dwPasswordLen,BOOL bReadOnly,BOOL bContInMem=false,DWORD dwFileSize=0);
SYSLIBEXP(HANDLE) FileCont_OpenA(LPCSTR lpContainerFile,LPCSTR lpPassword,DWORD dwPasswordLen,BOOL bReadOnly,BOOL bContInMem=false,DWORD dwFileSize=0);
#else
SYSLIBEXP(HANDLE) FileCont_OpenW(LPCWSTR lpContainerFile,LPCSTR lpPassword,DWORD dwPasswordLen,BOOL bReadOnly,BOOL bContInMem,DWORD dwFileSize);
SYSLIBEXP(HANDLE) FileCont_OpenA(LPCSTR lpContainerFile,LPCSTR lpPassword,DWORD dwPasswordLen,BOOL bReadOnly,BOOL bContInMem,DWORD dwFileSize);
#endif

#ifdef _UNICODE
#define FileCont_Open FileCont_OpenW
#else
#define FileCont_Open FileCont_OpenA
#endif


#ifdef __cplusplus
SYSLIBEXP(BOOL) FileCont_ExtractFileW(HANDLE hCont,LPCWSTR lpPath,LPCWSTR lpFileName,LPCSTR lpPassword=NULL,DWORD dwPasswordLen=0);
SYSLIBEXP(BOOL) FileCont_ExtractFileA(HANDLE hCont,LPCSTR lpPath,LPCSTR lpFileName,LPCSTR lpPassword=NULL,DWORD dwPasswordLen=0);
#else
SYSLIBEXP(BOOL) FileCont_ExtractFileW(HANDLE hCont,LPCWSTR lpPath,LPCWSTR lpFileName,LPCSTR lpPassword,DWORD dwPasswordLen);
SYSLIBEXP(BOOL) FileCont_ExtractFileA(HANDLE hCont,LPCSTR lpPath,LPCSTR lpFileName,LPCSTR lpPassword,DWORD dwPasswordLen);
#endif

#ifdef _UNICODE
#define FileCont_ExtractFile FileCont_ExtractFileW
#else
#define FileCont_ExtractFile FileCont_ExtractFileA
#endif


SYSLIBEXP(BOOL) FileCont_ExtractFilesW(HANDLE hCont,LPCWSTR lpPath);
SYSLIBEXP(BOOL) FileCont_ExtractFilesA(HANDLE hCont,LPCSTR lpPath);

#ifdef _UNICODE
#define FileCont_ExtractFiles FileCont_ExtractFilesW
#else
#define FileCont_ExtractFiles FileCont_ExtractFilesA
#endif


#ifdef __cplusplus
SYSLIBEXP(BOOL) FileCont_GetFileW(HANDLE hCont,LPCWSTR lpFileName,LPBYTE *lppMem,LPDWORD lpdwSize,LPCSTR lpPassword=NULL,DWORD dwPasswordLen=0);
SYSLIBEXP(BOOL) FileCont_GetFileA(HANDLE hCont,LPCSTR lpFileName,LPBYTE *lppMem,LPDWORD lpdwSize,LPCSTR lpPassword=NULL,DWORD dwPasswordLen=0);
#else
SYSLIBEXP(BOOL) FileCont_GetFileW(HANDLE hCont,LPCWSTR lpFileName,LPBYTE *lppMem,LPDWORD lpdwSize,LPCSTR lpPassword,DWORD dwPasswordLen);
SYSLIBEXP(BOOL) FileCont_GetFileA(HANDLE hCont,LPCSTR lpFileName,LPBYTE *lppMem,LPDWORD lpdwSize,LPCSTR lpPassword,DWORD dwPasswordLen);
#endif

#ifdef _UNICODE
#define FileCont_GetFile FileCont_GetFileW
#else
#define FileCont_GetFile FileCont_GetFileA
#endif


SYSLIBEXP(BOOL) FileCont_EnumFilesW(HANDLE hCont,CONTENUMNAMESCALLBACKW *lpCallback);
SYSLIBEXP(BOOL) FileCont_EnumFilesA(HANDLE hCont,CONTENUMNAMESCALLBACKA *lpCallback);

#ifdef _UNICODE
#define FileCont_EnumFiles    FileCont_EnumFilesW
#define CONTENUMNAMESCALLBACK CONTENUMNAMESCALLBACKW
#else
#define FileCont_EnumFiles    FileCont_EnumFilesA
#define CONTENUMNAMESCALLBACK CONTENUMNAMESCALLBACKA
#endif


SYSLIBEXP(BOOL) FileCont_GetFileInfoW(HANDLE hCont,LPCWSTR lpFileName,PFILE_IN_CONT_INFO lpInfo);
SYSLIBEXP(BOOL) FileCont_GetFileInfoA(HANDLE hCont,LPCSTR lpFileName,PFILE_IN_CONT_INFO lpInfo);

#ifdef _UNICODE
#define FileCont_GetFileInfo FileCont_GetFileInfoW
#else
#define FileCont_GetFileInfo FileCont_GetFileInfoA
#endif


SYSLIBEXP(BOOL) FileCont_DeleteFileW(HANDLE hCont,LPCWSTR lpFileName);
SYSLIBEXP(BOOL) FileCont_DeleteFileA(HANDLE hCont,LPCSTR lpFileName);

#ifdef _UNICODE
#define FileCont_DeleteFile FileCont_DeleteFileW
#else
#define FileCont_DeleteFile FileCont_DeleteFileA
#endif

SYSLIBEXP(DWORD) FileCont_GetRealSize(HANDLE hCont);

SYSLIBEXP(void) FileCont_Close(HANDLE hCont);

#endif // SYSLIB_FILE_CONTAINER_H_INCLUDED
