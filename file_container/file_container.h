#ifndef FILE_CONTAINER_H_INCLUDED
#define FILE_CONTAINER_H_INCLUDED

#pragma warning(disable:4200)

#define FILE_CONT_FILE_HDR_MAGIC 0xBADC0DE

#define FILE_FLAG_COMPRESSED 1
#define FILE_FLAG_ENCRYPTED 2

typedef struct _FILE_CONT_FILE_HDR
{
    DWORD dwFileHdrMagic;

    DWORD dwFileTime;
    DWORD dwRealFileSize;
    DWORD dwCompressedFileSize;
    DWORD dwFileCheckSum;
    DWORD dwFileNameSize;
    DWORD dwFlags;
    union
    {
        char szFileName[0];
        byte bFileBody[0];
    };
} FILE_CONT_FILE_INFO, *PFILE_CONT_FILE_INFO;


typedef struct _FILE_CONT_FILES_LIST
{
    PFILE_CONT_FILE_INFO lpFile;

    _FILE_CONT_FILES_LIST *lpNext;
} FILE_CONT_FILES_LIST, *PFILE_CONT_FILES_LIST;

#define FILE_CONT_HANDLE_MAGIC 0x100500

typedef struct _FILE_CONT_HANDLE
{
    DWORD dwHandleMagic;

    HANDLE hContFile;

    bool bInMem;
    bool bReadOnly;
    LPSTR lpPassword;
    DWORD dwPasswordLen;

    CRITICAL_SECTION csContainer;

    PFILE_CONT_FILES_LIST lpFiles;
} FILE_CONT_HANDLE, *PFILE_CONT_HANDLE;

typedef struct _CFF_STRUCT
{
    PFILE_CONT_HANDLE lpContainer;
    DWORD dwFilesCount;
    DWORD dwPathOffset;
    DWORD dwFlags;
    bool bCompress;
    bool bDelete;

    LPCSTR lpPassword;
    DWORD dwPasswordLen;
} CFF_STRUCT, *PCFF_STRUCT;

#endif // FILE_CONTAINER_H_INCLUDED
