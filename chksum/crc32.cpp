#include "sys_includes.h"

#include "syslib\system.h"

namespace SYSLIB
{
    DWORD chksum_crc32_int(LPBYTE block,DWORD length)
    {
        byte *buf = block;
        DWORD crc32 = -1;
        for (DWORD i=0; i < length; i++)
        {
            unsigned int cur_byte = *(byte *)&buf[i] ^ *(byte*)&crc32;
            crc32 >>= 8;
            for (int j = 0; j < 8; j++)
            {
                bool c = ((cur_byte & 1) != 0);
                cur_byte >>= 1;
                if (c) cur_byte ^= 0xEDB88320u;
            }
            crc32 ^= cur_byte;
        }
        return ~crc32;
    }
}

SYSLIBFUNC(DWORD) chksum_crc32(LPBYTE block,DWORD length)
{
    if (!SYSLIB_SAFE::CheckParamRead(block,length))
        return 0;

    return SYSLIB::chksum_crc32_int(block,length);
}

SYSLIBFUNC(DWORD) GetFileChecksumA(LPCSTR lpFileName)
{
    if (!SYSLIB_SAFE::CheckStrParamA(lpFileName,MAX_PATH))
        return 0;

    DWORD dwChecksum=0;
    HANDLE hFile=CreateFileA(lpFileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,NULL,NULL,NULL);
        if (hMapping)
        {
            byte *lpMap=(byte*)MapViewOfFile(hMapping,FILE_MAP_READ,NULL,NULL,NULL);
            if (lpMap)
            {
                dwChecksum=chksum_crc32(lpMap,GetFileSize(hFile,NULL));
                UnmapViewOfFile(lpMap);
            }
            SysCloseHandle(hMapping);
        }
        SysCloseHandle(hFile);
    }
    return dwChecksum;
}

SYSLIBFUNC(DWORD) GetFileChecksumW(LPCWSTR lpFileName)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFileName,MAX_PATH))
        return 0;

    DWORD dwChecksum=0;
    HANDLE hFile=CreateFileW(lpFileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,NULL,NULL,NULL);
        if (hMapping)
        {
            byte *lpMap=(byte*)MapViewOfFile(hMapping,FILE_MAP_READ,NULL,NULL,NULL);
            if (lpMap)
            {
                dwChecksum=chksum_crc32(lpMap,GetFileSize(hFile,NULL));
                UnmapViewOfFile(lpMap);
            }
            SysCloseHandle(hMapping);
        }
        SysCloseHandle(hFile);
    }
    return dwChecksum;
}

