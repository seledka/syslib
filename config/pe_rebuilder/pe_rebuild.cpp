#include "sys_includes.h"
#include <shlwapi.h>
#include <imagehlp.h>

#include "system\system.h"

#include "syslib\ldr.h"
#include "syslib\mem.h"
#include "syslib\system.h"
#include "syslib\files.h"
#include "syslib\debug.h"
#include "syslib\str.h"

#include "pe_rebuild.h"


namespace SYSLIB
{
    DWORD ALIGN_SECTION(DWORD dwAlign,HPE_REBUILD hPE)
    {
        DWORD dwAlignOn;
        if (hPE->x86)
            dwAlignOn=hPE->NTHdrs32.OptionalHeader.SectionAlignment;
        else
            dwAlignOn=hPE->NTHdrs64.OptionalHeader.SectionAlignment;

        return RALIGN(dwAlign,dwAlignOn);
    }

    DWORD ALIGN_FILE(DWORD dwAlign,HPE_REBUILD hPE)
    {
        DWORD dwAlignOn;
        if (hPE->x86)
            dwAlignOn=hPE->NTHdrs32.OptionalHeader.FileAlignment;
        else
            dwAlignOn=hPE->NTHdrs64.OptionalHeader.FileAlignment;

        return RALIGN(dwAlign,dwAlignOn);
    }
}

// TODO (Гость#1#): ребилд всего и вся при необходимости...

static bool GetDOSHdrAndStub(HPE_REBUILD hPE,void *lpMem)
{
    bool bRet=false;
    byte *lpStart=(byte*)lpMem+sizeof(IMAGE_DOS_HEADER),
         *lpEnd=(byte*)lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew;
    DWORD dwDosStubSize=lpEnd-lpStart,
          dwAlignedSize=RALIGN(dwDosStubSize,4);
    hPE->lpDosStub=MemQuickAlloc(dwAlignedSize);
    if (hPE->lpDosStub)
    {
        memcpy(&hPE->DosHdr,lpMem,sizeof(IMAGE_DOS_HEADER));
        memcpy(hPE->lpDosStub,lpStart,dwDosStubSize);
        hPE->dwDosStubSize=dwAlignedSize;
        bRet=true;
    }
    return bRet;
}

static bool GetNTHdrsSectsAndDirs(HPE_REBUILD hPE,void *lpMem)
{
    bool bRet=true;

    PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((byte*)lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew+4);
    PIMAGE_SECTION_HEADER psh;
    PIMAGE_DATA_DIRECTORY pdd;
    if (pfh->Machine == IMAGE_FILE_MACHINE_I386)
    {
        hPE->x86=true;
        PIMAGE_NT_HEADERS32 pnth=(PIMAGE_NT_HEADERS32)((byte*)lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew),
                            rpnth=&hPE->NTHdrs32;
        memcpy(rpnth,pnth,sizeof(*pnth));

        PIMAGE_FILE_HEADER pfh=&pnth->FileHeader,
                           rpfh=&rpnth->FileHeader;
        PIMAGE_OPTIONAL_HEADER32 poh=&pnth->OptionalHeader,
                                 rpoh=&rpnth->OptionalHeader;
        psh=(PIMAGE_SECTION_HEADER)((ULONG_PTR)poh+sizeof(*poh));

        /// обнуляем поля, значения которых будут пересчитаны
        rpfh->NumberOfSections=0;
        rpoh->SizeOfImage=0;
        rpoh->CheckSum=0;
        memset(rpoh->DataDirectory,0,sizeof(rpoh->DataDirectory));

        rpoh->SizeOfHeaders=sizeof(*pnth)+sizeof(IMAGE_DOS_HEADER)+hPE->dwDosStubSize-sizeof(IMAGE_DATA_DIRECTORY)*(IMAGE_NUMBEROF_DIRECTORY_ENTRIES-rpoh->NumberOfRvaAndSizes);
        pdd=poh->DataDirectory;
    }
    else
    {
        PIMAGE_NT_HEADERS64 pnth=(PIMAGE_NT_HEADERS64)((byte*)lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew),
                            rpnth=&hPE->NTHdrs64;
        memcpy(rpnth,pnth,sizeof(*pnth));

        PIMAGE_FILE_HEADER pfh=&pnth->FileHeader,
                           rpfh=&rpnth->FileHeader;
        PIMAGE_OPTIONAL_HEADER64 poh=&pnth->OptionalHeader,
                                 rpoh=&rpnth->OptionalHeader;
        psh=(PIMAGE_SECTION_HEADER)((ULONG_PTR)poh+sizeof(*poh));

        /// обнуляем поля, значения которых будут пересчитаны
        rpfh->NumberOfSections=0;
        rpoh->SizeOfImage=0;
        rpoh->CheckSum=0;
        memset(rpoh->DataDirectory,0,sizeof(rpoh->DataDirectory));

        rpoh->SizeOfHeaders=sizeof(*pnth)+sizeof(IMAGE_DOS_HEADER)+hPE->dwDosStubSize-sizeof(IMAGE_DATA_DIRECTORY)*(IMAGE_NUMBEROF_DIRECTORY_ENTRIES-rpoh->NumberOfRvaAndSizes);
        pdd=poh->DataDirectory;
    }

    DWORD dwNumOfSect=pfh->NumberOfSections;
    /// добавляем информацию о секциях
    for (WORD i=0; i < dwNumOfSect; i++)
    {
        if (!SYSLIB::PE_AddSection(hPE,(char*)psh[i].Name,psh[i].Characteristics,psh[i].VirtualAddress,psh[i].Misc.VirtualSize))
        {
            bRet=false;
            break;
        }
        if (!SYSLIB::PE_SetSectionData(hPE,(char*)psh[i].Name,(byte*)lpMem+psh[i].PointerToRawData,psh[i].SizeOfRawData))
        {
            bRet=false;
            break;
        }
    }

    if (bRet)
    {
        /// добавляем информацию о директориях
        for (int i=0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
        {
            /// пропускаем bound import (нахуй он нам не всрался)
            if (i == IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)
                continue;

            DWORD dwRVA=pdd[i].VirtualAddress,
                  dwSize=pdd[i].Size;
            if (dwRVA)
            {
                for (WORD j=0; j < dwNumOfSect; j++)
                {
                    DWORD dwSectSize=SYSLIB::ALIGN_SECTION(psh[j].Misc.VirtualSize,hPE);
                    if ((dwRVA >= psh[j].VirtualAddress) &&
                        (dwRVA < psh[j].VirtualAddress+dwSectSize))
                    {
                        hPE->iddDirs[i].hdr.VirtualAddress=dwRVA-psh[j].VirtualAddress;
                        hPE->iddDirs[i].lpSection=SYSLIB::FindSectionByIndex(hPE,j);
                        break;
                    }
                }
                hPE->iddDirs[i].hdr.Size=dwSize;
                if (!hPE->iddDirs[i].lpSection)
                {
                    /**
                        если вне секций (в хидере?) - запоминаем адрес и данные.
                        позже они нам пригодятся.
                    **/
                    hPE->iddDirs[i].hdr.VirtualAddress=dwRVA;
                    hPE->iddDirs[i].lpData=MemQuickAlloc(dwSize);
                    if (!hPE->iddDirs[i].lpData)
                    {
                        bRet=false;
                        break;
                    }
                    memcpy(hPE->iddDirs[i].lpData,(byte*)lpMem+dwRVA,dwSize);
                }
            }
        }
    }
    return bRet;
}

SYSLIBFUNC(HPE_REBUILD) PE_Parse(LPVOID lpMem,DWORD dwSize)
{
    HPE_REBUILD hPE=NULL;
    if (ldr_CheckPE((byte*)lpMem,dwSize))
    {
        hPE=(HPE_REBUILD)MemAlloc(sizeof(PE_REBUILD));
        if (hPE)
        {
            bool bDone=false;
            do
            {
                if (!GetDOSHdrAndStub(hPE,lpMem))
                    break;
                if (!GetNTHdrsSectsAndDirs(hPE,lpMem))
                    break;
                hPE->dwFileSize=dwSize;
                bDone=true;
            }
            while (false);

            if (!bDone)
            {
                PE_Close(hPE);
                hPE=NULL;
            }
        }
    }
    return hPE;
}

SYSLIBFUNC(HPE_REBUILD) PE_ParseFileW(LPCWSTR lpFile)
{
    HPE_REBUILD hPE=NULL;
    HANDLE hFile=CreateFile(lpFile,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwFileSize=GetFileSize(hFile,NULL);

        HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,NULL);
        if (hMapping)
        {
            void *lpMapping=MapViewOfFile(hMapping,FILE_MAP_READ,0,0,NULL);
            if (lpMapping)
            {
                hPE=PE_Parse(lpMapping,dwFileSize);
                UnmapViewOfFile(lpMapping);
            }
            SysCloseHandle(hMapping);
        }
        SysCloseHandle(hFile);
    }
    return hPE;
}

SYSLIBFUNC(HPE_REBUILD) PE_ParseFileA(LPCSTR lpFile)
{
    WCHAR *lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    HPE_REBUILD hPE=PE_ParseFileW(lpFileNameW);

    MemFree(lpFileNameW);
    return hPE;
}

SYSLIBFUNC(void) PE_Close(HPE_REBUILD hPE)
{
    if (hPE)
    {
        if (hPE->lpDosStub)
            MemFree(hPE->lpDosStub);

        if (hPE->lpSections)
        {
            INT_IMAGE_SECTION_HEADER *lpHdr=hPE->lpSections;
            while (lpHdr)
            {
                void *lpMem=(void*)lpHdr;
                lpHdr=lpHdr->lpNext;
                MemFree(lpMem);
            }
        }

        for (int i=0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
        {
            if (hPE->iddDirs[i].lpData)
                MemFree(hPE->iddDirs[i].lpData);
        }
    }
    return;
}

static DWORD CalcImageSize(byte *lpMem)
{
    PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)(lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew+4);
    PIMAGE_SECTION_HEADER psh;
    DWORD dwSectionAlignment;
    if (pfh->Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        PIMAGE_OPTIONAL_HEADER64 poh=(PIMAGE_OPTIONAL_HEADER64)(pfh+1);
        psh=(PIMAGE_SECTION_HEADER)((DWORD_PTR)poh+sizeof(*poh));
        dwSectionAlignment=poh->SectionAlignment;
    }
    else
    {
        PIMAGE_OPTIONAL_HEADER32 poh=(PIMAGE_OPTIONAL_HEADER32)(pfh+1);
        psh=(PIMAGE_SECTION_HEADER)((DWORD_PTR)poh+sizeof(*poh));
        dwSectionAlignment=poh->SectionAlignment;
    }

    DWORD dwNumOfSect=pfh->NumberOfSections,
          dwSize=0;
    for (WORD i=0; i < dwNumOfSect; i++)
    {
        DWORD dwCurSize=RALIGN((psh[i].VirtualAddress+psh[i].Misc.VirtualSize),dwSectionAlignment);
        dwSize=max(dwSize,dwCurSize);
    }

    if (pfh->Machine == IMAGE_FILE_MACHINE_I386)
    {
        PIMAGE_NT_HEADERS32 pnth=(PIMAGE_NT_HEADERS32)(lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew);
        pnth->OptionalHeader.SizeOfImage=dwSize;
    }
    else
    {
        PIMAGE_NT_HEADERS64 pnth=(PIMAGE_NT_HEADERS64)(lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew);
        pnth->OptionalHeader.SizeOfImage=dwSize;
    }
    return dwSize;
}

static DWORD CalcFileSize(byte *lpMem)
{
    PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)(lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew+4);
    PIMAGE_SECTION_HEADER psh;
    DWORD dwFileAlignment;
    if (pfh->Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        PIMAGE_OPTIONAL_HEADER64 poh=(PIMAGE_OPTIONAL_HEADER64)(pfh+1);
        psh=(PIMAGE_SECTION_HEADER)((DWORD_PTR)poh+sizeof(*poh));
        dwFileAlignment=poh->FileAlignment;
    }
    else
    {
        PIMAGE_OPTIONAL_HEADER32 poh=(PIMAGE_OPTIONAL_HEADER32)(pfh+1);
        psh=(PIMAGE_SECTION_HEADER)((DWORD_PTR)poh+sizeof(*poh));
        dwFileAlignment=poh->FileAlignment;
    }

    DWORD dwNumOfSect=pfh->NumberOfSections,
          dwSize=0;
    for (WORD i=0; i < dwNumOfSect; i++)
    {
        DWORD dwCurSize=RALIGN((psh[i].PointerToRawData+psh[i].SizeOfRawData),dwFileAlignment);
        dwSize=max(dwSize,dwCurSize);
    }
    return dwSize;
}

static DWORD CopyPEInternalData(HPE_REBUILD hPE,byte *lpMem)
{
    byte *lpPtr=lpMem;

    /// копируем IMAGE_DOS_HEADER
    memcpy(lpPtr,&hPE->DosHdr,sizeof(hPE->DosHdr));
    lpPtr+=sizeof(hPE->DosHdr);

    /// копируем DOS-стаб
    memcpy(lpPtr,hPE->lpDosStub,hPE->dwDosStubSize);
    lpPtr+=hPE->dwDosStubSize;

    DWORD dwSizeOfHeaders;

    /// копируем IMAGE_NT_HEADERS
    if (hPE->x86)
    {
        memcpy(lpPtr,&hPE->NTHdrs32,sizeof(hPE->NTHdrs32));
        lpPtr+=sizeof(hPE->NTHdrs32);

        PIMAGE_NT_HEADERS32 pnth=(PIMAGE_NT_HEADERS32)(lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew);
        dwSizeOfHeaders=pnth->OptionalHeader.SizeOfHeaders=SYSLIB::ALIGN_FILE(pnth->OptionalHeader.SizeOfHeaders,hPE);
    }
    else
    {
        memcpy(lpPtr,&hPE->NTHdrs64,sizeof(hPE->NTHdrs64));
        lpPtr+=sizeof(hPE->NTHdrs64);

        PIMAGE_NT_HEADERS64 pnth=(PIMAGE_NT_HEADERS64)(lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew);
        dwSizeOfHeaders=pnth->OptionalHeader.SizeOfHeaders=SYSLIB::ALIGN_FILE(pnth->OptionalHeader.SizeOfHeaders,hPE);
    }

    INT_IMAGE_SECTION_HEADER *lpSection=hPE->lpSections;

    /**
        размер хидеров не может вылазить за RVA первой секции,
        иначе придется двигать image base
    **/
    if (dwSizeOfHeaders > lpSection->hdr.VirtualAddress)
        return 0;

    PIMAGE_SECTION_HEADER lpSectPtr=(PIMAGE_SECTION_HEADER)lpPtr;
    lpPtr=lpMem+dwSizeOfHeaders;

    DWORD dwVirtualAddress=lpSection->hdr.VirtualAddress,
          dwRawAddress=dwSizeOfHeaders;
    /// копируем секции
    while (lpSection)
    {
        memcpy(lpSectPtr,&lpSection->hdr,sizeof(lpSection->hdr));
        lpSectPtr->VirtualAddress=dwVirtualAddress;
        lpSectPtr->SizeOfRawData=lpSection->dwSize;

        if (!lpSectPtr->Misc.VirtualSize)
            lpSectPtr->Misc.VirtualSize=SYSLIB::ALIGN_SECTION(lpSection->dwSize,hPE);

        dwVirtualAddress+=SYSLIB::ALIGN_SECTION(lpSectPtr->Misc.VirtualSize,hPE);

        lpSectPtr->PointerToRawData=dwRawAddress;

        DWORD dwNewOffset=lpSection->dwSize;
        if (lpSection->lpNext)
        {
            dwNewOffset=SYSLIB::ALIGN_FILE(dwNewOffset,hPE);
            dwRawAddress+=dwNewOffset;
        }

        memcpy(lpPtr,lpSection->lpData,lpSection->dwSize);
        lpPtr+=dwNewOffset;

        lpSectPtr++;
        lpSection=lpSection->lpNext;
    }

    CalcImageSize(lpMem);
    return CalcFileSize(lpMem);
}

static void CalcCheckSum(byte *lpMem)
{
    DWORD *lpDwordMem=(DWORD*)lpMem,
          dwCheckSumPos;
    PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((byte*)lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew+4);
    if (pfh->Machine == IMAGE_FILE_MACHINE_I386)
    {
        PIMAGE_NT_HEADERS32 pnth=(PIMAGE_NT_HEADERS32)(lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew);
        dwCheckSumPos=(DWORD_PTR)&pnth->OptionalHeader.CheckSum-(DWORD_PTR)lpMem;
    }
    else
    {
        PIMAGE_NT_HEADERS64 pnth=(PIMAGE_NT_HEADERS64)(lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew);
        dwCheckSumPos=(DWORD_PTR)&pnth->OptionalHeader.CheckSum-(DWORD_PTR)lpMem;
    }

    unsigned long long dwCheckSum=0,
                       dwTop=0xFFFFFFFF+1;

    DWORD dwFileSize=CalcFileSize(lpMem);
    for (DWORD i=0; i < dwFileSize; i+=4,lpDwordMem++)
    {
        if (i == dwCheckSumPos)
            continue;

        DWORD dwCur=*lpDwordMem;
        dwCheckSum=(dwCheckSum & 0xFFFFFFFF)+dwCur+(dwCheckSum >> 32);
        if (dwCheckSum > dwTop)
            dwCheckSum=(dwCheckSum & 0xFFFFFFFF)+(dwCheckSum >> 32);
    }

    dwCheckSum=(dwCheckSum & 0xFFFF)+(dwCheckSum >> 16);
    dwCheckSum+=dwCheckSum >> 16;
    dwCheckSum=dwCheckSum & 0xFFFF;
    dwCheckSum+=dwFileSize;

    if (pfh->Machine == IMAGE_FILE_MACHINE_I386)
    {
        PIMAGE_NT_HEADERS32 pnth=(PIMAGE_NT_HEADERS32)(lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew);
        pnth->OptionalHeader.CheckSum=dwCheckSum;
    }
    else
    {
        PIMAGE_NT_HEADERS64 pnth=(PIMAGE_NT_HEADERS64)(lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew);
        pnth->OptionalHeader.CheckSum=dwCheckSum;
    }
    return;
}

static bool RebuildDataDirectories(HPE_REBUILD hPE,byte *lpMem)
{
    bool bRet=true;

    PIMAGE_DATA_DIRECTORY pdd;
    PIMAGE_SECTION_HEADER psh;

    if (hPE->x86)
    {
        PIMAGE_NT_HEADERS32 pnth=(PIMAGE_NT_HEADERS32)(lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew);
        PIMAGE_FILE_HEADER pfh=&pnth->FileHeader;
        PIMAGE_OPTIONAL_HEADER32 poh=&pnth->OptionalHeader;
        psh=(PIMAGE_SECTION_HEADER)((ULONG_PTR)poh+sizeof(*poh));
        pdd=poh->DataDirectory;
    }
    else
    {
        PIMAGE_NT_HEADERS64 pnth=(PIMAGE_NT_HEADERS64)(lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew);
        PIMAGE_FILE_HEADER pfh=&pnth->FileHeader;
        PIMAGE_OPTIONAL_HEADER64 poh=&pnth->OptionalHeader;
        psh=(PIMAGE_SECTION_HEADER)((ULONG_PTR)poh+sizeof(*poh));
        pdd=poh->DataDirectory;
    }

    for (int i=0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
    {
        DWORD dwSize=hPE->iddDirs[i].hdr.Size,
              dwOffset=hPE->iddDirs[i].hdr.VirtualAddress;
        if ((dwSize) && (hPE->iddDirs[i].lpSection))
        {
            DWORD dwIndex=hPE->iddDirs[i].lpSection->dwIndex;

            pdd[i].Size=dwSize;
            pdd[i].VirtualAddress=dwOffset+psh[dwIndex].VirtualAddress;
        }
    }
    CalcCheckSum(lpMem);
    return bRet;
}

SYSLIBFUNC(BOOL) PE_BuildW(HPE_REBUILD hPE,LPCWSTR lpFile)
{
    bool bRet=false;
    if (hPE)
    {
        TCHAR *lpTmpFile=GetTmpFileName(NULL,NULL);
        HANDLE hFile=CreateFile(lpTmpFile,GENERIC_READ|GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            SetFilePointer(hFile,hPE->dwFileSize*2,0,FILE_BEGIN);
            SetEndOfFile(hFile);

            DWORD dwRealFileSize=0;
            HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READWRITE,0,0,NULL);
            if (hMapping)
            {
                void *lpMapping=MapViewOfFile(hMapping,FILE_MAP_WRITE|FILE_MAP_READ,0,0,NULL);
                if (lpMapping)
                {
                    do
                    {
                        dwRealFileSize=CopyPEInternalData(hPE,(byte*)lpMapping);
                        if (!dwRealFileSize)
                            break;
                        if (!RebuildDataDirectories(hPE,(byte*)lpMapping))
                            break;
                        bRet=true;
                    }
                    while (false);
                    UnmapViewOfFile(lpMapping);
                }
                SysCloseHandle(hMapping);
            }

            if (bRet)
            {
                SetFilePointer(hFile,dwRealFileSize,0,FILE_BEGIN);
                SetEndOfFile(hFile);
                FlushFileBuffers(hFile);
            }
            SysCloseHandle(hFile);
        }

        if (!bRet)
            RemoveFile(lpTmpFile);
        else
        {
            CopyFileAndFlushBuffers(lpTmpFile,lpFile,false);
            RemoveFile(lpTmpFile);
            MemFree(lpTmpFile);
        }
    }
    return bRet;
}

SYSLIBFUNC(BOOL) PE_BuildA(HPE_REBUILD hPE,LPCSTR lpFile)
{
    WCHAR *lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=PE_BuildW(hPE,lpFileNameW);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(BOOL) PE_ValidateFileW(LPCWSTR lpFile)
{
    BOOL bRet=false;
    HPE_REBUILD hPE=PE_ParseFileW(lpFile);
    if (hPE)
    {
        bRet=PE_BuildW(hPE,lpFile);
        PE_Close(hPE);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) PE_ValidateFileA(LPCSTR lpFile)
{
    WCHAR *lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=PE_ValidateFileW(lpFileNameW);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(LPBYTE) PE_Dump(HINSTANCE hModule,LPDWORD lpdwSize)
{
    LPBYTE lpDump=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckParamWrite(lpdwSize,sizeof(*lpdwSize)))
            break;

        if (!ldr_CheckPE((LPBYTE)hModule,*lpdwSize))
            break;

        PIMAGE_DOS_HEADER lpDosHdr=(PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS lpHdrs=(PIMAGE_NT_HEADERS)((LPBYTE)hModule+lpDosHdr->e_lfanew);
        PIMAGE_NT_HEADERS32 lpNtHdrs32=NULL;
        PIMAGE_NT_HEADERS64 lpNtHdrs64=NULL;

        PIMAGE_SECTION_HEADER lpSections;
        DWORD dwSectionAligment,dwDumpSize;

        switch (lpHdrs->FileHeader.Machine)
        {
            case IMAGE_FILE_MACHINE_I386:
            {
                lpNtHdrs32=(PIMAGE_NT_HEADERS32)lpHdrs;
                lpSections=(PIMAGE_SECTION_HEADER)((LPBYTE)&lpNtHdrs32->OptionalHeader+lpNtHdrs32->FileHeader.SizeOfOptionalHeader);
                dwSectionAligment=lpNtHdrs32->OptionalHeader.SectionAlignment;
                dwDumpSize=lpNtHdrs32->OptionalHeader.SizeOfImage;
                break;
            }
            case IMAGE_FILE_MACHINE_AMD64:
            {
                lpNtHdrs64=(PIMAGE_NT_HEADERS64)lpHdrs;
                lpSections=(PIMAGE_SECTION_HEADER)((LPBYTE)&lpNtHdrs64->OptionalHeader+lpNtHdrs64->FileHeader.SizeOfOptionalHeader);
                dwSectionAligment=lpNtHdrs64->OptionalHeader.SectionAlignment;
                dwDumpSize=lpNtHdrs64->OptionalHeader.SizeOfImage;
                break;
            }
        }

        if (dwDumpSize & dwSectionAligment)
            dwDumpSize=dwDumpSize+dwSectionAligment-(dwDumpSize & dwSectionAligment);

        if (!dwDumpSize)
            break;

        lpDump=(LPBYTE)VirtualAlloc(NULL,dwDumpSize,MEM_COMMIT,PAGE_READWRITE);
        if (!lpDump)
            break;

        DWORD dwHdrsSize=(DWORD_PTR)lpSections-(DWORD_PTR)lpDosHdr+sizeof(IMAGE_SECTION_HEADER)*lpHdrs->FileHeader.NumberOfSections;
        memcpy(lpDump,lpDosHdr,dwHdrsSize);

        for (WORD i=0; i < lpHdrs->FileHeader.NumberOfSections; i++)
        {
            LPBYTE pOut=lpDump+lpSections[i].PointerToRawData,
                   pIn=(LPBYTE)hModule+lpSections[i].VirtualAddress;
            memcpy(pOut,pIn,lpSections[i].SizeOfRawData);
        }

        *lpdwSize=dwDumpSize;
    }
    while (false);
    return lpDump;
}

