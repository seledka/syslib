#ifndef PE_REBUILD_H_INCLUDED
#define PE_REBUILD_H_INCLUDED

#include "syslib\syslib_exp.h"

struct INT_IMAGE_SECTION_HEADER
{
    IMAGE_SECTION_HEADER hdr;
    void *lpData;
    DWORD dwSize;
    DWORD dwIndex;
    INT_IMAGE_SECTION_HEADER *lpNext;
};

struct INT_IMAGE_DATA_DIRECTORY
{
    IMAGE_DATA_DIRECTORY hdr;
    INT_IMAGE_SECTION_HEADER *lpSection;
    void *lpData; /// на случай, если данные вне секций (в хидере)
};

typedef struct _PE_REBUILD
{
    IMAGE_DOS_HEADER DosHdr;

    void *lpDosStub;
    DWORD dwDosStubSize;

    bool x86;
    union
    {
        IMAGE_NT_HEADERS32 NTHdrs32;
        IMAGE_NT_HEADERS64 NTHdrs64;
    };

    INT_IMAGE_DATA_DIRECTORY iddDirs[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    INT_IMAGE_SECTION_HEADER *lpSections;

    DWORD dwFileSize;
} PE_REBUILD, *HPE_REBUILD;

extern_C HPE_REBUILD PE_ParseFileW(const WCHAR *lpFile);
extern_C HPE_REBUILD PE_ParseFileA(const char *lpFile);

#ifdef UNICODE
#define PE_ParseFile PE_ParseFileW
#else
#define PE_ParseFile PE_ParseFileA
#endif


extern_C HPE_REBUILD PE_Parse(void *lpMem,DWORD dwSize);

extern_C BOOL PE_BuildW(HPE_REBUILD hPE,const WCHAR *lpFile);
extern_C BOOL PE_BuildA(HPE_REBUILD hPE,const char *lpFile);

#ifdef UNICODE
#define PE_Build PE_BuildW
#else
#define PE_Build PE_BuildA
#endif

extern_C void PE_Close(HPE_REBUILD hPE);

#define RALIGN(dwToAlign, dwAlignOn) (((dwToAlign)+(dwAlignOn)-1)&(~((dwAlignOn)-1)))

namespace SYSLIB
{
    void *PE_GetSectionDataFromModule(void *lpMem,char *lpSection);

    INT_IMAGE_SECTION_HEADER *PE_AddSection(HPE_REBUILD hPE,char *lpSection,DWORD dwCharacteristics,DWORD dwVA=0,DWORD dwVirtSize=0);
    BOOL PE_SetSectionDataInt(HPE_REBUILD hPE,INT_IMAGE_SECTION_HEADER *lpHdr,void *lpData,DWORD cbData);
    BOOL PE_SetSectionData(HPE_REBUILD hPE,int dwSection,void *lpData,DWORD cbData);
    BOOL PE_SetSectionData(HPE_REBUILD hPE,char *lpSection,void *lpData,DWORD cbData);

    void *PE_GetSectionData(HPE_REBUILD hPE,int dwSection);
    void *PE_GetSectionData(HPE_REBUILD hPE,char *lpSection);

    BOOL PE_RemoveSection(HPE_REBUILD hPE,int dwSection);
    BOOL PE_RemoveSection(HPE_REBUILD hPE,char *lpSection);

    DWORD ALIGN_SECTION(DWORD dwAlign,HPE_REBUILD hPE);
    DWORD ALIGN_FILE(DWORD dwAlign,HPE_REBUILD hPE);

    INT_IMAGE_SECTION_HEADER *FindSectionByIndex(HPE_REBUILD hPE,int dwSection);

    WORD PE_GetSectionsCount(HPE_REBUILD hPE);
    INT_IMAGE_SECTION_HEADER *PE_GetSectionByAddress(HPE_REBUILD hPE,byte *lpAddr);
    BOOL PE_RemoveSectionInt(HPE_REBUILD hPE,INT_IMAGE_SECTION_HEADER *lpHdr);
};

#define MIN_SECTION_TERM 5

extern_C BOOL PE_ValidateFileW(const WCHAR *lpFile);
extern_C BOOL PE_ValidateFileA(const char *lpFile);

#ifdef UNICODE
#define PE_ValidateFile PE_ValidateFileW
#else
#define PE_ValidateFile PE_ValidateFileA
#endif


#endif // PE_REBUILD_H_INCLUDED
