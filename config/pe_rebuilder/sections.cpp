#include "sys_includes.h"
#include <shlwapi.h>

#include "pe_rebuild.h"

#include "syslib\str.h"
#include "syslib\debug.h"
#include "syslib\ldr.h"
#include "syslib\mem.h"

namespace SYSLIB
{
    void *PE_GetSectionDataFromModule(void *lpImg,char *lpSection)
    {
    #ifdef _X86_
        byte *lpMem=(byte*)((size_t)(lpMem) & 0xFFFFFF000);
    #else
        byte *lpMem=(byte*)((size_t)(lpMem) & 0xFFFFFFFFFFFFF000);
    #endif
        void *lpData=NULL;
        if (ldr_CheckPE(lpMem,ldr_GetImageSize(lpMem)))
        {
            PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)(lpMem+((PIMAGE_DOS_HEADER)lpMem)->e_lfanew+4);
            PIMAGE_SECTION_HEADER psh;
            if (pfh->Machine == IMAGE_FILE_MACHINE_I386)
            {
                PIMAGE_OPTIONAL_HEADER32 poh=(PIMAGE_OPTIONAL_HEADER32)(pfh+1);
                psh=(PIMAGE_SECTION_HEADER)((ULONG_PTR)poh+sizeof(*poh));
            }
            else
            {
                PIMAGE_OPTIONAL_HEADER64 poh=(PIMAGE_OPTIONAL_HEADER64)(pfh+1);
                psh=(PIMAGE_SECTION_HEADER)((ULONG_PTR)poh+sizeof(*poh));
            }

            DWORD dwNumOfSect=pfh->NumberOfSections;
            for (DWORD i=0; i<dwNumOfSect; i++)
            {
                if (!StrCmpNIA((char*)psh[i].Name,lpSection,8))
                {
                    lpData=(void*)((LONG_PTR)psh[i].PointerToRawData+lpMem);
                    break;
                }
            }
        }
        return lpData;
    }

    INT_IMAGE_SECTION_HEADER *FindSectionByIndex(HPE_REBUILD hPE,int dwSection)
    {
        INT_IMAGE_SECTION_HEADER *lpHdr=hPE->lpSections;
        while (lpHdr)
        {
            if (lpHdr->dwIndex == dwSection)
                break;
            lpHdr=lpHdr->lpNext;
        }
        return lpHdr;
    }

    static INT_IMAGE_SECTION_HEADER *FindFirstSectionByName(HPE_REBUILD hPE,char *lpName)
    {
        INT_IMAGE_SECTION_HEADER *lpHdr=hPE->lpSections;
        while (lpHdr)
        {
            if (!StrCmpNIA((char*)lpHdr->hdr.Name,lpName,8))
                break;
            lpHdr=lpHdr->lpNext;
        }
        return lpHdr;
    }

    void *PE_GetSectionData(HPE_REBUILD hPE,int dwSection)
    {
        void *lpData=NULL;
        INT_IMAGE_SECTION_HEADER *lpHdr=FindSectionByIndex(hPE,dwSection);
        if (lpHdr)
            lpData=lpHdr->lpData;
        return lpData;
    }

    void *PE_GetSectionData(HPE_REBUILD hPE,char *lpSection)
    {
        void *lpData=NULL;
        INT_IMAGE_SECTION_HEADER *lpHdr=FindFirstSectionByName(hPE,lpSection);
        if (lpHdr)
            lpData=lpHdr->lpData;
        return lpData;
    }

    /**
        признаком наличия секции в исходном варианте пересобираемого модуля
        служит поле VirtualSize. если это не последняя секция с этим признаком
        то выйти за пределы ее VirtualSize нельзя, т.к. придется смещать
        остальные секции что не возможно без наличия релоков, которые есть
        не везде
    **/
    static bool IsDataCanBePlaced(INT_IMAGE_SECTION_HEADER *lpHdr,DWORD dwNewSize)
    {
        bool bRet=false;
        /**
            если это последняя секция или мы добавили ее сами -
            значит все хорошо
        **/
        if ((!lpHdr->lpNext) || (!lpHdr->hdr.Misc.VirtualSize))
            bRet=true;
        else
        {
            /**
                если следующая запись добавлена нами -
                значит опять же все хорошо
            **/
            if (!lpHdr->lpNext->hdr.Misc.VirtualSize)
                bRet=true;

            /**
                если новая порция данных не выходит за границы -
                просто превосходно! чего мы только переживали зря...
            **/
            if (lpHdr->hdr.Misc.VirtualSize >= dwNewSize)
                bRet=true;
        }
        return bRet;
    }

    BOOL PE_SetSectionDataInt(HPE_REBUILD hPE,INT_IMAGE_SECTION_HEADER *lpHdr,void *lpData,DWORD cbData)
    {
        if (!IsDataCanBePlaced(lpHdr,SYSLIB::ALIGN_SECTION(cbData,hPE)))
            return false;

        BOOL bRet=false;
        void *lpPrevData=lpHdr->lpData;
        DWORD dwPrevSize=SYSLIB::ALIGN_FILE(lpHdr->dwSize,hPE);

        if (!cbData)
        {
            MemFree(lpHdr->lpData);
            lpHdr->lpData=NULL;
            lpHdr->dwSize=0;
            bRet=true;
        }
        else
        {
            if (lpData)
            {
                void *lpNewData=MemQuickAlloc(cbData);
                if (lpNewData)
                {
                    memcpy(lpNewData,lpData,cbData);
                    char *lpSectEnd=(char*)lpNewData+cbData-1;
                    DWORD dwTmpSize=cbData-1;
                    while (*lpSectEnd == 0)
                    {
                        dwTmpSize--;
                        lpSectEnd--;
                    }
                    dwTmpSize+=MIN_SECTION_TERM;

                    if (dwTmpSize < cbData)
                        cbData=dwTmpSize;

                    lpHdr->dwSize=cbData;
                    lpHdr->lpData=lpNewData;
                    bRet=true;
                }
            }
        }
        if (bRet)
        {
            if (lpPrevData)
                MemFree(lpPrevData);
            hPE->dwFileSize-=dwPrevSize;
            hPE->dwFileSize+=SYSLIB::ALIGN_FILE(cbData,hPE);
        }
        return bRet;
    }

    BOOL PE_SetSectionData(HPE_REBUILD hPE,int dwSection,void *lpData,DWORD cbData)
    {
        BOOL bRet=false;
        INT_IMAGE_SECTION_HEADER *lpHdr=FindSectionByIndex(hPE,dwSection);
        if (lpHdr)
            bRet=PE_SetSectionDataInt(hPE,lpHdr,lpData,cbData);
        return bRet;
    }

    BOOL PE_SetSectionData(HPE_REBUILD hPE,char *lpSection,void *lpData,DWORD cbData)
    {
        BOOL bRet=false;
        INT_IMAGE_SECTION_HEADER *lpHdr=FindFirstSectionByName(hPE,lpSection);
        if (lpHdr)
            bRet=PE_SetSectionDataInt(hPE,lpHdr,lpData,cbData);
        return bRet;
    }

    BOOL PE_RemoveSectionInt(HPE_REBUILD hPE,INT_IMAGE_SECTION_HEADER *lpHdr)
    {
        BOOL bRet=false;
        INT_IMAGE_SECTION_HEADER *lpCurHdr=hPE->lpSections,*lpPrev=NULL;
        while (lpCurHdr)
        {
            if (lpCurHdr == lpHdr)
            {
                if (hPE->x86)
                {
                    hPE->NTHdrs32.OptionalHeader.SizeOfHeaders-=sizeof(IMAGE_SECTION_HEADER);
                    hPE->NTHdrs32.FileHeader.NumberOfSections--;
                }
                else
                {
                    hPE->NTHdrs64.OptionalHeader.SizeOfHeaders-=sizeof(IMAGE_SECTION_HEADER);
                    hPE->NTHdrs64.FileHeader.NumberOfSections--;
                }

                for (int i=0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
                {
                    if (hPE->iddDirs[i].lpSection == lpHdr)
                    {
                        if (hPE->iddDirs[i].lpData)
                            MemFree(hPE->iddDirs[i].lpData);
                        memset(&hPE->iddDirs[i],0,sizeof(IMAGE_DATA_DIRECTORY));
                    }
                }

                if (lpPrev)
                    lpPrev->lpNext=lpHdr->lpNext;
                else
                    hPE->lpSections=lpHdr->lpNext;

                lpHdr=lpHdr->lpNext;
                while (lpHdr)
                {
                    lpHdr->dwIndex--;
                    lpHdr=lpHdr->lpNext;
                }
                bRet=true;
                break;
            }
            lpPrev=lpCurHdr;
            lpCurHdr=lpCurHdr->lpNext;
        }
        return bRet;
    }

    BOOL PE_RemoveSection(HPE_REBUILD hPE,int dwSection)
    {
        BOOL bRet=false;
        INT_IMAGE_SECTION_HEADER *lpHdr=FindSectionByIndex(hPE,dwSection);
        if (lpHdr)
            bRet=PE_RemoveSectionInt(hPE,lpHdr);
        return bRet;
    }

    BOOL PE_RemoveSection(HPE_REBUILD hPE,char *lpSection)
    {
        BOOL bRet=false;
        INT_IMAGE_SECTION_HEADER *lpHdr=FindFirstSectionByName(hPE,lpSection);
        if (lpHdr)
            bRet=PE_RemoveSectionInt(hPE,lpHdr);
        return bRet;
    }

    INT_IMAGE_SECTION_HEADER *PE_AddSection(HPE_REBUILD hPE,char *lpSection,DWORD dwCharacteristics,DWORD dwVA,DWORD dwVirtSize)
    {
        INT_IMAGE_SECTION_HEADER *lpNewSection=(INT_IMAGE_SECTION_HEADER*)MemAlloc(sizeof(INT_IMAGE_SECTION_HEADER));
        if (lpNewSection)
        {
            INT_IMAGE_SECTION_HEADER *lpPrev=NULL;
            StrCpyNA((char*)lpNewSection->hdr.Name,lpSection,8);
            lpNewSection->hdr.Characteristics=dwCharacteristics;
            if (dwVirtSize)
                lpNewSection->hdr.Misc.VirtualSize=dwVirtSize,hPE;

            if (hPE->lpSections)
            {
                INT_IMAGE_SECTION_HEADER *lpSections=hPE->lpSections;
                while (lpSections->lpNext)
                    lpSections=lpSections->lpNext;
                lpPrev=lpSections;
                lpSections->lpNext=lpNewSection;
            }
            else
                hPE->lpSections=lpNewSection;

            if (!dwVA)
            {
                if (lpPrev)
                    lpNewSection->hdr.VirtualAddress=lpPrev->hdr.VirtualAddress+SYSLIB::ALIGN_SECTION(lpPrev->dwSize,hPE);
            }
            else
                lpNewSection->hdr.VirtualAddress=dwVA;

            if (lpPrev)
                lpNewSection->dwIndex=lpPrev->dwIndex+1;

            if (hPE->x86)
            {
                hPE->NTHdrs32.FileHeader.NumberOfSections++;
                hPE->NTHdrs32.OptionalHeader.SizeOfHeaders+=sizeof(IMAGE_SECTION_HEADER);
            }
            else
            {
                hPE->NTHdrs64.FileHeader.NumberOfSections++;
                hPE->NTHdrs64.OptionalHeader.SizeOfHeaders+=sizeof(IMAGE_SECTION_HEADER);
            }
        }
        return lpNewSection;
    }

    WORD PE_GetSectionsCount(HPE_REBUILD hPE)
    {
        if (hPE->x86)
            return hPE->NTHdrs32.FileHeader.NumberOfSections;

        return hPE->NTHdrs64.FileHeader.NumberOfSections;
    }

    INT_IMAGE_SECTION_HEADER *PE_GetSectionByAddress(HPE_REBUILD hPE,byte *lpAddr)
    {
        INT_IMAGE_SECTION_HEADER *lpSect=NULL;

        WORD wCount=PE_GetSectionsCount(hPE);
        for (WORD i=0; i < wCount; i++)
        {
            INT_IMAGE_SECTION_HEADER *lpHdr=FindSectionByIndex(hPE,i);
            if (lpHdr)
            {
                byte *lpData=(byte*)lpHdr->lpData;
                if (lpData)
                {
                    if ((lpAddr >= lpData) && (lpAddr <= lpData+lpHdr->dwSize))
                    {
                        lpSect=lpHdr;
                        break;
                    }
                }
            }
        }
        return lpSect;
    }
}

