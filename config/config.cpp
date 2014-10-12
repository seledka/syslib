#include "sys_includes.h"
#include <shlwapi.h>

#include "pe_rebuilder\pe_rebuild.h"

#include "syslib\ldr.h"
#include "syslib\mem.h"
#include "syslib\chksum.h"
#include "syslib\str.h"
#include "syslib\utils.h"
#include "syslib\system.h"

#include "config.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

/**
    вспомогательные функции общего назначения
**/

static byte CONF_XOR_KEY[4]={48,93,56,12};
static void XorIt(byte *lpFrom,byte *lpTo,DWORD dwSize)
{
    for (DWORD i=0, j=0; i < dwSize; i++, j++)
    {
        if (j >= ARRAYSIZE(CONF_XOR_KEY))
            j=0;
        lpTo[i]=lpFrom[i]^CONF_XOR_KEY[j];
    }
    return;
}

static void DecryptData(HCONFIG hConf,byte *lpOutBuf)
{
    if (hConf->bEncrypted)
        XorIt(hConf->bData,lpOutBuf,hConf->dwSize);
    else
        memcpy(lpOutBuf,hConf->bData,hConf->dwSize);
    return;
}

static bool IsGoodConfig(HCONFIG hConf,bool bCheckHash)
{
    bool bRet=false;
    do
    {
        if (!hConf)
            break;
        if (hConf->wMagicWord != CONFIG_MAGIC)
            break;
        if (hConf->dwStructSize != sizeof(CONFIG))
            break;
        if (bCheckHash)
        {
            if (MurmurHash3((byte*)&hConf->wMagicWord,hConf->dwStructSize+hConf->dwSize-sizeof(hConf->dwCheckSum)) != hConf->dwCheckSum)
                break;
        }
        bRet=true;
    }
    while (false);
    return bRet;
}

static DWORD GetHashByName(LPCSTR lpName)
{
    DWORD dwHash=0;
    if (!IS_INTRESOURCE(lpName))
    {
        if (lpName[0] == '#')
        {
            DWORD dwTmpKey=StrToIntA((char*)lpName+1);
            if (dwTmpKey <= 0xFFFF)
                dwHash=(WORD)dwTmpKey;
            else
                dwHash=MurmurHash3((byte*)lpName,lstrlenA((LPCSTR)lpName));
        }
        else
            dwHash=MurmurHash3((byte*)lpName,lstrlenA((LPCSTR)lpName));
    }
    else
        dwHash=(WORD)lpName;
    return dwHash;
}

static HCONFIG GetNextItem(HCONFIG hConf)
{
    HCONFIG hRet=NULL;
    if (IsGoodConfig(hConf,false))
    {
        if (!hConf->bLastItem)
            hRet=(HCONFIG)((DWORD_PTR)hConf+hConf->dwSize+hConf->dwStructSize);
    }
    return hRet;
}

static char *ConvertWtoA(LPCWSTR lpName,char *lpOut)
{
    char *ptr=lpOut;
    if (!IS_INTRESOURCE(lpName))
        StrUnicodeToAnsi(lpName,0,lpOut,0);
    else
        ptr=MAKEINTRESOURCEA(lpName);
    return ptr;
}



/**
    замена и удаление ресурсов
**/

static void EncrypData(HCONFIG hConf,byte *lpIn,DWORD dwSize)
{
    hConf->dwSize=dwSize;
    hConf->bEncrypted=true;
    XorIt(lpIn,hConf->bData,dwSize);
    return;
}

static byte *FindConfigSection(HPE_REBUILD hPE)
{
    byte *lpData=NULL;
    WORD wCount=SYSLIB::PE_GetSectionsCount(hPE);
    for (WORD i=0; i < wCount; i++)
    {
        DWORD *lpSectData=(DWORD*)SYSLIB::PE_GetSectionData(hPE,i);
        if (lpSectData)
        {
            if (*lpSectData == CONFIG_START_MARKER)
            {
                lpData=(byte*)(lpSectData+1);
                break;
            }
        }
    }
    return lpData;
}

static DWORD GetDirHashName(CONFIG_DIR_ENTRY *lpDir)
{
    DWORD dwHash=0;
    if (!lpDir->bIntName)
        dwHash=MurmurHash3((byte*)lpDir->szName,lstrlenA(lpDir->szName));
    else
        dwHash=lpDir->dwIntName;
    return dwHash;
}

static CONFIG_DIR_ENTRY *ParseInternalConfigData(HCONFIG hConf)
{
    CONFIG_DIR_ENTRY *lpDir=NULL,*lpFirstEntry=NULL,*lpPrev=NULL;
    while (hConf)
    {
        lpDir=(CONFIG_DIR_ENTRY*)MemAlloc(sizeof(CONFIG_DIR_ENTRY));
        if (!lpDir)
            break;

        if (!lpPrev)
            lpFirstEntry=lpDir;
        else
            lpPrev->lpNext=lpDir;
        lpPrev=lpDir;

        lpDir->lpData=MemQuickAlloc(hConf->dwSize);
        if (!lpDir->lpData)
        {
            // TODO (Гость#1#): сделать что-нибудь ужасное
        }
        lpDir->dwSize=hConf->dwSize;
        DecryptData(hConf,(byte*)lpDir->lpData);

        if (hConf->bIntName)
        {
            lpDir->bIntName=true;
            lpDir->dwIntName=hConf->dwIntName;
        }
        else
            StrCpyNA(lpDir->szName,hConf->szName,ARRAYSIZE(lpDir->szName));

        lpDir->dwNameHash=GetDirHashName(lpDir);
        hConf=GetNextItem(hConf);
    }

    return lpFirstEntry;
}

SYSLIBFUNC(HANDLE) BeginUpdateConfigW(LPCWSTR lpFileName,bool bDeleteExistingConfigs)
{
    HANDLE hUpdate=NULL;
    if (ldr_CheckFileW((WCHAR*)lpFileName))
    {
        HUPDATECONFIG lpUpdate=(HUPDATECONFIG)MemAlloc(sizeof(UPDATECONFIG));
        if (lpUpdate)
        {
            lpUpdate->hPE=PE_ParseFile((TCHAR*)lpFileName);
            if (lpUpdate->hPE)
            {
                InitializeCriticalSection(&lpUpdate->csUpdate);
                if (!bDeleteExistingConfigs)
                    lpUpdate->lpNewConfigsDir=ParseInternalConfigData((HCONFIG)FindConfigSection(lpUpdate->hPE));
                lstrcpyW(lpUpdate->szFile,lpFileName);
                hUpdate=(HANDLE)lpUpdate;
            }
            else
                MemFree(lpUpdate);
        }
    }
    return hUpdate;
}

SYSLIBFUNC(HANDLE) BeginUpdateConfigA(LPCSTR lpFileName,bool bDeleteExistingConfigs)
{
    WCHAR *lpFileNameW=StrAnsiToUnicodeEx((char*)lpFileName,0,NULL);

    HANDLE hUpdate=BeginUpdateConfigW(lpFileNameW,bDeleteExistingConfigs);

    MemFree(lpFileNameW);
    return hUpdate;
}

static bool DeleteConfig(HUPDATECONFIG hUpdate,LPCSTR lpName)
{
    bool bRet=false;
    if (hUpdate->lpNewConfigsDir)
    {
        DWORD dwHashToFind=GetHashByName(lpName);
        CONFIG_DIR_ENTRY *lpDir=hUpdate->lpNewConfigsDir,*lpPrev=NULL;
        while (lpDir)
        {
            if (dwHashToFind == lpDir->dwNameHash)
            {
                /// запись найдена. удаляем
                if (lpPrev)
                    lpPrev->lpNext=lpDir->lpNext;
                else
                    hUpdate->lpNewConfigsDir=lpDir->lpNext;

                MemFree(lpDir->lpData);
                MemFree(lpDir);
                break;
            }
            lpPrev=lpDir;
            lpDir=lpDir->lpNext;
        }
    }
    return bRet;
}

static CONFIG_DIR_ENTRY *CreateNewEntry(LPCSTR lpName,LPVOID lpData,DWORD cbData)
{
    CONFIG_DIR_ENTRY *lpEntry=(CONFIG_DIR_ENTRY*)MemAlloc(sizeof(CONFIG_DIR_ENTRY));
    if (lpEntry)
    {
        lpEntry->lpData=MemQuickAlloc(cbData);
        if (!lpEntry->lpData)
        {
            MemFree(lpEntry);
            lpEntry=NULL;
        }
        else
        {
            lpEntry->dwSize=cbData;
            memcpy(lpEntry->lpData,lpData,cbData);
            if (IS_INTRESOURCE(lpName))
            {
                lpEntry->bIntName=true;
                lpEntry->dwIntName=(WORD)lpName;
            }
            else
            {
                if (lpName[0] == '#')
                {
                    DWORD dwTmpKey=StrToIntA((char*)lpName+1);
                    if (dwTmpKey <= 0xFFFF)
                    {
                        lpEntry->bIntName=true;
                        lpEntry->dwIntName=(WORD)StrToIntA((char*)lpName+1);
                    }
                    else
                        lstrcpyA(lpEntry->szName,lpName);
                }
                else
                    lstrcpyA(lpEntry->szName,lpName);
            }

            lpEntry->dwNameHash=GetDirHashName(lpEntry);
        }
    }
    return lpEntry;
}

static bool AddReplaceConfig(HUPDATECONFIG hUpdate,LPCSTR lpName,LPVOID lpData,DWORD cbData)
{
    bool bRet=false;
    if (hUpdate->lpNewConfigsDir)
    {
        bool bFound=false;
        DWORD dwHashToFind=GetHashByName(lpName);
        CONFIG_DIR_ENTRY *lpDir=hUpdate->lpNewConfigsDir,*lpLast=NULL;
        while (lpDir)
        {
            if (dwHashToFind == lpDir->dwNameHash)
            {
                /// запись найдена. обновляем
                bFound=true;
                if (lpDir->dwSize != cbData)
                {
                    lpDir->dwSize=cbData;
                    lpDir->lpData=MemRealloc(lpDir->lpData,cbData);
                }

                if (lpDir->lpData)
                {
                    memcpy(lpDir->lpData,lpData,cbData);
                    bRet=true;
                    break;
                }
                else
                {
                    /// если что-то пошло не так - попробуем добавить запись в конец
                    bFound=false;

                    if (lpLast)
                        lpLast->lpNext=lpDir->lpNext;
                    else
                        hUpdate->lpNewConfigsDir=lpDir->lpNext;

                    CONFIG_DIR_ENTRY *lpCur=lpDir;
                    lpDir=lpDir->lpNext;
                    MemFree(lpCur);
                    continue;
                }
            }
            lpLast=lpDir;
            lpDir=lpDir->lpNext;
        }

        /// запись не найдена, добавляем новую.
        if (!bFound)
        {
            if (lpLast)
            {
                lpLast->lpNext=CreateNewEntry(lpName,lpData,cbData);
                bRet=(lpLast->lpNext != NULL);
            }
            else
            {
                /// записей нет, создаем первую
                hUpdate->lpNewConfigsDir=CreateNewEntry(lpName,lpData,cbData);
                bRet=(hUpdate->lpNewConfigsDir != NULL);
            }
        }
    }
    else
    {
        /// записей нет, создаем первую
        hUpdate->lpNewConfigsDir=CreateNewEntry(lpName,lpData,cbData);
        bRet=(hUpdate->lpNewConfigsDir != NULL);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) UpdateConfigA(HANDLE hHandle,LPCSTR lpName,LPVOID lpData,DWORD cbData)
{
    BOOL bRet=false;
    if (hHandle)
    {
        HUPDATECONFIG hUpdate=(HUPDATECONFIG)hHandle;
        EnterCriticalSection(&hUpdate->csUpdate);
        {
            if ((!lpData) && (!cbData))
                bRet=DeleteConfig(hUpdate,lpName);
            else
                bRet=AddReplaceConfig(hUpdate,lpName,lpData,cbData);
        }
        LeaveCriticalSection(&hUpdate->csUpdate);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) UpdateConfigW(HANDLE hHandle,LPCWSTR lpName,LPVOID lpData,DWORD cbData)
{
    char szNameA[60];
    return UpdateConfigA(hHandle,ConvertWtoA(lpName,szNameA),lpData,cbData);
}

SYSLIBFUNC(BOOL) UpdateConfigFromFileA(HANDLE hHandle,LPCSTR lpName,LPCSTR lpFileName)
{
    BOOL bRet=false;
    HANDLE hFile=CreateFileA(lpFileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,NULL);
        if (hMapping)
        {
            void *lpMapping=MapViewOfFile(hMapping,FILE_MAP_READ,0,0,0);
            if (lpMapping)
            {
                bRet=UpdateConfigA(hHandle,lpName,lpMapping,GetFileSize(hFile,NULL));
                UnmapViewOfFile(lpMapping);
            }
            SysCloseHandle(hMapping);
        }
        SysCloseHandle(hFile);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) UpdateConfigFromFileW(HANDLE hHandle,LPCWSTR lpName,LPCWSTR lpFileName)
{
    BOOL bRet=false;
    HANDLE hFile=CreateFileW(lpFileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,NULL);
        if (hMapping)
        {
            void *lpMapping=MapViewOfFile(hMapping,FILE_MAP_READ,0,0,0);
            if (lpMapping)
            {
                bRet=UpdateConfigW(hHandle,lpName,lpMapping,GetFileSize(hFile,NULL));
                UnmapViewOfFile(lpMapping);
            }
            SysCloseHandle(hMapping);
        }
        SysCloseHandle(hFile);
    }
    return bRet;
}

static void *ConvertToConfigInternalData(CONFIG_DIR_ENTRY *lpDir,DWORD *lpSize)
{
    void *lpSection=NULL;
    DWORD dwSize=4;
    CONFIG_DIR_ENTRY *lpCurDir=lpDir;
    while (lpCurDir)
    {
        dwSize+=lpCurDir->dwSize+sizeof(CONFIG);
        lpCurDir=lpCurDir->lpNext;
    }
    lpSection=MemAlloc(dwSize);
    if (lpSection)
    {
        *(DWORD*)lpSection=CONFIG_START_MARKER;
        HCONFIG hConf=(HCONFIG)((byte*)lpSection+4);
        while ((lpDir) && (hConf))
        {
            if ((lpDir->dwSize) && (lpDir->lpData))
            {
                hConf->wMagicWord=CONFIG_MAGIC;
                hConf->dwStructSize=sizeof(CONFIG);
                hConf->bLastItem=(lpDir->lpNext == NULL);
                hConf->bIntName=lpDir->bIntName;
                memcpy(hConf->szName,lpDir->szName,sizeof(hConf->szName));
                EncrypData(hConf,(byte*)lpDir->lpData,lpDir->dwSize);
                hConf->dwCheckSum=MurmurHash3((byte*)&hConf->wMagicWord,hConf->dwSize+hConf->dwStructSize-sizeof(hConf->dwCheckSum));
                hConf=GetNextItem(hConf);
            }

            lpDir=lpDir->lpNext;
        }
        if (lpSize)
            *lpSize=dwSize;
    }
    return lpSection;
}

static BOOL WriteConfigs(HUPDATECONFIG hUpdate)
{
    INT_IMAGE_SECTION_HEADER *lpSection=SYSLIB::PE_GetSectionByAddress(hUpdate->hPE,FindConfigSection(hUpdate->hPE));
    BOOL bRet=false,
         bSectionPresent=(lpSection != NULL);

    if (!hUpdate->lpNewConfigsDir)
    {
        /// удалены все записи
        if (bSectionPresent)
        {
            /// секция присутствует, удаяем
            bRet=SYSLIB::PE_RemoveSectionInt(hUpdate->hPE,lpSection);
        }
        else
        {
            /// секция не была создана, все и так замечательно:)
            bRet=true;
        }
    }
    else
    {
        /// данные на запись есть, пишем...
        if (!bSectionPresent)
        {
            char szConfigSectionName[8];
            StrFormatA(szConfigSectionName,dcrA_90aa17cf(".%x"),xor128(GetTickCount()));
            /// если секция еще не создана - создаем
            lpSection=SYSLIB::PE_AddSection(hUpdate->hPE,szConfigSectionName,IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ);
        }
        /// пытаемся перезаписать данные в секции
        DWORD dwSize=0;
        void *lpTmpDir=ConvertToConfigInternalData(hUpdate->lpNewConfigsDir,&dwSize);
        if (lpTmpDir)
        {
            bRet=SYSLIB::PE_SetSectionDataInt(hUpdate->hPE,lpSection,lpTmpDir,dwSize);
            if (bRet)
            {
                /// если это последняя секция - изменим размер
                if ((lpSection->hdr.Misc.VirtualSize) && (!lpSection->lpNext))
                    lpSection->hdr.Misc.VirtualSize=SYSLIB::ALIGN_SECTION(dwSize,hUpdate->hPE);
            }
            else
            {
                if (lpSection->lpNext)
                {
                    /**
                        если не получилось записать данные - удалим секцию
                        и создадим новую, куда спокойно запишем все данные
                    **/
                    bRet=SYSLIB::PE_RemoveSectionInt(hUpdate->hPE,lpSection);
                    if (bRet)
                    {
                        char szConfigSectionName[8];
                        StrFormatA(szConfigSectionName,dcrA_90aa17cf(".%x"),xor128(GetTickCount()));

                        lpSection=SYSLIB::PE_AddSection(hUpdate->hPE,szConfigSectionName,IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ);
                        bRet=SYSLIB::PE_SetSectionDataInt(hUpdate->hPE,lpSection,lpTmpDir,dwSize);
                    }
                }
            }
            MemFree(lpTmpDir);
        }
    }

    if (bRet)
        bRet=PE_Build(hUpdate->hPE,hUpdate->szFile);
    return bRet;
}

SYSLIBFUNC(BOOL) EndUpdateConfig(HANDLE hHandle,BOOL bDiscard)
{
    BOOL bRet=false;
    if (hHandle)
    {
        HUPDATECONFIG hUpdate=(HUPDATECONFIG)hHandle;

        EnterCriticalSection(&hUpdate->csUpdate);
            bRet=((bDiscard) || (WriteConfigs(hUpdate)));
        LeaveCriticalSection(&hUpdate->csUpdate);

        if (hUpdate->lpNewConfigsDir)
        {
            CONFIG_DIR_ENTRY *lpDir=hUpdate->lpNewConfigsDir;
            while (lpDir)
            {
                CONFIG_DIR_ENTRY *lpCur=lpDir;
                lpDir=lpDir->lpNext;

                MemFree(lpCur->lpData);
                MemFree(lpCur);
            }
        }

        PE_Close(hUpdate->hPE);
        DeleteCriticalSection(&hUpdate->csUpdate);
        MemFree(hUpdate);
    }
    return bRet;
}



/**
    чтение и поиск ресурсов
**/

static byte *FindConfigSection(byte *lpMem)
{
#ifdef _X86_
    byte *lpImg=(byte*)((size_t)(lpMem) & 0xFFFFFF000);
#else
    byte *lpImg=(byte*)((size_t)(lpMem) & 0xFFFFFFFFFFFFF000);
#endif
    byte *lpData=NULL;
    if (ldr_CheckPE(lpImg,ldr_GetImageSize(lpImg)))
    {
        PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)(lpImg+((PIMAGE_DOS_HEADER)lpImg)->e_lfanew+4);
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
        for (DWORD i=0; i < dwNumOfSect; i++)
        {
            if (psh[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
                continue;

            DWORD *lpSectData;
            if (!LDR_IS_RESOURCE(lpMem))
                lpSectData=(DWORD*)((LONG_PTR)psh[i].VirtualAddress+lpImg);
            else
                lpSectData=(DWORD*)((LONG_PTR)psh[i].PointerToRawData+lpImg);
            if (*lpSectData == CONFIG_START_MARKER)
            {
                lpData=(byte*)(lpSectData+1);
                break;
            }
        }
    }
    return lpData;
}

static HCONFIG GetConfigPtr(HINSTANCE hModule,HANDLE hHandle)
{
    if (!hModule)
        hModule=(HINSTANCE)ldr_GetImageBase(ldr_GetOurAddr());

    HCONFIG hConfig=(HCONFIG)((DWORD_PTR)hModule+(DWORD_PTR)hHandle);
    if (!IsGoodConfig(hConfig,true))
        hConfig=NULL;
    return hConfig;
}

static DWORD GetConfigHashName(HCONFIG hConf)
{
    DWORD dwHash=0;
    if (IsGoodConfig(hConf,false))
    {
        if (!hConf->bIntName)
            dwHash=MurmurHash3((byte*)hConf->szName,lstrlenA(hConf->szName));
        else
            dwHash=hConf->dwIntName;
    }
    return dwHash;
}

SYSLIBFUNC(HANDLE) FindConfigA(HINSTANCE hModule,LPCSTR lpName)
{
    if (!hModule)
        hModule=(HINSTANCE)ldr_GetImageBase(ldr_GetOurAddr());

    HANDLE hHandle=NULL;
    HCONFIG hConf=(HCONFIG)FindConfigSection((byte*)hModule);
    if (hConf)
    {
        DWORD dwHashToFind=GetHashByName(lpName);
        while (hConf)
        {
            if (dwHashToFind == GetConfigHashName(hConf))
            {
                hHandle=(HANDLE)((DWORD_PTR)hConf-(DWORD_PTR)hModule);
                break;
            }
            hConf=GetNextItem(hConf);
        }
    }
    return hHandle;
}

SYSLIBFUNC(HANDLE) FindConfigW(HINSTANCE hModule,LPCWSTR lpName)
{
    char szNameA[60];
    return FindConfigA(hModule,ConvertWtoA(lpName,szNameA));
}

static bool EnumConfigNamesInt(HMODULE hModule,ENUM_CONFIGS_INT *lpInt)
{
    bool bRet=true;

    HCONFIG hConf=(HCONFIG)FindConfigSection((byte*)hModule);
    if (hConf)
    {
        while (hConf)
        {
            if (lpInt->bUnicode)
            {
                WCHAR szNameW[50],*lpName=szNameW;
                if (hConf->bIntName)
                    lpName=(WCHAR*)hConf->dwIntName;
                else
                    StrAnsiToUnicode(hConf->szName,0,szNameW,0);
                bRet=lpInt->lpUnicode(hModule,lpName,lpInt->lParam);
            }
            else
            {
                char szNameA[50],*lpName=szNameA;
                if (hConf->bIntName)
                    lpName=(char*)hConf->dwIntName;
                else
                    StrCpyNA(szNameA,hConf->szName,ARRAYSIZE(szNameA));
                bRet=lpInt->lpAnsi(hModule,lpName,lpInt->lParam);
            }
            if (!bRet)
                break;

            hConf=GetNextItem(hConf);
        }
    }
    return bRet;
}

SYSLIBFUNC(BOOL) EnumConfigNamesW(HINSTANCE hModule,ENUMCONFNAMEPROCW lpFun,LONG_PTR lParam)
{
    ENUM_CONFIGS_INT eci;
    eci.lParam=lParam;
    eci.bUnicode=true;
    eci.lpUnicode=lpFun;
    return EnumConfigNamesInt(hModule,&eci);
}

SYSLIBFUNC(BOOL) EnumConfigNamesA(HINSTANCE hModule,ENUMCONFNAMEPROCA lpFun,LONG_PTR lParam)
{
    ENUM_CONFIGS_INT eci;
    eci.lParam=lParam;
    eci.bUnicode=false;
    eci.lpAnsi=lpFun;
    return EnumConfigNamesInt(hModule,&eci);
}

SYSLIBFUNC(LPVOID) LoadConfig(HINSTANCE hModule,HANDLE hHandle)
{
    LPVOID lpConfig=NULL;
    HCONFIG hConf=GetConfigPtr(hModule,hHandle);
    if (hConf)
    {
        lpConfig=MemQuickAlloc(hConf->dwSize);
        if (lpConfig)
            DecryptData(hConf,(byte*)lpConfig);
    }
    return lpConfig;
}

SYSLIBFUNC(void) FreeConfig(LPVOID lpConfig)
{
    if (lpConfig)
        MemFree(lpConfig);
    return;
}

SYSLIBFUNC(DWORD) SizeofConfig(HINSTANCE hModule,HANDLE hHandle)
{
    DWORD dwSize=0;
    HCONFIG hConfig=GetConfigPtr(hModule,hHandle);
    if (hConfig)
        dwSize=hConfig->dwSize;
    return dwSize;
}

