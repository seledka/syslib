#include "sys_includes.h"
#include "res.h"

#include "syslib\ldr.h"
#include "syslib\system.h"
#include "syslib\str.h"
#include "syslib\mem.h"

#include <shlwapi.h>

static PIMAGE_RESOURCE_DIRECTORY_ENTRY SearchResourceEntry(PIMAGE_RESOURCE_DIRECTORY lpRoot,PIMAGE_RESOURCE_DIRECTORY lpResources,LPCWSTR lpKey)
{
    PIMAGE_RESOURCE_DIRECTORY_ENTRY lpEntries=(PIMAGE_RESOURCE_DIRECTORY_ENTRY)lpResources+1,lpResult=NULL;
    DWORD dwStart,dwMiddle,dwEnd;

    if ((!IS_INTRESOURCE(lpKey)) && (lpKey[0] == L'#'))
    {
        DWORD dwTmpKey=StrToIntW(lpKey+1);
        if (dwTmpKey <= 0xFFFF)
            lpKey=MAKEINTRESOURCE(dwTmpKey);
    }

    if (IS_INTRESOURCE(lpKey))
    {
        WORD wCheck=(WORD)(DWORD_PTR)lpKey;
        dwStart=lpResources->NumberOfNamedEntries;
        dwEnd=dwStart+lpResources->NumberOfIdEntries;

        while (dwEnd > dwStart)
        {
            dwMiddle=(dwStart+dwEnd) >> 1;
            WORD wEntryName=(WORD)lpEntries[dwMiddle].Name;
            if (wCheck < wEntryName)
                dwEnd=(dwEnd != dwMiddle ? dwMiddle : dwMiddle-1);
            else if (wCheck > wEntryName)
                dwStart=(dwStart != dwMiddle ? dwMiddle : dwMiddle+1);
            else
            {
                lpResult=&lpEntries[dwMiddle];
                break;
            }
        }
    }
    else
    {
        dwStart=0;
        dwEnd=lpResources->NumberOfIdEntries;
        while (dwEnd > dwStart)
        {
            dwMiddle=(dwStart+dwEnd) >> 1;
            PIMAGE_RESOURCE_DIR_STRING_U lpResourceString=(PIMAGE_RESOURCE_DIR_STRING_U)(((char *) lpRoot)+(lpEntries[dwMiddle].Name & 0x7FFFFFFF));

            int dwCmpResult=StrCmpNW(lpKey,lpResourceString->NameString,lpResourceString->Length);
            if (dwCmpResult < 0)
                dwEnd=(dwMiddle != dwEnd ? dwMiddle : dwMiddle-1);
            else if (dwCmpResult > 0)
                dwStart=(dwMiddle != dwStart ? dwMiddle : dwMiddle+1);
             else
             {
                lpResult=&lpEntries[dwMiddle];
                break;
            }
        }
    }
    return lpResult;
}

SYSLIBFUNC(HMEMRESOURCE) ldr_FindResourceExW(HMODULE hModule,LPCWSTR lpName,LPCWSTR lpType,WORD wLang)
{
    HMEMRESOURCE hRes=NULL;

    PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)hModule;
    PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((ULONG_PTR)hModule+dos->e_lfanew+4);
    PIMAGE_OPTIONAL_HEADER poh=(PIMAGE_OPTIONAL_HEADER)(pfh+1);

    do
    {
        PIMAGE_DATA_DIRECTORY lpDirectory=&poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
        if (!lpDirectory->Size)
            break;

        if (wLang == DEFAULT_LANGUAGE)
            wLang=LANGIDFROMLCID(GetThreadLocale());

        PIMAGE_RESOURCE_DIRECTORY lpRootResources=(PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)hModule+lpDirectory->VirtualAddress);
        PIMAGE_RESOURCE_DIRECTORY_ENTRY lpFoundType=SearchResourceEntry(lpRootResources,lpRootResources,lpType);
        if (!lpFoundType)
            break;

        PIMAGE_RESOURCE_DIRECTORY lpTypeResources=(PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)hModule+lpDirectory->VirtualAddress+(lpFoundType->OffsetToData & 0x7FFFFFFF));
        PIMAGE_RESOURCE_DIRECTORY_ENTRY lpFoundName=SearchResourceEntry(lpRootResources,lpTypeResources,lpName);
        if (!lpFoundName)
            break;

        PIMAGE_RESOURCE_DIRECTORY lpNameResources=(PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)hModule+lpDirectory->VirtualAddress+(lpFoundName->OffsetToData & 0x7FFFFFFF));
        PIMAGE_RESOURCE_DIRECTORY_ENTRY lpFoundLanguage=SearchResourceEntry(lpRootResources,lpNameResources,(LPCWSTR)(DWORD_PTR)wLang);
        if (!lpFoundLanguage)
        {
            if (!lpNameResources->NumberOfIdEntries)
                break;

            lpFoundLanguage=(PIMAGE_RESOURCE_DIRECTORY_ENTRY)(lpNameResources+1);
        }

        hRes=(HMEMRESOURCE)((DWORD_PTR)hModule+lpDirectory->VirtualAddress+(lpFoundLanguage->OffsetToData & 0x7FFFFFFF));
    }
    while (false);

    return hRes;
}

SYSLIBFUNC(HMEMRESOURCE) ldr_FindResourceExA(HMODULE hModule,LPCSTR lpName,LPCSTR lpType,WORD wLang)
{
    LPWSTR lpNameW=StrAnsiToUnicodeEx(lpName,0,NULL),
           lpTypeW=StrAnsiToUnicodeEx(lpType,0,NULL);

    HMEMRESOURCE hRes=ldr_FindResourceExW(hModule,lpNameW,lpTypeW,wLang);

    MemFree(lpNameW);
    MemFree(lpTypeW);

    return hRes;
}

SYSLIBFUNC(HMEMRESOURCE) ldr_FindResourceW(HMODULE hModule,LPCWSTR lpName,LPCWSTR lpType)
{
    return ldr_FindResourceExW(hModule,lpName,lpType,DEFAULT_LANGUAGE);
}

SYSLIBFUNC(HMEMRESOURCE) ldr_FindResourceA(HMODULE hModule,LPCSTR lpName,LPCSTR lpType)
{
    LPWSTR lpNameW=StrAnsiToUnicodeEx(lpName,0,NULL),
           lpTypeW=StrAnsiToUnicodeEx(lpType,0,NULL);

    HMEMRESOURCE hRes=ldr_FindResourceW(hModule,lpNameW,lpTypeW);

    MemFree(lpNameW);
    MemFree(lpTypeW);

    return hRes;
}

SYSLIBFUNC(DWORD) ldr_SizeofResource(HMODULE hModule,HMEMRESOURCE hResource)
{
    PIMAGE_RESOURCE_DATA_ENTRY lpEntry=(PIMAGE_RESOURCE_DATA_ENTRY)hResource;

    DWORD dwSize=0;
    if (lpEntry)
        dwSize=lpEntry->Size;
    return dwSize;
}

SYSLIBFUNC(LPVOID) ldr_LoadResource(HMODULE hModule,HMEMRESOURCE hResource)
{
    PIMAGE_RESOURCE_DATA_ENTRY lpEntry=(PIMAGE_RESOURCE_DATA_ENTRY)hResource;
    LPVOID lpResource=NULL;
    if (lpEntry)
        lpResource=(LPVOID)((DWORD_PTR)hModule+lpEntry->OffsetToData);

    return lpResource;
}

/**
int
MemoryLoadString(HMEMORYMODULE module, UINT id, LPTSTR buffer, int maxsize)
{
    return MemoryLoadStringEx(module, id, buffer, maxsize, DEFAULT_LANGUAGE);
}

int
MemoryLoadStringEx(HMEMORYMODULE module, UINT id, LPTSTR buffer, int maxsize, WORD language)
{
	HMEMORYRSRC resource;
	PIMAGE_RESOURCE_DIR_STRING_U data;
	DWORD size;
    if (maxsize == 0) {
        return 0;
    }

    resource = MemoryFindResourceEx(module, MAKEINTRESOURCE((id >> 4) + 1), RT_STRING, language);
    if (resource == NULL) {
        buffer[0] = 0;
        return 0;
    }

    data = MemoryLoadResource(module, resource);
    id = id & 0x0f;
    while (id--) {
        data = (PIMAGE_RESOURCE_DIR_STRING_U) (((char *) data) + (data->Length + 1) * sizeof(WCHAR));
    }
    if (data->Length == 0) {
        SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
        buffer[0] = 0;
        return 0;
    }

    size = data->Length;
    if (size >= (DWORD) maxsize) {
        size = maxsize;
    } else {
        buffer[size] = 0;
    }
#if defined(UNICODE)
    wcsncpy(buffer, data->NameString, size);
#else
    wcstombs(buffer, data->NameString, size);
#endif
    return size;
}
**/

