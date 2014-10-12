#include "sys_includes.h"
#include <intrin.h>

#include "ldr.h"
#include "system\system.h"
#include "inject\inject.h"

#include "syslib\debug.h"
#include "syslib\apihook.h"
#include "syslib\ldr.h"
#include "syslib\inject.h"
#include "syslib\chksum.h"
#include "syslib\system.h"
#include "syslib\str.h"
#include "syslib\mem.h"

#include <syslib\strcrypt.h>
#include "str_crx.h"

namespace SYSLIB
{
    DWORD chksum_crc32_int(LPBYTE block,DWORD length);
};

#pragma optimize("",off)
SYSLIBFUNC(LPBYTE) ldr_GetOurAddr()
{
    return (byte*)_ReturnAddress();
}
#pragma optimize("",on)

SYSLIBFUNC(LPBYTE) ldr_GetImageBase(LPBYTE lpImg)
{
    __try
    {
        WORD tmp='ZM' ^ 0x3030;
        tmp^=0x3030;

    #ifdef _X86_
        lpImg=(byte*)((size_t)(lpImg) & 0xFFFFFF000);
    #else
        lpImg=(byte*)((size_t)(lpImg) & 0xFFFFFFFFFFFFF000);
    #endif
        for (;; lpImg-=0x1000)
        {
            if (*(WORD*)lpImg == tmp)
            {
                tmp='EP' ^ 0x3030;
                tmp^=0x3030;
                if (*(WORD*)&lpImg[((PIMAGE_DOS_HEADER)lpImg)->e_lfanew] == tmp)
                    return lpImg;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    return NULL;
}

static int strcmpiW(const WCHAR *s1,const WCHAR *s2)
{
    const WCHAR *p1 = (const WCHAR *) s1;
    const WCHAR *p2 = (const WCHAR *) s2;
    WCHAR c1, c2;

    if (p1 == p2)
        return 0;

    while (true)
    {
        c1 = *p1++;
        if (c1 == 0)
            break;

        c2 = *p2++;
        if (c1 != c2)
        {
            if (c1 < c2)
            {
                c1 = c2;
                c2 = *(p1-1);
            }

            if (c1-c2 != 0x20)
                return 1;
        }
    }
    return 0;
}

static HMODULE GetK32Base()
{
    HMODULE hMod=NULL;
	PPEB_LDR_DATA lpLdr=SysGetCurrentPeb()->Ldr;
	PEB_LDR_MODULE *lpModule=(PEB_LDR_MODULE *)lpLdr->InLoadOrderModuleList.Flink;
	WCHAR szKernel32[]={L'k',L'e',L'r',L'n',L'e',L'l',L'3',L'2',L'.',L'd',L'l',L'l',0};
	do
	{
		if (!strcmpiW(lpModule->BaseDllName.Buffer,szKernel32))
		{
			hMod=(HMODULE)lpModule->BaseAddress;
			break;
		}

		lpModule=(PEB_LDR_MODULE *)lpModule->InLoadOrderModuleList.Flink;
	}
	while ((lpModule->BaseAddress) && (lpModule != (PEB_LDR_MODULE *)lpLdr->InLoadOrderModuleList.Flink));
    return hMod;
}

static size_t _strlen(char *str)
{
    char *eos = str;
    while( *eos++ ) str=str;
    return((int)(eos - str - 1));
}

static char *_strcpy(char *dst,char *src)
{
    memcpy(dst,src, _strlen(src) + 1);
    return dst;
}

static char *_strchr(char *s,char c)
{
    char *ret=s;

    do
    {
        if (*ret==c) break;
        ret++;
    }
    while (*ret);

    return (*ret==c) ? ret : NULL;
}

static LPVOID GetProcAddressEx(HMODULE lpImg,LPCSTR lpProcName,int dwFlags,__LoadLibraryExA *lpLoadLibraryExA)
{
    if (!lpImg)
        return NULL;

    LPVOID lpRet=NULL;
    byte *buf=(byte *)lpImg;

    WORD tmp='ZM'^0x3030;
    tmp^=0x3030;
    if (*(WORD *)buf == tmp)
    {
        PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)buf;
        PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((ULONG_PTR)buf+dos->e_lfanew+4);
#ifdef _X86_
        if (pfh->Machine == IMAGE_FILE_MACHINE_I386)
#else
        if (pfh->Machine == IMAGE_FILE_MACHINE_AMD64)
#endif
        {
            PIMAGE_OPTIONAL_HEADER poh=(PIMAGE_OPTIONAL_HEADER)(pfh+1);
            if (poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
            {
                PIMAGE_EXPORT_DIRECTORY exp=(PIMAGE_EXPORT_DIRECTORY)&buf[poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress];

                ULONG dwOrd=-1;
                //импорт по ординалу
                if (!HIWORD(lpProcName))
                    dwOrd=((ULONG)LOWORD(lpProcName))-exp->Base;
                else
                {
                    int func_hash;
                    if (dwFlags & LDR_GET_BY_HASH)
                        //импорт по хэшу
                        func_hash=(int)lpProcName;
                    else
                        //импорт по имени
                        func_hash=SYSLIB::chksum_crc32_int((byte *)lpProcName,_strlen((char*)lpProcName));

                    //импорт по имени
                    for (DWORD i=0; i < exp->NumberOfNames; i++)
                    {
                        byte *s=(byte*)&buf[*(DWORD*)&buf[exp->AddressOfNames+i*sizeof(DWORD)]];
                        if (func_hash == SYSLIB::chksum_crc32_int(s,_strlen((char*)s)))
                        {
                            dwOrd=*(WORD*)&buf[exp->AddressOfNameOrdinals+i*2];
                            break;
                        }
                    }
                }
                lpRet=((dwOrd != -1) ? (LPVOID*)&buf[*(DWORD*)&buf[exp->AddressOfFunctions+dwOrd*sizeof(DWORD)]] : 0);
                if (((ULONG_PTR)lpRet >= (ULONG_PTR)exp) && ((ULONG_PTR)lpRet < (ULONG_PTR)exp+poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
                {
                    if (!lpLoadLibraryExA)
                        return NULL;

                    //в экспорте форвард на другую библиотеку...
                    char FwName[128];
                    _strcpy(FwName,(char*)lpRet);
                    lpRet=NULL;

                    char *p=_strchr(FwName,'.');
                    if (p)
                    {
                        *p=0;
                        if (HMODULE hMod=lpLoadLibraryExA(FwName,NULL,0))
                            lpRet=GetProcAddressEx(hMod,p+1,0,lpLoadLibraryExA);
                    }
                }
            }
        }
    }
    return lpRet;
}

SYSLIBFUNC(LPVOID) ldr_GetProcAddress(HINSTANCE hModule,LPCSTR lpProc)
{
    return GetProcAddressEx(hModule,lpProc,0,LoadLibraryExA);
}

static __ZwQueryInformationProcess *pZwQueryInformationProcess;
static NTSTATUS NTAPI ZwQueryInformationProcess_handler(HANDLE ProcessHandle,PROCESS_INFORMATION_CLASS ProcessInformationClass,PVOID ProcessInformation,ULONG ProcessInformationLength,PULONG ReturnLength)
{
    NTSTATUS dwRet=NULL;
    if (pZwQueryInformationProcess)
    {
        dwRet=pZwQueryInformationProcess(ProcessHandle,ProcessInformationClass,ProcessInformation,ProcessInformationLength,ReturnLength);
        if ((NT_SUCCESS(dwRet)) && (ProcessInformationClass == ProcessExecuteFlags) && (ProcessInformation) && (ProcessInformationLength >= 4))
        {
            void *lpNTDLL=GetModuleHandleA(dcrA_91764d8a("ntdll.dll"));
            PIMAGE_NT_HEADERS lpNTHdrs=RtlImageNtHeader(lpNTDLL);
            void *lpEnd=(void*)((INT_PTR)lpNTDLL+(INT_PTR)lpNTHdrs->OptionalHeader.SizeOfImage),
                 *lpRet=HookAPI_GetReturnAddress(ZwQueryInformationProcess);
            if ((lpRet >= lpNTDLL) && (lpRet < lpEnd))
            {
                ULONG uFlags=*(PULONG)ProcessInformation;
                if (!(uFlags & MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE))
                {
                    uFlags|=MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE;
                    *(PULONG)ProcessInformation=uFlags;
                }
            }
        }
    }
    return dwRet;
}

static DWORD GetProcessExecuteFlags()
{
    DWORD dwFlags=0,n=0;
    if (!NT_SUCCESS(ZwQueryInformationProcess(GetCurrentProcess(),(PROCESS_INFORMATION_CLASS)ProcessExecuteFlags,&dwFlags,sizeof(dwFlags),&n)))
        dwFlags=0;
    return dwFlags;
}

static void SysInitExceptions()
{
    DWORD dwFlags=GetProcessExecuteFlags();
    if (!(dwFlags & MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE))
        pZwQueryInformationProcess=(__ZwQueryInformationProcess*)HookAPI_Hook(ZwQueryInformationProcess,ZwQueryInformationProcess_handler);
    return;
}

#ifndef _X86_
static void ldr_BuildExeceptionsTable(PIMAGE_OPTIONAL_HEADER poh,LPBYTE lpImage)
{
    if (poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress)
    {
        PRUNTIME_FUNCTION lpRuntimeFunc=(PRUNTIME_FUNCTION) RVATOVA(poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress,lpImage);
        RtlAddFunctionTable(lpRuntimeFunc,poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size/sizeof(RUNTIME_FUNCTION),(DWORD64)lpImage);
    }
    return;
}
#endif

#ifdef _WIN64
static PIMAGE_BASE_RELOCATION ProcessRelocationBlock(ULONG_PTR VA, ULONG SizeOfBlock, PUSHORT NextOffset, LONGLONG Diff)
{
	PUCHAR FixupVA;
	USHORT Offset;
	LONG Temp;
	ULONGLONG Value64;

	while (SizeOfBlock--)
	{

		Offset = *NextOffset & (USHORT)0xfff;
		FixupVA = (PUCHAR)(VA + Offset);

		switch ((*NextOffset) >> 12)
		{

		case IMAGE_REL_BASED_HIGHLOW :
			*(LONG UNALIGNED *)FixupVA += (ULONG) Diff;
			break;

		case IMAGE_REL_BASED_HIGH :
			Temp = *(PUSHORT)FixupVA < 16;
			Temp += (ULONG) Diff;
			*(PUSHORT)FixupVA = (USHORT)(Temp >> 16);
			break;

		case IMAGE_REL_BASED_HIGHADJ :
			if (Offset & LDRP_RELOCATION_FINAL) {
				++NextOffset;
				--SizeOfBlock;
				break;
			}

			Temp = *(PUSHORT)FixupVA < 16;
			++NextOffset;
			--SizeOfBlock;
			Temp += (LONG)(*(PSHORT)NextOffset);
			Temp += (ULONG) Diff;
			Temp += 0x8000;
			*(PUSHORT)FixupVA = (USHORT)(Temp >> 16);

			break;

		case IMAGE_REL_BASED_LOW :
			Temp = *(PSHORT)FixupVA;
			Temp += (ULONG) Diff;
			*(PUSHORT)FixupVA = (USHORT)Temp;
			break;

		case IMAGE_REL_BASED_IA64_IMM64:
			FixupVA = (PUCHAR)((ULONG_PTR)FixupVA & ~(15));
			Value64 = (ULONGLONG)0;

			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X,
				EMARCH_ENC_I17_IMM7B_SIZE_X,
				EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM7B_VAL_POS_X);
			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X,
				EMARCH_ENC_I17_IMM9D_SIZE_X,
				EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM9D_VAL_POS_X);
			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X,
				EMARCH_ENC_I17_IMM5C_SIZE_X,
				EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM5C_VAL_POS_X);
			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X,
				EMARCH_ENC_I17_IC_SIZE_X,
				EMARCH_ENC_I17_IC_INST_WORD_POS_X,
				EMARCH_ENC_I17_IC_VAL_POS_X);
			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X,
				EMARCH_ENC_I17_IMM41a_SIZE_X,
				EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41a_VAL_POS_X);

			EXT_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
				EMARCH_ENC_I17_IMM41b_SIZE_X,
				EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41b_VAL_POS_X);
			EXT_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
				EMARCH_ENC_I17_IMM41c_SIZE_X,
				EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41c_VAL_POS_X);
			EXT_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
				EMARCH_ENC_I17_SIGN_SIZE_X,
				EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
				EMARCH_ENC_I17_SIGN_VAL_POS_X);

			Value64+=Diff;

			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X),
				EMARCH_ENC_I17_IMM7B_SIZE_X,
				EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM7B_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X),
				EMARCH_ENC_I17_IMM9D_SIZE_X,
				EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM9D_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X),
				EMARCH_ENC_I17_IMM5C_SIZE_X,
				EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM5C_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X),
				EMARCH_ENC_I17_IC_SIZE_X,
				EMARCH_ENC_I17_IC_INST_WORD_POS_X,
				EMARCH_ENC_I17_IC_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X),
				EMARCH_ENC_I17_IMM41a_SIZE_X,
				EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41a_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
				EMARCH_ENC_I17_IMM41b_SIZE_X,
				EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41b_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
				EMARCH_ENC_I17_IMM41c_SIZE_X,
				EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41c_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
				EMARCH_ENC_I17_SIGN_SIZE_X,
				EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
				EMARCH_ENC_I17_SIGN_VAL_POS_X);
			break;

		case IMAGE_REL_BASED_DIR64:

			*(ULONGLONG UNALIGNED *)FixupVA += Diff;

			break;

		case IMAGE_REL_BASED_MIPS_JMPADDR :
			Temp = (*(PULONG)FixupVA & 0x3ffffff) < 2;
			Temp += (ULONG) Diff;
			*(PULONG)FixupVA = (*(PULONG)FixupVA & ~0x3ffffff) |
				((Temp >> 2) & 0x3ffffff);

			break;

		case IMAGE_REL_BASED_ABSOLUTE :
			break;

		case IMAGE_REL_BASED_SECTION :
			break;

		case IMAGE_REL_BASED_REL32 :
			break;

		default :
			return (PIMAGE_BASE_RELOCATION)NULL;
		}

		++NextOffset;
	}

	return (PIMAGE_BASE_RELOCATION)NextOffset;
}
#else
static PIMAGE_BASE_RELOCATION ProcessRelocationBlock(ULONG_PTR VA, ULONG SizeOfBlock, PUSHORT NextOffset, LONGLONG Diff)
{
	PBYTE pFixupVA = NULL;
	USHORT uOffset = 0;
	LONG lTemp = 0;
	LONG lTempOrig = 0;
	LONGLONG l64Temp64 = 0;
	LONG_PTR lActualDiff = 0;
	SHORT dwNextOffset;

	while (SizeOfBlock --)
	{
		uOffset = *NextOffset & ((USHORT) 0xFFF);
		pFixupVA = (PBYTE) (VA + uOffset);

		dwNextOffset = (*NextOffset) >> 12;

		if ( dwNextOffset == IMAGE_REL_BASED_HIGHLOW )
		{
			*(LONG UNALIGNED*) pFixupVA += (ULONG) Diff;
		}
		else if ( dwNextOffset == IMAGE_REL_BASED_HIGH )
		{
			lTemp = *(PUSHORT) pFixupVA << 16;
			lTemp += (ULONG) Diff;
			*(PUSHORT) pFixupVA = (USHORT) (lTemp >> 16);
		}
		else if ( dwNextOffset == IMAGE_REL_BASED_HIGHADJ )
		{
			if (uOffset & LDRP_RELOCATION_FINAL)
			{
				NextOffset ++;
				SizeOfBlock --;
			}
			else
			{
				lTemp = *(PUSHORT) pFixupVA << 16;
				lTempOrig = lTemp;

				NextOffset ++;
				SizeOfBlock --;

				lTemp += (LONG) (*(PSHORT) NextOffset);
				lTemp += (ULONG) Diff;
				lTemp += 0x8000;

				*(PUSHORT) pFixupVA = (USHORT) (lTemp >> 16);

				lActualDiff = ((((ULONG_PTR) (lTemp - lTempOrig)) >> 16) -
					(((ULONG_PTR) Diff) >> 16));

				if (lActualDiff == 1)
				{
					*(NextOffset - 1) |= LDRP_RELOCATION_INCREMENT;
				}
				else if (lActualDiff != 0)
				{
					*(NextOffset - 1) |= LDRP_RELOCATION_FINAL;
				}
			}
		}
		else if ( dwNextOffset == IMAGE_REL_BASED_LOW )
		{
			lTemp = *((PSHORT) pFixupVA);
			lTemp += (ULONG) Diff;
			*((PUSHORT) pFixupVA) = (USHORT) lTemp;
		}
		else if ( dwNextOffset == IMAGE_REL_BASED_ABSOLUTE )
		{
		}
		else if ( dwNextOffset == IMAGE_REL_BASED_SECTION )
		{
		}
		else if ( dwNextOffset == IMAGE_REL_BASED_REL32 )
		{
		}
		else if ( dwNextOffset == IMAGE_REL_BASED_HIGH3ADJ )
		{
			NextOffset ++;
			SizeOfBlock --;

			l64Temp64 = *(PUSHORT) pFixupVA << 16;
			l64Temp64 += (LONG) ((SHORT) NextOffset [1]);
			l64Temp64 <<= 16;
			l64Temp64 += (LONG) ((USHORT) NextOffset [0]);
			l64Temp64 += Diff;
			l64Temp64 += 0x8000;
			l64Temp64 >>= 16;
			l64Temp64 += 0x8000;

			*(PUSHORT) pFixupVA = (USHORT) (l64Temp64 >> 16);

			NextOffset ++;
			SizeOfBlock --;
		}
		else
		{
			return (PIMAGE_BASE_RELOCATION) NULL;
		}

		NextOffset ++;
	}

	return (PIMAGE_BASE_RELOCATION) NextOffset;
}
#endif

static BOOL ProcessRelocations(PBYTE pImageBase,ULONG_PTR lImageBaseDelta,PIMAGE_OPTIONAL_HEADER pOptionalHeader,PIMAGE_BASE_RELOCATION pRelocBlocks)
{
    PIMAGE_BASE_RELOCATION pRelocBlock = NULL;
    ULONG uBlockSize = 0;
    PUSHORT pNextOffset = 0;
    ULONG_PTR uVA = 0;
    ULONG uRelocsSize = 0;

    pRelocBlock = pRelocBlocks;
    uRelocsSize = pOptionalHeader -> DataDirectory [IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    while (uRelocsSize > 0)
    {
        uBlockSize = pRelocBlock -> SizeOfBlock;
        uRelocsSize -= uBlockSize;

        uBlockSize -= sizeof (IMAGE_BASE_RELOCATION);
        uBlockSize /= sizeof (USHORT);

        pNextOffset = (PUSHORT) (((PBYTE) pRelocBlock) + sizeof (IMAGE_BASE_RELOCATION));
        uVA = (ULONG_PTR) pImageBase + pRelocBlock -> VirtualAddress;

        pRelocBlock = ProcessRelocationBlock (uVA, uBlockSize, pNextOffset, lImageBaseDelta);
        if (!pRelocBlock)
            return FALSE;
    }
    return TRUE;
}

static ULONG_PTR ImportGetAddress(__GetProcAddress *lpGetProcAddress,HMODULE hDll,PBYTE pImageBase,PIMAGE_THUNK_DATA Thunk)
{
    LPCSTR lpName=Thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ? (MAKEINTRESOURCEA(LOWORD(Thunk->u1.Ordinal))) : ((char*) ((PIMAGE_IMPORT_BY_NAME) &pImageBase[(ULONG_PTR)Thunk->u1.AddressOfData])->Name);
    return (ULONG_PTR)lpGetProcAddress(hDll,lpName);
}

static BOOL ProcessImports(PBYTE pImageBase,PIMAGE_OPTIONAL_HEADER pOptionalHeader)
{
    BOOL bRet=false;

    HMODULE hKernel32=GetK32Base();
    __LoadLibraryExA *lpLoadLibraryExA=(__LoadLibraryExA*)GetProcAddressEx(hKernel32,(LPCSTR)0x9B102E2D,LDR_GET_BY_HASH,NULL);
    if (lpLoadLibraryExA)
    {
        __GetProcAddress *lpGetProcAddress=(__GetProcAddress*)GetProcAddressEx(hKernel32,(LPCSTR)0xC97C1FFF,LDR_GET_BY_HASH,NULL);
        if (lpGetProcAddress)
        {
            bool bOk=true;
            PIMAGE_IMPORT_DESCRIPTOR lpImport=(PIMAGE_IMPORT_DESCRIPTOR)&pImageBase[pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress];
            for (; lpImport->Name; lpImport++)
            {
                HMODULE hDll=lpLoadLibraryExA((LPCSTR)&pImageBase[lpImport->Name],NULL,0);
                if (hDll)
                {
                    if (!lpImport->FirstThunk)
                        continue;

                    ULONG_PTR *lpAddr=(ULONG_PTR*)(&pImageBase[lpImport->FirstThunk]);

                    DWORD_PTR *lpThunk;
                    if (lpImport->TimeDateStamp == -1)
                    {
                        PIMAGE_THUNK_DATA OriginalThunk=(PIMAGE_THUNK_DATA)&pImageBase[lpImport->OriginalFirstThunk];
                        ULONG_PTR lpFunc=ImportGetAddress(lpGetProcAddress,hDll,pImageBase,OriginalThunk);

                        PIMAGE_THUNK_DATA Thunk=(PIMAGE_THUNK_DATA)&pImageBase[lpImport->FirstThunk];
                        if (Thunk->u1.Function == lpFunc)
                            continue;

                        lpThunk=(DWORD_PTR*)OriginalThunk;
                    }
                    else
                    {
                        if (lpImport->OriginalFirstThunk)
                            lpThunk=(DWORD_PTR*)&pImageBase[lpImport->OriginalFirstThunk];
                        else
                            lpThunk=(DWORD_PTR*)&pImageBase[lpImport->FirstThunk];
                    }

                    for (; *lpThunk; lpThunk++)
                    {
                        ULONG_PTR lpFunc=ImportGetAddress(lpGetProcAddress,hDll,pImageBase,(PIMAGE_THUNK_DATA)lpThunk);
                        if (!lpFunc)
                        {
                            bOk=false;
                            break;
                        }
                        *lpAddr++=lpFunc;
                    }

                    if (!bOk)
                        break;
                }
                else
                {
                    bOk=false;
                    break;
                }
            }

            bRet=(bOk != false);
        }
    }
    return bRet;
}

SYSLIBFUNC(void) ldr_RebasePE()
{
    byte *lpImg=ldr_GetImageBase(ldr_GetOurAddr());
    if (!lpImg)
        return;

    PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER) (lpImg);
    PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((ULONG_PTR)lpImg+dos->e_lfanew+4);
    PIMAGE_OPTIONAL_HEADER poh=(PIMAGE_OPTIONAL_HEADER)(pfh+1);

    bool bRelocated=false;
    ULONG_PTR hInst=poh->ImageBase;
    if ((ULONG_PTR)lpImg != hInst)
    {
        bRelocated=true;
        if (poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
        {
            PIMAGE_BASE_RELOCATION lpReloc=(PIMAGE_BASE_RELOCATION) RVATOVA(poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,lpImg);
            ProcessRelocations(lpImg,(ULONG_PTR)lpImg-(ULONG_PTR)poh->ImageBase,poh,lpReloc);
        }
        poh->ImageBase=(ULONG_PTR)lpImg;
    }

    if (poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
        ProcessImports(lpImg,poh);

    #ifndef _X86_
    if (bRelocated)
        ldr_BuildExeceptionsTable(poh,lpImg);
    #endif

    SysInitExceptions();
    return;
}

SYSLIBFUNC(DWORD) ldr_GetImageSize(LPBYTE lpImage)
{
    if (!lpImage)
        lpImage=ldr_GetImageBase(ldr_GetOurAddr());

    PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((byte*)lpImage+((PIMAGE_DOS_HEADER)lpImage)->e_lfanew+4);
    DWORD dwSize;
    if (pfh->Machine == IMAGE_FILE_MACHINE_I386)
        dwSize=((PIMAGE_OPTIONAL_HEADER32)((lpImage)+((PIMAGE_DOS_HEADER)(lpImage))->e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)))->SizeOfImage;
    else
        dwSize=((PIMAGE_OPTIONAL_HEADER64)((lpImage)+((PIMAGE_DOS_HEADER)(lpImage))->e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)))->SizeOfImage;
    return dwSize;
}

SYSLIBFUNC(HMODULE) ldr_LoadImageFromMemory(LPBYTE lpMem)
{
    HMODULE hImage=NULL;
    if (lpMem)
    {
        PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)lpMem;
        PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((ULONG_PTR)lpMem+dos->e_lfanew+4);
#ifdef _X86_
        if (pfh->Machine == IMAGE_FILE_MACHINE_I386)
#else
        if (pfh->Machine == IMAGE_FILE_MACHINE_AMD64)
#endif
        {
            PIMAGE_OPTIONAL_HEADER poh=(PIMAGE_OPTIONAL_HEADER)(pfh+1);
            PIMAGE_SECTION_HEADER psh=(PIMAGE_SECTION_HEADER)((ULONG_PTR)poh+sizeof(*poh));
            byte *lpNewBase=(byte*)VirtualAlloc(NULL,poh->SizeOfImage,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
            if (lpNewBase)
            {
                //копируем хидеры и делаем пометку о том, что модуль загружен "руками"
                {
                    memcpy(lpNewBase,lpMem,psh->PointerToRawData);

                    PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)lpNewBase;
                    PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((ULONG_PTR)lpNewBase+dos->e_lfanew+4);
                    pfh->TimeDateStamp=0xDEAD;
                    pfh->PointerToSymbolTable=0xDEAD;
                }

                //копируем секции
                for (int i=0; i < pfh->NumberOfSections; i++, psh++)
                {
                    LPVOID lpNewImg=(byte *)lpNewBase+psh->VirtualAddress;
                    memcpy(lpNewImg,(byte *)lpMem+psh->PointerToRawData,psh->SizeOfRawData);
                }

                //корректируем фиксапы
                if (poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
                {
                    PIMAGE_BASE_RELOCATION lpReloc=(PIMAGE_BASE_RELOCATION) RVATOVA(poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,lpNewBase);
                    ProcessRelocations(lpNewBase,(ULONG_PTR)lpNewBase-(ULONG_PTR)poh->ImageBase,poh,lpReloc);
                }

                //обрабатываем tls
                if (poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
                {
                    PIMAGE_TLS_DIRECTORY lpTlsDir=(PIMAGE_TLS_DIRECTORY)&lpNewBase[poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress];
                    ULONG_PTR **lppArray=(ULONG_PTR **)&lpNewBase[lpTlsDir->AddressOfCallBacks];
                    if (*lppArray)
                    {
                        while (*lppArray)
                        {
                            *lppArray=(ULONG_PTR*)(*lppArray-(ULONG_PTR)poh->ImageBase+(ULONG_PTR)lpNewBase);
                            lppArray++;
                        }
                    }

                    if (lpTlsDir->AddressOfIndex)
                    {
                        lpTlsDir->AddressOfIndex=(ULONG_PTR)lpTlsDir->AddressOfIndex-(ULONG_PTR)poh->ImageBase+(ULONG_PTR)lpNewBase;
                        if (!IsBadWritePtr((LPVOID)lpTlsDir->AddressOfIndex,sizeof(DWORD)))
                            *(LPDWORD)lpTlsDir->AddressOfIndex=TlsAlloc();
                    }
                }

                bool bOk=true;
                //обрабатываем импорт
                if (poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
                    bOk=(ProcessImports(lpNewBase,poh) != FALSE);

                if (bOk)
                {
                    PIMAGE_OPTIONAL_HEADER new_poh=(PIMAGE_OPTIONAL_HEADER)(((DWORD_PTR)poh-(DWORD_PTR)lpMem)+(DWORD_PTR)lpNewBase);
                    new_poh->ImageBase=(ULONG_PTR)lpNewBase;

                    #ifndef _X86_
                        ldr_BuildExeceptionsTable(new_poh,lpNewBase);
                    #endif

                    if (poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
                    {
                        PIMAGE_TLS_DIRECTORY lpTlsDir=(PIMAGE_TLS_DIRECTORY)&lpNewBase[poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress];
                        PIMAGE_TLS_CALLBACK *lppCallback=(PIMAGE_TLS_CALLBACK *)&lpNewBase[lpTlsDir->AddressOfCallBacks];
                        if (*lppCallback)
                        {
                            while (*lppCallback)
                            {
                                (*lppCallback)((LPVOID)lpNewBase,DLL_PROCESS_ATTACH,NULL);
                                lppCallback++;
                            }
                        }
                    }

                    if (poh->AddressOfEntryPoint)
                    {
                        if (pfh->Characteristics & IMAGE_FILE_DLL)
                        {
                            _DllEntry lpDllEntry=(_DllEntry)&lpNewBase[poh->AddressOfEntryPoint];
                            if (lpDllEntry)
                                bOk=lpDllEntry((HINSTANCE)lpNewBase,DLL_PROCESS_ATTACH,NULL);
                        }
                        else
                        {
                            _EntryPoint lpEntryPoint=(_EntryPoint)&lpNewBase[poh->AddressOfEntryPoint];
                            SysCloseHandle(CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)lpEntryPoint,NULL,0,NULL));
                        }
                    }
                    hImage=(HMODULE)lpNewBase;

                    #ifndef _X86_
                    ldr_BuildExeceptionsTable(poh,lpNewBase);
                    #endif

                    SysInitExceptions();
                }

                if (!bOk)
                {
                    VirtualFree(lpNewBase,0,MEM_RELEASE);
                    hImage=NULL;
                }
            }
        }
    }
    return hImage;
}

SYSLIBFUNC(BOOL) ldr_FreeImage(HMODULE hImage)
{
    BOOL bRet=false;
    if ((hImage) && (ldr_CheckPE((LPBYTE)hImage,1024)))
    {
        PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)hImage;
        PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((ULONG_PTR)hImage+dos->e_lfanew+4);
        if ((pfh->TimeDateStamp == 0xDEAD) && (pfh->PointerToSymbolTable == 0xDEAD))
        {
            LPBYTE lpBase=(LPBYTE)hImage;

            // если dll - оповещаем о выгрузке
            PIMAGE_OPTIONAL_HEADER poh=(PIMAGE_OPTIONAL_HEADER)(pfh+1);
            if (poh->AddressOfEntryPoint)
            {
                if (pfh->Characteristics & IMAGE_FILE_DLL)
                {
                    _DllEntry lpDllEntry=(_DllEntry)&lpBase[poh->AddressOfEntryPoint];
                    if (lpDllEntry)
                        lpDllEntry(hImage,DLL_PROCESS_DETACH,NULL);
                }
            }

            // выгружаем библиотеки
            if (poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
            {
                PIMAGE_IMPORT_DESCRIPTOR lpImport=(PIMAGE_IMPORT_DESCRIPTOR)&lpBase[poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress];
                for (; lpImport->Name; lpImport++)
                {
                    HMODULE hDll=GetModuleHandleA((LPCSTR) &lpBase[lpImport->Name]);
                    if (hDll)
                        FreeLibrary(hDll);
                }
            }
            VirtualFree(hImage,0,MEM_RELEASE);
            bRet=true;
        }
    }
    return bRet;
}

SYSLIBFUNC(BOOL) ldr_CheckPE(LPBYTE lpMem,DWORD dwMemSize)
{
    BOOL bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckParamRead(lpMem,ALIGN(sizeof(IMAGE_NT_HEADERS32)+sizeof(IMAGE_DOS_HEADER),1024)))
            break;

        if (dwMemSize <= sizeof(IMAGE_NT_HEADERS32)+sizeof(IMAGE_DOS_HEADER))
            break;

        WORD tmp='ZM'^0x3030;
        tmp^=0x3030;

        IMAGE_DOS_HEADER *lpDosHdr=(IMAGE_DOS_HEADER*)lpMem;
        if (lpDosHdr->e_magic != tmp)
            break;

        if (lpDosHdr->e_lfanew < sizeof(WORD))
            break;

        if (lpDosHdr->e_lfanew >= dwMemSize-sizeof(IMAGE_NT_HEADERS32))
            break;

        tmp='EP'^0x3030;
        tmp^=0x3030;

        byte *lpOffset=lpMem+lpDosHdr->e_lfanew;
        if (((IMAGE_NT_HEADERS32 *)lpOffset)->Signature != tmp)
            break;

        byte *lpEnd=lpMem+dwMemSize;
        IMAGE_NT_HEADERS32 *lpNtHdr=(IMAGE_NT_HEADERS32*)lpOffset;
        if (lpNtHdr->FileHeader.SizeOfOptionalHeader >= (DWORD)(lpEnd-(lpOffset+sizeof(IMAGE_FILE_HEADER)+sizeof(DWORD))))
            break;

        DWORD dwFileAligment=0,dwVirtualAligment=0;
        switch (lpNtHdr->FileHeader.Machine)
        {
            case IMAGE_FILE_MACHINE_I386:
            {
                if (lpNtHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                    break;
                dwFileAligment=lpNtHdr->OptionalHeader.FileAlignment;
                dwVirtualAligment=lpNtHdr->OptionalHeader.SectionAlignment;
                break;
            }
            case IMAGE_FILE_MACHINE_AMD64:
            {
                IMAGE_NT_HEADERS64 *lpNt64Hdr=(IMAGE_NT_HEADERS64*)lpNtHdr;
                if (lpDosHdr->e_lfanew >= dwMemSize-sizeof(IMAGE_NT_HEADERS64))
                    break;
                if (lpNt64Hdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                    break;
                dwFileAligment=lpNt64Hdr->OptionalHeader.FileAlignment;
                dwVirtualAligment=lpNt64Hdr->OptionalHeader.SectionAlignment;
                break;
            }
        }

        if ((dwFileAligment > MAX_FILE_ALIGMENT) || (dwFileAligment < MIN_FILE_ALIGMENT))
            break;
        if ((dwVirtualAligment > MAX_VIRTUAL_ALIGMENT) || (dwVirtualAligment < MIN_VIRTUAL_ALIGMENT))
            break;
        if (dwVirtualAligment < dwFileAligment)
            break;
        if ((dwFileAligment%2 != 0) || (dwVirtualAligment%2 != 0))
            break;

        bRet=true;
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) ldr_CheckFileW(LPCWSTR lpFileName)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFileName,MAX_PATH))
        return false;

    BOOL bRet=false;
    HANDLE hFile=CreateFileW(lpFileName,GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,NULL);
        if (hMapping)
        {
            byte *lpMap=(byte*)MapViewOfFile(hMapping,FILE_MAP_READ,0,0,0);
            if (lpMap)
            {
                bRet=ldr_CheckPE(lpMap,GetFileSize(hFile,NULL));
                UnmapViewOfFile(lpMap);
            }
            SysCloseHandle(hMapping);
        }
        SysCloseHandle(hFile);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) ldr_CheckFileA(LPCSTR lpFileName)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFileName,0,NULL);

    BOOL bRet=ldr_CheckFileW(lpFileNameW);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(BOOL) ldr_IsModuleContainAddress(HINSTANCE hModule,LPVOID lpAddress)
{
    return SysIsPtrInside((LPVOID)hModule,lpAddress);
}

SYSLIBFUNC(LPVOID) ldr_GetEntryPoint(HINSTANCE hModule)
{
    LPVOID lpEntry=NULL;
    do
    {
        if (!ldr_CheckPE((LPBYTE)hModule,1024))
            break;

        PIMAGE_DOS_HEADER lpDosHdr=(PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS lpHdrs=(PIMAGE_NT_HEADERS)((LPBYTE)hModule+lpDosHdr->e_lfanew);

        switch (lpHdrs->FileHeader.Machine)
        {
            case IMAGE_FILE_MACHINE_I386:
            {
                lpEntry=(LPVOID)((PIMAGE_NT_HEADERS32)lpHdrs)->OptionalHeader.AddressOfEntryPoint;
                break;
            }
            case IMAGE_FILE_MACHINE_AMD64:
            {
                lpEntry=(LPVOID)((PIMAGE_NT_HEADERS64)lpHdrs)->OptionalHeader.AddressOfEntryPoint;
                break;
            }
        }

        if (!lpEntry)
            break;

        lpEntry=(LPVOID)((DWORD_PTR)hModule+(DWORD_PTR)lpEntry);
    }
    while (false);
    return lpEntry;
}

SYSLIBEXP(HMODULE) ldr_LoadImageFromFileW(LPCWSTR lpFileName)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFileName,MAX_PATH))
        return NULL;

    HMODULE hModule=NULL;
    HANDLE hFile=CreateFileW(lpFileName,GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,NULL);
        if (hMapping)
        {
            byte *lpMap=(byte*)MapViewOfFile(hMapping,FILE_MAP_READ,0,0,0);
            if (lpMap)
            {
                hModule=ldr_LoadImageFromMemory(lpMap);
                UnmapViewOfFile(lpMap);
            }
            SysCloseHandle(hMapping);
        }
        SysCloseHandle(hFile);
    }
    return hModule;
}


SYSLIBEXP(HMODULE) ldr_LoadImageFromFileA(LPCSTR lpFileName)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFileName,0,NULL);

    HMODULE hModule=ldr_LoadImageFromFileW(lpFileNameW);

    MemFree(lpFileNameW);
    return hModule;
}

