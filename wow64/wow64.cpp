#include "sys_includes.h"

#include "wow64.h"
#include "wow64ext.h"
#include "syslib\strcrypt.h"
#include "syslib\debug.h"
#include "syslib\system.h"
#include "syslib\mem.h"
#include "syslib\str.h"
#include "ldr\ldr.h"
#include "system\system.h"

#include "stdint.h"
#include "hooks\hde64\hde64.h"
#include "hooks\hde32\hde32.h"

#include "str_crx.h"

SYSLIBFUNC(DWORD64) X64Call(DWORD64 func,int nArgc, ...)
{
    va_list args;
	DWORD64 arg1, arg2, arg3, arg4, _nArgc, _lvpFunctionPtr, rest;
	DWORD dwEspBackup;
	union reg64 sRax;

	va_start( args, nArgc );
	arg1 = ( nArgc ) ? nArgc--, va_arg( args, DWORD64 ) : 0;
	arg2 = ( nArgc ) ? nArgc--, va_arg( args, DWORD64 ) : 0;
	arg3 = ( nArgc ) ? nArgc--, va_arg( args, DWORD64 ) : 0;
	arg4 = ( nArgc ) ? nArgc--, va_arg( args, DWORD64 ) : 0;

	rest = (DWORD64)&va_arg( args, DWORD64 );

	_nArgc = nArgc;
	_lvpFunctionPtr = func;
	sRax.v = 0;
	__asm {
		mov dwEspBackup, esp
		and sp, 0xFFF8
		X64_Start();
		push arg1
		X64_Pop(_RCX);
		push arg2
		X64_Pop(_RDX);
		push arg3
		X64_Pop(_R8);
		push arg4
		X64_Pop(_R9);

		push   edi
		push   rest
		X64_Pop(_RDI);
		push   _nArgc
		X64_Pop(_RAX);
		test   eax, eax
		jz     _ls_e
		lea    edi, dword ptr [edi + 8*eax - 8]
	_ls:
		test   eax, eax
		jz     _ls_e
		push   dword ptr [edi]
		sub    edi, 8
		sub    eax, 1
		jmp    _ls
	_ls_e:
		sub    esp, 0x20
		call   _lvpFunctionPtr
		push   _nArgc
		X64_Pop(_RCX);
		lea    esp, dword ptr [esp + 8*ecx + 0x20]
		pop    edi
		X64_Push(_RAX);
		pop    sRax.dw[0]
		X64_End();
		mov    esp, dwEspBackup
	}
	return sRax.v;
}

static DWORD64 GetModuleHandle64Int()
{
    reg64 lpHead,lpLdr;
    _asm
    {
        X64_Push(_RSI)
        X64_Push(_RDI)

        X64_Push(_RCX)
        X64_Pop(_RDI)

        EMIT(0x65) EMIT(0x48) EMIT(0x8b) EMIT(0x04) EMIT(0x25) EMIT(0x60) EMIT(0x00) EMIT(0x00) EMIT(0x00) /** mov     rax, qword ptr gs:0x60 **/
        EMIT(0x48) EMIT(0x8B) EMIT(0x40) EMIT(0x18)                                                        /** mov     rax, [rax+18h],  PEB64->Ldr **/
        EMIT(0x48) EMIT(0x8B) EMIT(0x50) EMIT(0x10)                                                        /** mov     rdx, [rax+10h],  PEB_LDR_DATA->InLoadOrderModuleList **/
        X64_Push(_RDX)
        pop lpHead.dw[0]
        X64_Push(_RDX)
        pop lpLdr.dw[0]

_do:    EMIT(0x48) EMIT(0x8B) EMIT(0x42) EMIT(0x30)                                                        /** mov     rax, [rdx+30h],  LDR_DATA_TABLE_ENTRY->DllBase **/
        EMIT(0x48) EMIT(0x85) EMIT(0xC0)                                                                   /** test    rax, rax **/
        je _end
        EMIT(0x48) EMIT(0x0F) EMIT(0xB7) EMIT(0x4A) EMIT(0x58)                                             /** movzx   rcx, word ptr [rdx+58h],  LDR_DATA_TABLE_ENTRY->BaseDllName.Length **/
        EMIT(0x48) EMIT(0x8B) EMIT(0x72) EMIT(0x60)                                                        /** mov     rsi, [rdx+60h],  LDR_DATA_TABLE_ENTRY->BaseDllName.Buffer **/
        EMIT(0x48) EMIT(0x29) EMIT(0xC0)                                                                   /** sub     rax, rax **/
        X64_Push(_RDI)
        repe cmpsb
        X64_Pop(_RDI)
        jne _while
        push lpHead.dw[0]
        X64_Pop(_RAX)
        EMIT(0x48) EMIT(0x8B) EMIT(0x40) EMIT(0x30)                                                        /** mov     rax, [rax+30h],  LDR_DATA_TABLE_ENTRY->DllBase **/
        jmp _end

_while: push lpHead.dw[0]
        X64_Pop(_RCX)
        EMIT(0x48) EMIT(0x8B) EMIT(0x11)                                                                   /** mov     rdx, [rcx],  LDR_DATA_TABLE_ENTRY->Flink **/
        X64_Push(_RDX)
        pop lpHead.dw[0]
        push lpLdr.dw[0]
        X64_Pop(_RAX)
        EMIT(0x48) EMIT(0x39) EMIT(0xC2)                                                                   /** cmp     rdx, rax **/
        jne _do

        EMIT(0x48) EMIT(0x29) EMIT(0xC0)                                                                   /** sub     rax, rax **/

_end:   X64_Pop(_RDI)
        X64_Pop(_RSI)
    }
}

SYSLIBFUNC(DWORD64) GetModuleHandle64(LPCWSTR lpModuleName)
{
    reg64 sRax={0};
	DWORD64 lpModule=(DWORD64)lpModuleName;
    DWORD dwEspBackup;
    _asm
    {
		mov dwEspBackup,esp
		and sp,0xFFF8
        X64_Start();

        push lpModule
        X64_Pop(_RCX)
        call GetModuleHandle64Int
        X64_Push(_RAX)
        pop sRax.dw[0]

		X64_End();
		mov esp,dwEspBackup
    }
    return sRax.v;
}

static __declspec(naked) DWORD64 GetProcAddress64Int()
{
    _asm
    {
        EMIT(0x48) EMIT(0x89) EMIT(0x5C) EMIT(0x24) EMIT(0x08)                          /** mov     [rsp+arg_0], rbx **/
        EMIT(0x48) EMIT(0x89) EMIT(0x74) EMIT(0x24) EMIT(0x10)                          /** mov     [rsp+arg_8], rsi **/
        EMIT(0x48) EMIT(0x89) EMIT(0x7C) EMIT(0x24) EMIT(0x18)                          /** mov     [rsp+arg_10], rdi **/
        EMIT(0x48) EMIT(0x63) EMIT(0x41) EMIT(0x3C)                                     /** movsxd  rax, dword ptr [rcx+3Ch] **/
        EMIT(0x4C) EMIT(0x8B) EMIT(0xD1)                                                /** mov     r10, rcx **/
        EMIT(0x45) EMIT(0x33) EMIT(0xC0)                                                /** xor     r8d, r8d **/
        EMIT(0x8B) EMIT(0x8C) EMIT(0x08) EMIT(0x88) EMIT(0x00) EMIT(0x00) EMIT(0x00)    /** mov     ecx, [rax+rcx+88h] **/
        EMIT(0x85) EMIT(0xC9)                                                           /** test    ecx, ecx **/
        jz loc_9E
        EMIT(0x48) EMIT(0x8B) EMIT(0xC2)                                                /** mov     rax, rdx **/
        EMIT(0x4D) EMIT(0x8D) EMIT(0x0C) EMIT(0x0A)                                     /** lea     r9, [r10+rcx] **/
        EMIT(0x48) EMIT(0xC1) EMIT(0xE8) EMIT(0x10)                                     /** shr     rax, 10h **/
        EMIT(0x66) EMIT(0x85) EMIT(0xC0)                                                /** test    ax, ax **/
        jnz loc_3D
        EMIT(0x0F) EMIT(0xB7) EMIT(0xCA)                                                /** movzx   ecx, dx **/
        EMIT(0x41) EMIT(0x2B) EMIT(0x49) EMIT(0x10)                                     /** sub     ecx, [r9+10h] **/
        jmp loc_8B

loc_3D: EMIT(0x41) EMIT(0x8B) EMIT(0xC8)                                                /** mov     ecx, r8d **/
        EMIT(0x45) EMIT(0x39) EMIT(0x41) EMIT(0x18)                                     /** cmp     [r9+18h], r8d **/
        jbe loc_9E
        EMIT(0x41) EMIT(0x8B) EMIT(0x41) EMIT(0x20)                                     /** mov     eax, [r9+20h] **/
        EMIT(0x49) EMIT(0x03) EMIT(0xC2)                                                /** add     rax, r10 **/

loc_4D:
        EMIT(0x44) EMIT(0x8B) EMIT(0x18)                                                /** mov     r11d, [rax] **/
        EMIT(0x48) EMIT(0x8B) EMIT(0xF2)                                                /** mov     rsi, rdx **/
        EMIT(0x4D) EMIT(0x03) EMIT(0xDA)                                                /** add     r11, r10 **/
        EMIT(0x49) EMIT(0x2B) EMIT(0xF3)                                                /** sub     rsi, r11 **/

loc_59: EMIT(0x41) EMIT(0x0F) EMIT(0xB6) EMIT(0x1B)                                     /** movzx   ebx, byte ptr [r11] **/
        EMIT(0x41) EMIT(0x0F) EMIT(0xB6) EMIT(0x3C) EMIT(0x33)                          /** movzx   edi, byte ptr [r11+rsi] **/
        EMIT(0x2B) EMIT(0xDF)                                                           /** sub     ebx, edi **/
        jnz loc_6D
        EMIT(0x49) EMIT(0xFF) EMIT(0xC3)                                                /** inc     r11 **/
        EMIT(0x85) EMIT(0xFF)                                                           /** test    edi, edi **/
        jnz loc_59

loc_6D: EMIT(0x85) EMIT(0xDB)                                                           /** test    ebx, ebx **/
        jz loc_7F
        EMIT(0xFF) EMIT(0xC1)                                                           /** inc     ecx **/
        EMIT(0x48) EMIT(0x83) EMIT(0xC0) EMIT(0x04)                                     /** add     rax, 4 **/
        EMIT(0x41) EMIT(0x3B) EMIT(0x49) EMIT(0x18)                                     /** cmp     ecx, [r9+18h] **/
        jb loc_4D
        jmp loc_9E

loc_7F: EMIT(0x41) EMIT(0x8B) EMIT(0x41) EMIT(0x24)                                     /** mov     eax, [r9+24h] **/
        EMIT(0x8D) EMIT(0x0C) EMIT(0x48)                                                /** lea     ecx, [rax+rcx*2] **/
        EMIT(0x42) EMIT(0x0F) EMIT(0xB7) EMIT(0x0C) EMIT(0x11)                          /** movzx   ecx, word ptr [rcx+r10] **/

loc_8B: EMIT(0x83) EMIT(0xF9) EMIT(0xFF)                                                /** cmp     ecx, 0FFFFFFFFh **/
        jz loc_9E
        EMIT(0x41) EMIT(0x8B) EMIT(0x41) EMIT(0x1C)                                     /** mov     eax, [r9+1Ch] **/
        EMIT(0x49) EMIT(0x03) EMIT(0xC2)                                                /** add     rax, r10 **/
        EMIT(0x44) EMIT(0x8B) EMIT(0x04) EMIT(0x88)                                     /** mov     r8d, [rax+rcx*4] **/
        EMIT(0x4D) EMIT(0x03) EMIT(0xC2)                                                /** add     r8, r10 **/

loc_9E: EMIT(0x48) EMIT(0x8B) EMIT(0x5C) EMIT(0x24) EMIT(0x08)                          /** mov     rbx, [rsp+arg_0] **/
        EMIT(0x48) EMIT(0x8B) EMIT(0x74) EMIT(0x24) EMIT(0x10)                          /** mov     rsi, [rsp+arg_8] **/
        EMIT(0x48) EMIT(0x8B) EMIT(0x7C) EMIT(0x24) EMIT(0x18)                          /** mov     rdi, [rsp+arg_10] **/
        EMIT(0x49) EMIT(0x8B) EMIT(0xC0)                                                /** mov     rax, r8 **/
        EMIT(0xC3)                                                                      /** retn **/
    }
}

SYSLIBFUNC(DWORD64) GetProcAddress64(DWORD64 hModule,LPCSTR lpFuncName)
{
    reg64 sRax;
	DWORD64 lpBaseAddr=hModule,
            lpName=(DWORD64)lpFuncName;
    DWORD dwEspBackup;
    _asm
    {
		mov dwEspBackup,esp
		and sp, 0xFFF8
        X64_Start();

        push lpBaseAddr
        X64_Pop(_RCX)
        push lpName
        X64_Pop(_RDX)
		sub esp, 0x20
        call GetProcAddress64Int
		add esp, 0x20
        X64_Push(_RAX)
        pop sRax.dw[0]

		X64_End();
		mov esp,dwEspBackup
    }
    return sRax.v;
}

static NTSTATUS NotifyCSRSS(DWORD64 hThread,CLIENT_ID64 *lpId)
{
    DWORD64 lpNtDll=GetModuleHandle64(dcrW_91764d8a("ntdll.dll")),
            lpCsrClientCallServer=GetProcAddress64(lpNtDll,dcrA_5f694e87("CsrClientCallServer"));

    __declspec(align(16))
    BASE_API_MSG64 CsrRequest={0};
    CsrRequest.u.CreateThreadRequest.ClientId=*lpId;
    CsrRequest.u.CreateThreadRequest.ThreadHandle=hThread;
    return (NTSTATUS)X64Call(lpCsrClientCallServer,4,(DWORD64)&CsrRequest,(DWORD64)0,(DWORD64)0x10001,(DWORD64)(sizeof(CsrRequest.u.CreateThreadRequest)));
}

static bool IsWin8()
{
    OSVERSIONINFO osvi;
    osvi.dwOSVersionInfoSize=sizeof(osvi);
    GetVersionEx(&osvi);
    return ((osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion > 1));
}

SYSLIBFUNC(HANDLE) CreateRemoteThread64(HANDLE hProcess,DWORD64 lpStartAddress,DWORD64 lpParameter)
{
    DWORD64 lpNtDll=GetModuleHandle64(dcrW_91764d8a("ntdll.dll")),
            lpRtlCreateUserThread=GetProcAddress64(lpNtDll,dcrA_7e0ee6ed("RtlCreateUserThread"));

    __declspec(align(16))
    DWORD64 hThread;
    CLIENT_ID64 id;
    NTSTATUS dwRet=(NTSTATUS)X64Call(lpRtlCreateUserThread,10,(DWORD64)hProcess,(DWORD64)0,(DWORD64)TRUE,(DWORD64)0,(DWORD64)0,(DWORD64)0,lpStartAddress,lpParameter,(DWORD64)&hThread,(DWORD64)&id);
    if (NT_SUCCESS(dwRet))
    {
        if (!IsWin8())
            dwRet=NotifyCSRSS(hThread,&id);

        if (NT_SUCCESS(dwRet))
        {
            DWORD64 lpNtResumeThread=GetProcAddress64(lpNtDll,dcrA_446aed9e("NtResumeThread"));

            X64Call(lpNtResumeThread,2,hThread,(DWORD64)0);
        }
        else
        {
            DWORD64 lpNtTerminateThread=GetProcAddress64(lpNtDll,dcrA_7d2236d1("NtTerminateThread")),
                    lpNtClose=GetProcAddress64(lpNtDll,dcrA_7ff70ae3("NtClose"));

            X64Call(lpNtTerminateThread,2,hThread,(DWORD64)0);
            X64Call(lpNtClose,1,hThread);
            hThread=NULL;
        }
    }
    return (HANDLE)hThread;
}

SYSLIBFUNC(DWORD64) VirtualAllocEx64(HANDLE hProcess,DWORD64 lpAddress,SIZE_T dwSize,DWORD flAllocationType,DWORD flProtect)
{
    DWORD64 lpNtDll=GetModuleHandle64(dcrW_91764d8a("ntdll.dll")),
            lpNtAllocateVirtualMemory=GetProcAddress64(lpNtDll,dcrA_ced7e31f("NtAllocateVirtualMemory"));

    __declspec(align(16))
	DWORD64 dwTmpAddr=lpAddress,
            dwTmpSize=dwSize;
    NTSTATUS dwRet=(NTSTATUS)X64Call(lpNtAllocateVirtualMemory,6,(DWORD64)hProcess,(DWORD64)&dwTmpAddr,(DWORD64)0,(DWORD64)&dwTmpSize,(DWORD64)flAllocationType,(DWORD64)flProtect);
    if (!NT_SUCCESS(dwRet))
        dwTmpAddr=NULL;
    return dwTmpAddr;
}

SYSLIBFUNC(BOOL) VirtualFreeEx64(HANDLE hProcess,DWORD64 lpAddress,SIZE_T dwSize,DWORD dwFreeType)
{
    DWORD64 lpNtDll=GetModuleHandle64(dcrW_91764d8a("ntdll.dll")),
            lpNtFreeVirtualMemory=GetProcAddress64(lpNtDll,dcrA_04aa2948("NtFreeVirtualMemory"));

    __declspec(align(16))
	DWORD64 dwTmpAddr=lpAddress,
            dwTmpSize=dwSize;
	return NT_SUCCESS((NTSTATUS)X64Call(lpNtFreeVirtualMemory,4,(DWORD64)hProcess,(DWORD64)&dwTmpAddr,(DWORD64)&dwTmpSize,(DWORD64)dwFreeType));
}

SYSLIBFUNC(BOOL) WriteProcessMemory64(HANDLE hProcess,DWORD64 lpBaseAddress,LPVOID lpBuffer,SIZE_T nSize,DWORD64 *lpNumberOfBytesWritten)
{
    DWORD64 lpNtDll=GetModuleHandle64(dcrW_91764d8a("ntdll.dll")),
            lpNtWriteVirtualMemory=GetProcAddress64(lpNtDll,dcrA_b2036547("NtWriteVirtualMemory"));
	return NT_SUCCESS((NTSTATUS)X64Call(lpNtWriteVirtualMemory,5,(DWORD64)hProcess,lpBaseAddress,(DWORD64)lpBuffer,(DWORD64)nSize,(DWORD64)lpNumberOfBytesWritten));
}

SYSLIBFUNC(BOOL) ReadProcessMemory64(HANDLE hProcess,DWORD64 lpBaseAddress,LPVOID lpBuffer,SIZE_T nSize,DWORD64 *lpNumberOfBytesRead)
{
    DWORD64 lpNtDll=GetModuleHandle64(dcrW_91764d8a("ntdll.dll")),
            lpNtReadVirtualMemory=GetProcAddress64(lpNtDll,dcrA_f1cebbac("NtReadVirtualMemory"));
	return NT_SUCCESS((NTSTATUS)X64Call(lpNtReadVirtualMemory,5,(DWORD64)hProcess,lpBaseAddress,(DWORD64)lpBuffer,(DWORD64)nSize,(DWORD64)lpNumberOfBytesRead));
}

SYSLIBFUNC(NTSTATUS) NtQueryInformationProcess64(HANDLE ProcessHandle,DWORD ProcessInformationClass,LPVOID ProcessInformation,SIZE_T ProcessInformationLength,DWORD64 *ReturnLength)
{
    DWORD64 lpNtDll=GetModuleHandle64(dcrW_91764d8a("ntdll.dll")),
            lpNtQueryInformationProcess=GetProcAddress64(lpNtDll,dcrA_506aa97b("NtQueryInformationProcess"));
	return (NTSTATUS)X64Call(lpNtQueryInformationProcess,5,(DWORD64)ProcessHandle,(DWORD64)ProcessInformationClass,(DWORD64)ProcessInformation,(DWORD64)ProcessInformationLength,(DWORD64)ReturnLength);
}

SYSLIBFUNC(NTSTATUS) NtMapViewOfSection64(HANDLE SectionHandle,HANDLE ProcessHandle,DWORD64 *BaseAddress,DWORD64 ZeroBits,DWORD64 CommitSize,PLARGE_INTEGER SectionOffset,DWORD64 *ViewSize,ULONG InheritDisposition,ULONG AllocationType,ULONG Protect)
{
    DWORD64 lpNtDll=GetModuleHandle64(dcrW_91764d8a("ntdll.dll")),
            lpNtMapViewOfSection=GetProcAddress64(lpNtDll,dcrA_e08a0291("NtMapViewOfSection"));
	return (NTSTATUS)X64Call(lpNtMapViewOfSection,10,(DWORD64)SectionHandle,(DWORD64)ProcessHandle,(DWORD64)BaseAddress,ZeroBits,CommitSize,(DWORD64)SectionOffset,(DWORD64)ViewSize,(DWORD64)InheritDisposition,(DWORD64)AllocationType,(DWORD64)Protect);
}

SYSLIBFUNC(NTSTATUS) NtUnmapViewOfSection64(HANDLE ProcessHandle,DWORD64 BaseAddress)
{
    DWORD64 lpNtDll=GetModuleHandle64(dcrW_91764d8a("ntdll.dll")),
            lpNtUnmapViewOfSection=GetProcAddress64(lpNtDll,dcrA_de1f1c3e("NtUnmapViewOfSection"));
	return (NTSTATUS)X64Call(lpNtUnmapViewOfSection,2,(DWORD64)ProcessHandle,BaseAddress);
}

SYSLIBFUNC(BOOL) SysWow64DisableWow64FsRedirection(PVOID *OldValue)
{
    BOOL bRet=false;
    if (SysIsWow64())
    {
        __Wow64DisableWow64FsRedirection *lpWow64DisableWow64FsRedirection=(__Wow64DisableWow64FsRedirection*)GetProcAddress(GetModuleHandle(dcr_30884675("kernel32.dll")),dcrA_6f8ccbfb("Wow64DisableWow64FsRedirection"));
        if (lpWow64DisableWow64FsRedirection)
            bRet=(lpWow64DisableWow64FsRedirection(OldValue) != FALSE);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) SysWow64RevertWow64FsRedirection(PVOID OldValue)
{
    BOOL bRet=false;
    if (SysIsWow64())
    {
        __Wow64RevertWow64FsRedirection *lpWow64RevertWow64FsRedirection=(__Wow64RevertWow64FsRedirection*)GetProcAddress(GetModuleHandle(dcr_30884675("kernel32.dll")),dcrA_f47eaad5("Wow64RevertWow64FsRedirection"));
        if (lpWow64RevertWow64FsRedirection)
            bRet=(lpWow64RevertWow64FsRedirection(OldValue) != FALSE);
    }
    return bRet;
}

static LPVOID GetWow64ProcAddress(HMODULE lpImg,LPCSTR lpProcName)
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
        if (pfh->Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            PIMAGE_OPTIONAL_HEADER64 poh=(PIMAGE_OPTIONAL_HEADER64)(pfh+1);
            if (poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
            {
                PIMAGE_EXPORT_DIRECTORY lpExport=(PIMAGE_EXPORT_DIRECTORY)&buf[poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress];

                ULONG *lpFunctions=(ULONG*)RVATOVA(lpImg,lpExport->AddressOfFunctions),
                      *lpNames=(ULONG*)RVATOVA(lpImg,lpExport->AddressOfNames);
                WORD *lpOrds=(WORD*)RVATOVA(lpImg,lpExport->AddressOfNameOrdinals);

                for (DWORD i=0; i < lpExport->NumberOfNames; i++)
                {
                    if (!lstrcmpA(lpProcName,(char*)RVATOVA(lpImg,lpNames[i])))
                    {
                        lpRet=(void*)RVATOVA(lpImg,lpFunctions[lpOrds[i]]);
                        break;
                    }
                }
            }
        }
    }
    return lpRet;
}

static HMODULE PrepareImage64(byte *lpMem)
{
    HMODULE hImage=NULL;
    if (lpMem)
    {
        PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)lpMem;
        PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((ULONG_PTR)lpMem+dos->e_lfanew+4);

        if (pfh->Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            PIMAGE_OPTIONAL_HEADER64 poh=(PIMAGE_OPTIONAL_HEADER64)(pfh+1);
            PIMAGE_SECTION_HEADER psh=(PIMAGE_SECTION_HEADER)((ULONG_PTR)poh+sizeof(*poh));

            byte *lpNewBase=(byte*)VirtualAlloc(NULL,poh->SizeOfImage,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
            if (lpNewBase)
            {
                memcpy(lpNewBase,lpMem,psh->PointerToRawData); //копируем хидеры
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
                    DWORD dwSize=poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                    DWORD64 dwNewOffset=(DWORD64)lpNewBase-(DWORD64)poh->ImageBase;
                    u_int i=0;
                    while (i < dwSize)
                    {
                        for (PIMAGE_FIXUP_ENTRY lpFixup=(PIMAGE_FIXUP_ENTRY)((ULONG_PTR)lpReloc+sizeof(IMAGE_BASE_RELOCATION)); (ULONG_PTR)lpFixup < (ULONG_PTR)lpReloc+lpReloc->SizeOfBlock; lpFixup++)
                        {
                            if (lpFixup->Type == IMAGE_REL_BASED_DIR64)
                            {
                                DWORD64 *pFixup=(DWORD64 *)RVATOVA(lpReloc->VirtualAddress+lpFixup->Offset,lpNewBase);
                                *pFixup+=dwNewOffset;
                            }
                        }
                        i+=lpReloc->SizeOfBlock;
                        *(ULONG_PTR*)&lpReloc+=lpReloc->SizeOfBlock;
                    }
                }

                hImage=(HMODULE)lpNewBase;
            }
        }
    }
    return hImage;
}

static DWORD64 *Get_SharedInfo()
{
    DWORD64 *lpShared=NULL;
    byte *lpUserRegisterWowHandlers=(byte*)GetProcAddress(GetModuleHandle(dcr_f16654e2("user32.dll")),dcrA_2e52d91e("UserRegisterWowHandlers"));

    for (int i=0; i <= 0x1000; )
    {
        hde32s hs;
        i+=hde32_disasm(&lpUserRegisterWowHandlers[i],&hs);

        if ((hs.flags & F_ERROR) == F_ERROR)
            break;

        if ((!(hs.flags & F_SIB)) && (!hs.modrm_reg) && (hs.flags & F_IMM32) && (hs.opcode == 0xB8)) /// mov eax,mem32
        {
            lpShared=(DWORD64*)hs.imm.imm32;
            break;
        }
    }

    return lpShared;
}

static bool Prepare_gSharedInfoPtr(HMODULE hUser64)
{
    bool bRet=false;
    DWORD64 *lpShared=Get_SharedInfo();
    if (lpShared)
    {
        byte *lpGetMenuItemCount=(byte*)GetWow64ProcAddress(hUser64,dcrA_4e448e6b("GetMenuItemCount")),
             *pHMValidateHandle=lpGetMenuItemCount;
        for (int i=0; i <= 20; )
        {
            hde64s hs;
            i+=hde64_disasm(&pHMValidateHandle[i],&hs);

            if ((hs.flags & F_ERROR) == F_ERROR)
                break;

            if ((hs.flags & F_IMM32) && (hs.opcode == 0xE8)) // call
            {
                pHMValidateHandle=(byte*)((DWORD)&pHMValidateHandle[i]+hs.len+hs.imm.imm32);
                break;
            }
        }

        if (pHMValidateHandle != lpGetMenuItemCount)
        {
            DWORD64 *gpsi=NULL;
            for (int i=0; i <= 50; )
            {
                hde64s hs;
                i+=hde64_disasm(&pHMValidateHandle[i],&hs);

                if ((hs.flags & F_ERROR) == F_ERROR)
                    break;

                if ((hs.flags & F_MODRM) && (!(hs.flags & F_SIB)) && (!hs.modrm_reg) /**&& (hs.flags & F_DISP32)**/ && (hs.opcode == 0x8B)) /// mov rax,mem32
                {
                    gpsi=(DWORD64*)(&pHMValidateHandle[i]+hs.disp.disp32);
                    *gpsi=*lpShared;
                    break;
                }
            }

            byte *lpUserRegisterWowHandlers=(byte*)GetWow64ProcAddress(hUser64,dcrA_2e52d91e("UserRegisterWowHandlers")),
                 *lpLastLeaRax;

            for (int i=0; i <= 0x1000; )
            {
                hde64s hs;
                i+=hde64_disasm(&lpUserRegisterWowHandlers[i],&hs);

                if ((hs.flags & F_ERROR) == F_ERROR)
                    break;

                if ((hs.flags & F_MODRM) && (!(hs.flags & F_SIB)) && (!hs.modrm_reg) /**&& (hs.flags & F_DISP32)**/ && (hs.opcode == 0x8D)) /// lea rax,mem32
                {
                    lpLastLeaRax=&lpUserRegisterWowHandlers[i-hs.len];
                    continue;
                }

                if (hs.opcode == 0xC3) /// retn
                    break;
            }
            hde64s hs;
            hde64_disasm(lpLastLeaRax,&hs);
            byte *lpSharedInfo=(byte*)(&lpLastLeaRax[hs.len]+hs.disp.disp32);
            memcpy(lpSharedInfo,lpShared,0x238);
            bRet=true;
        }
    }
    return bRet;
}

static HMODULE LoadUser64()
{
    HMODULE hUser64=NULL;

    TCHAR szSysDir[MAX_PATH];
    GetSystemDirectory(szSysDir,MAX_PATH);
    TCHAR szUser64[MAX_PATH];
    StrFormat(szUser64,dcr_406b74bb("%s\\user32.dll"),szSysDir);

    LPVOID lpOld;
    SysWow64DisableWow64FsRedirection(&lpOld);

    HANDLE hFile=CreateFile(szUser64,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,NULL,NULL,NULL);
        if (hMapping)
        {
            byte *lpMap=(byte*)MapViewOfFile(hMapping,FILE_MAP_READ,NULL,NULL,NULL);
            if (lpMap)
            {
                hUser64=PrepareImage64(lpMap);
                if (hUser64)
                {
                    if (!Prepare_gSharedInfoPtr(hUser64))
                    {
                        VirtualFree(hUser64,0,MEM_RELEASE);
                        hUser64=NULL;
                    }
                }
                UnmapViewOfFile(lpMap);
            }
            SysCloseHandle(hMapping);
        }
        SysCloseHandle(hFile);
    }

    SysWow64RevertWow64FsRedirection(lpOld);
    return hUser64;
}

static void FreeUser64(HMODULE hUser64)
{
    VirtualFree(hUser64,0,MEM_RELEASE);
    return;
}

SYSLIBFUNC(DWORD64) SetWindowLongPtr64(HWND hWnd,DWORD dwIdx,DWORD64 dwNewValue)
{
    DWORD64 dwWindowLong=0;

    HMODULE hUser64=LoadUser64();
    if (hUser64)
    {
        DWORD64 dwSetWindowLongPtr64=(DWORD64)GetWow64ProcAddress(hUser64,dcrA_8aebebaf("SetWindowLongPtrA"));
        if (dwSetWindowLongPtr64)
            dwWindowLong=X64Call(dwSetWindowLongPtr64,3,(DWORD64)hWnd,(DWORD64)dwIdx,dwNewValue);

        FreeUser64(hUser64);
    }
    return dwWindowLong;
}

SYSLIBFUNC(DWORD64) GetWindowLongPtr64(HWND hWnd,DWORD dwIdx)
{
    DWORD64 dwWindowLong=0;

    HMODULE hUser64=LoadUser64();
    if (hUser64)
    {
        DWORD64 dwGetWindowLongPtr64=(DWORD64)GetWow64ProcAddress(hUser64,dcrA_16ebda44("GetWindowLongPtrA"));
        if (dwGetWindowLongPtr64)
            dwWindowLong=X64Call(dwGetWindowLongPtr64,2,(DWORD64)hWnd,(DWORD64)dwIdx);

        FreeUser64(hUser64);
    }
    return dwWindowLong;
}

SYSLIBFUNC(NTSTATUS) ZwTrueReplyWaitReceivePort(HANDLE PortHandle,PVOID *PortContext,PPORT_MESSAGE ReplyMessage,PPORT_MESSAGE ReceiveMessage)
{
    if (!SysIsWow64())
        return ZwReplyWaitReceivePort(PortHandle,PortContext,ReplyMessage,ReceiveMessage);

    MESSAGE64 *lpReply=NULL,*lpReceive=NULL;
    if (ReplyMessage)
    {
        lpReply=(MESSAGE64*)MemAlloc(sizeof(MESSAGE64));
        if (lpReply)
        {
            lpReply->hdr.u1.s1.DataLength=ReplyMessage->u1.s1.DataLength;
            lpReply->hdr.u1.s1.TotalLength=ReplyMessage->u1.s1.DataLength+sizeof(PORT_MESSAGE64);
            lpReply->hdr.u2.ZeroInit=ReplyMessage->u2.ZeroInit;
            lpReply->hdr.ClientId.UniqueProcess=(DWORD64)ReplyMessage->ClientId.UniqueProcess;
            lpReply->hdr.ClientId.UniqueThread=(DWORD64)ReplyMessage->ClientId.UniqueThread;
            lpReply->hdr.MessageId=ReplyMessage->MessageId;
            lpReply->hdr.ClientViewSize=ReplyMessage->ClientViewSize;
            if (ReplyMessage->u1.s1.DataLength)
                memcpy(lpReply->bTmp,(void*)((DWORD)ReplyMessage+sizeof(*ReplyMessage)),min(ReplyMessage->u1.s1.DataLength,sizeof(lpReply->bTmp)));
        }
    }
    if (ReceiveMessage)
        lpReceive=(MESSAGE64*)MemAlloc(sizeof(MESSAGE64));

    NTSTATUS dwRet=ZwReplyWaitReceivePort(PortHandle,PortContext,(PPORT_MESSAGE)lpReply,(PPORT_MESSAGE)lpReceive);
    if (NT_SUCCESS(dwRet))
    {
        memset(ReceiveMessage,0,sizeof(*ReceiveMessage));

        ReceiveMessage->u1.s1.DataLength=lpReceive->hdr.u1.s1.DataLength;
        ReceiveMessage->u1.s1.TotalLength=lpReceive->hdr.u1.s1.DataLength+sizeof(PORT_MESSAGE);
        ReceiveMessage->u2.ZeroInit=lpReceive->hdr.u2.ZeroInit;
        ReceiveMessage->ClientId.UniqueProcess=(HANDLE)lpReceive->hdr.ClientId.UniqueProcess;
        ReceiveMessage->ClientId.UniqueThread=(HANDLE)lpReceive->hdr.ClientId.UniqueThread;
        ReceiveMessage->MessageId=lpReceive->hdr.MessageId;
        ReceiveMessage->ClientViewSize=lpReceive->hdr.ClientViewSize;
        if (ReceiveMessage->u1.s1.DataLength)
            memcpy((void*)((DWORD)ReceiveMessage+sizeof(*ReceiveMessage)),lpReceive->bTmp,ReceiveMessage->u1.s1.DataLength);
    }
    MemFree(lpReply);
    MemFree(lpReceive);
    return dwRet;
}

SYSLIBFUNC(NTSTATUS) ZwTrueAcceptConnectPort(PHANDLE PortHandle,PVOID PortContext,PPORT_MESSAGE ConnectionRequest,BOOLEAN AcceptConnection,PPORT_VIEW ServerView,PREMOTE_PORT_VIEW ClientView)
{
    if (!SysIsWow64())
        return ZwAcceptConnectPort(PortHandle,PortContext,ConnectionRequest,AcceptConnection,ServerView,ClientView);

    MESSAGE64 *lpRequest=NULL;
    if (ConnectionRequest)
    {
        lpRequest=(MESSAGE64*)MemAlloc(sizeof(MESSAGE64));
        if (lpRequest)
        {
            lpRequest->hdr.u1.s1.DataLength=ConnectionRequest->u1.s1.DataLength;
            lpRequest->hdr.u1.s1.TotalLength=ConnectionRequest->u1.s1.DataLength+sizeof(PORT_MESSAGE64);
            lpRequest->hdr.u2.ZeroInit=ConnectionRequest->u2.ZeroInit;
            lpRequest->hdr.ClientId.UniqueProcess=(DWORD64)ConnectionRequest->ClientId.UniqueProcess;
            lpRequest->hdr.ClientId.UniqueThread=(DWORD64)ConnectionRequest->ClientId.UniqueThread;
            lpRequest->hdr.MessageId=ConnectionRequest->MessageId;
            lpRequest->hdr.ClientViewSize=ConnectionRequest->ClientViewSize;
            if (ConnectionRequest->u1.s1.DataLength)
                memcpy(lpRequest->bTmp,(void*)((DWORD)ConnectionRequest+sizeof(*ConnectionRequest)),min(ConnectionRequest->u1.s1.DataLength,sizeof(lpRequest->bTmp)));
        }
    }

    PORT_VIEW64 ServerView64={0},*lpServerView64=NULL;
    if (ServerView)
    {
        ServerView64.Length=sizeof(PORT_VIEW64);
        ServerView64.SectionHandle=(DWORD64)ServerView->SectionHandle;
        ServerView64.ViewSize=ServerView->ViewSize;
        lpServerView64=&ServerView64;
    }

    REMOTE_PORT_VIEW64 ClientView64={0},*lpClientView64=NULL;
    if (ClientView)
    {
        ClientView64.Length=ClientView->Length;
        lpClientView64=&ClientView64;
    }

    NTSTATUS dwRet=ZwAcceptConnectPort(PortHandle,PortContext,(PPORT_MESSAGE)lpRequest,AcceptConnection,(PPORT_VIEW)lpServerView64,(PREMOTE_PORT_VIEW)lpClientView64);

    if (NT_SUCCESS(dwRet))
    {
        if (ServerView)
        {
            ServerView->SectionOffset=ServerView64.SectionOffset;
            ServerView->ViewSize=ServerView64.ViewSize;
            ServerView->ViewBase=(LPVOID)ServerView64.ViewBase;
            ServerView->ViewRemoteBase=(LPVOID)ServerView64.ViewRemoteBase;
        }

        if (ClientView)
        {
            ClientView->ViewSize=ClientView64.ViewSize;
            ClientView->ViewBase=(LPVOID)ClientView64.ViewBase;
        }
    }
    MemFree(lpRequest);
    return dwRet;
}

SYSLIBFUNC(NTSTATUS) ZwTrueReplyPort(HANDLE PortHandle,PPORT_MESSAGE ReplyMessage)
{
    if (!SysIsWow64())
        return ZwReplyPort(PortHandle,ReplyMessage);

    MESSAGE64 *lpReply=NULL;
    if (ReplyMessage)
    {
        lpReply=(MESSAGE64*)MemAlloc(sizeof(MESSAGE64));
        if (lpReply)
        {
            lpReply->hdr.u1.s1.DataLength=ReplyMessage->u1.s1.DataLength;
            lpReply->hdr.u1.s1.TotalLength=ReplyMessage->u1.s1.DataLength+sizeof(PORT_MESSAGE64);
            lpReply->hdr.u2.ZeroInit=ReplyMessage->u2.ZeroInit;
            lpReply->hdr.ClientId.UniqueProcess=(DWORD64)ReplyMessage->ClientId.UniqueProcess;
            lpReply->hdr.ClientId.UniqueThread=(DWORD64)ReplyMessage->ClientId.UniqueThread;
            lpReply->hdr.MessageId=ReplyMessage->MessageId;
            lpReply->hdr.ClientViewSize=ReplyMessage->ClientViewSize;
            if (ReplyMessage->u1.s1.DataLength)
                memcpy(lpReply->bTmp,(void*)((DWORD)ReplyMessage+sizeof(*ReplyMessage)),min(ReplyMessage->u1.s1.DataLength,sizeof(lpReply->bTmp)));
        }
    }

    NTSTATUS dwRet=ZwReplyPort(PortHandle,(PPORT_MESSAGE)lpReply);

    MemFree(lpReply);
    return dwRet;
}

