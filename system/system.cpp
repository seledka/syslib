#include "sys_includes.h"
#include <shlwapi.h>
#include <intrin.h>
#include <sddl.h>
#include <aclapi.h>
#include <userenv.h>

#include "system.h"
#include "ldr\ldr.h"
#include "inject\inject.h"

#include "syslib\chksum.h"
#include "syslib\mem.h"
#include "syslib\debug.h"
#include "syslib\system.h"
#include "syslib\hash.h"
#include "syslib\str.h"
#include "syslib\wow64.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

inline PPEB SysGetCurrentPeb()
{
#ifdef _X86_
    return (PPEB)__readfsdword(0x30);
#else
    return (PPEB)__readgsqword(0x60);
#endif
}

inline PTEB SysGetCurrentTeb()
{
#ifdef _X86_
    return (PTEB)__readfsdword(0x18);
#else
    return (PTEB)__readgsqword(0x30);
#endif
}

SYSLIBFUNC(BOOL) SysCloseHandle(HANDLE hHandle)
{
    if ((hHandle) && (hHandle != INVALID_HANDLE_VALUE))
    {
        DWORD dwFlags=0;
        if (GetHandleInformation(hHandle,&dwFlags))
        {
            if (!(dwFlags & HANDLE_FLAG_PROTECT_FROM_CLOSE))
                return (CloseHandle(hHandle) != FALSE);
        }
    }
	return false;
}

SYSLIBFUNC(DWORD) SysFindProcessW(LPCWSTR lpFileName)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFileName,MAX_PATH))
        return 0;

    DWORD r=0;
    HANDLE hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,NULL);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W ppe={0};
        ppe.dwSize=sizeof(ppe);
        if (Process32FirstW(hSnap,&ppe))
        {
            do
            {
                if (StrStrIW(ppe.szExeFile,lpFileName))
                {
                    r=ppe.th32ProcessID;
                    break;
                }
            }
            while (Process32NextW(hSnap,&ppe));
        }
        SysCloseHandle(hSnap);
    }
    return r;
}

SYSLIBFUNC(DWORD) SysFindProcessA(LPCSTR lpFileName)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFileName,0,NULL);

    DWORD dwProcessId=SysFindProcessW(lpFileNameW);

    MemFree(lpFileNameW);
    return dwProcessId;
}

SYSLIBFUNC(DWORD) SysGetProcessSessionId(DWORD dwPID)
{
    DWORD dwSessionId=0;
    ProcessIdToSessionId(dwPID,&dwSessionId);
    return dwSessionId;
}

SYSLIBFUNC(DWORD) SysFindSessionProcessW(LPCWSTR lpFileName,DWORD dwSessionId)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFileName,MAX_PATH))
        lpFileName=NULL;

    DWORD r=0;
    HANDLE hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,NULL);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W ppe={0};
        ppe.dwSize=sizeof(ppe);
        if (Process32FirstW(hSnap,&ppe))
        {
            do
            {
                if ((lpFileName) && (!StrStrIW(ppe.szExeFile,lpFileName)))
                    continue;

                if ((SysGetProcessSessionId(ppe.th32ProcessID) == dwSessionId) && (SysCheckProcessGroup(ppe.th32ProcessID)))
                {
                    r=ppe.th32ProcessID;
                    break;
                }
            }
            while (Process32NextW(hSnap,&ppe));
        }
        SysCloseHandle(hSnap);
    }
    return r;
}

SYSLIBFUNC(DWORD) SysFindSessionProcessA(LPCSTR lpFileName,DWORD dwSessionId)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFileName,0,NULL);

    DWORD dwProcessId=SysFindSessionProcessW(lpFileNameW,dwSessionId);

    MemFree(lpFileNameW);
    return dwProcessId;
}

SYSLIBFUNC(BOOL) SysCheckProcessGroup(DWORD dwProcessId)
{
    BOOL bRet=false;
	HANDLE hProc=OpenProcess(PROCESS_QUERY_INFORMATION,false,dwProcessId);
	if (hProc)
	{
	    HANDLE hToken;
		bool bState=(OpenProcessToken(hProc,TOKEN_QUERY|TOKEN_QUERY_SOURCE,&hToken) != FALSE);
		if (bState)
		{
            TOKEN_SOURCE tsToken;
            DWORD dwIO;
			bState=(GetTokenInformation(hToken,TokenSource,&tsToken,sizeof(TOKEN_SOURCE),&dwIO) != FALSE);
			if (bState)
			{
			    CharUpperA(tsToken.SourceName);
				if ((memcmp(tsToken.SourceName,dcrA_65df934d("*SYSTEM*"),sizeof("*SYSTEM*"))) && (memcmp(tsToken.SourceName,dcrA_ede44591("ADVAPI"),sizeof("ADVAPI"))))
					bRet=true;
			}
			SysCloseHandle(hToken);
		}
		SysCloseHandle(hProc);
	}

	return bRet;
}

SYSLIBFUNC(BOOL) SysIsUserAdmin()
{
	SID_IDENTIFIER_AUTHORITY siaNTAuthority=SECURITY_NT_AUTHORITY;
	PSID lpAdministratorsGroup;
	BOOL bRet=AllocateAndInitializeSid(&siaNTAuthority,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&lpAdministratorsGroup);
	if (bRet)
	{
		if (!CheckTokenMembership(NULL,lpAdministratorsGroup,&bRet))
			bRet=false;
		FreeSid(lpAdministratorsGroup);
	}
	return (bRet != FALSE);
}

SYSLIBFUNC(HANDLE) SysOpenProcess(DWORD dwAccess,DWORD_PTR dwPID)
{
    HANDLE hRes=NULL;
    PCLIENT_ID lpClientId=(PCLIENT_ID)VirtualAlloc(NULL,sizeof(CLIENT_ID),MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);

    if (lpClientId)
    {
        lpClientId->UniqueProcess=(HANDLE)dwPID;
        lpClientId->UniqueThread=0;

        DWORD dwOldProtect;
        VirtualProtect(lpClientId,sizeof(CLIENT_ID),PAGE_READWRITE|PAGE_GUARD,&dwOldProtect);

        OBJECT_ATTRIBUTES ObjAttr;
        InitializeObjectAttributes(&ObjAttr,0,0,0,0);

        __try
        {
            if (!NT_SUCCESS(ZwOpenProcess(&hRes,dwAccess,&ObjAttr,lpClientId)))
                hRes=NULL;

            lpClientId->UniqueThread=0;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            hRes=NULL;
        }

        VirtualFree(lpClientId,0,MEM_RELEASE);
    }
    if (!hRes)
        hRes=OpenProcess(dwAccess,FALSE,dwPID);
    return hRes;
}

SYSLIBFUNC(BOOL) SysIsProcess(DWORD_PTR ProcessId)
{
    BOOL bResult=false;
    HANDLE hProc=SysOpenProcess(PROCESS_QUERY_INFORMATION,ProcessId);
    if (hProc)
    {
        DWORD dwCode=0;
        GetExitCodeProcess(hProc,&dwCode);
        if (dwCode == STILL_ACTIVE)
            bResult=true;
        SysCloseHandle(hProc);
    }
    else if (GetLastError() == ERROR_ACCESS_DENIED)
        bResult=true;
    return bResult;
}

SYSLIBFUNC(DWORD) SysGetThreadProcessId(DWORD dwThreadId)
{
    DWORD dwProcessId=0;
    HANDLE hThread=OpenThread(THREAD_QUERY_INFORMATION,false,dwThreadId);
    if (hThread)
    {
        DWORD dwSize;
        THREAD_BASIC_INFORMATION TBI;
        if (NT_SUCCESS(ZwQueryInformationThread(hThread,ThreadBasicInformation,&TBI,sizeof(TBI),&dwSize)))
            dwProcessId=(DWORD)TBI.ClientId.UniqueProcess;
        SysCloseHandle(hThread);
    }
    return dwProcessId;
}

SYSLIBFUNC(BOOL) SysTerminateProcess(DWORD dwProcessId,UINT dwExitCode)
{
    BOOL bResult=false;
    if (dwProcessId != GetCurrentProcessId())
    {
        HANDLE hProc=SysOpenProcess(PROCESS_TERMINATE,dwProcessId);
        if (hProc)
        {
            bResult=(TerminateProcess(hProc,dwExitCode) != FALSE);
            SysCloseHandle(hProc);
        }
    }
    return bResult;
}

static void SysTerminateProcessTreeEx(HANDLE hSnap,DWORD dwProcessId,UINT dwExitCode,bool bKillParent)
{
    PROCESSENTRY32 pe={0};
    pe.dwSize=sizeof(pe);
    if (Process32First(hSnap,&pe))
    {
        do
        {
            if (pe.th32ParentProcessID == dwProcessId)
                SysTerminateProcessTreeEx(hSnap,pe.th32ProcessID,dwExitCode,true);
        }
        while (Process32Next(hSnap,&pe));
    }

    if (bKillParent)
        SysTerminateProcess(dwProcessId,dwExitCode);

    return;
}

static void SysTerminateProcessTreeEx(DWORD dwProcessId,UINT dwExitCode,bool bKillParent)
{
    HANDLE hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        SysTerminateProcessTreeEx(hSnap,dwProcessId,dwExitCode,bKillParent);

        SysCloseHandle(hSnap);
    }
    return;
}

SYSLIBFUNC(void) SysTerminateProcessTree(DWORD dwProcessId,UINT dwExitCode)
{
    SysTerminateProcessTreeEx(dwProcessId,dwExitCode,true);
    return;
}

SYSLIBFUNC(void) SysTerminateProcessTreeExceptParent(DWORD dwProcessId,UINT dwExitCode)
{
    SysTerminateProcessTreeEx(dwProcessId,dwExitCode,false);
    return;
}

SYSLIBFUNC(LPVOID) SysGetProcessList(LPDWORD lpProcCount)
{
    ULONG dwSize=0x8000;
    void *lpBuffer;
    NTSTATUS dwStatus;

    do
    {
        lpBuffer=MemQuickAlloc(dwSize);
        if (!lpBuffer)
            break;

        dwStatus=ZwQuerySystemInformation(SystemProcessInformation,lpBuffer,dwSize,NULL);
        if (dwStatus == STATUS_INFO_LENGTH_MISMATCH)
        {
            MemFree(lpBuffer);
            dwSize*=2;
        }
        else if (!NT_SUCCESS(dwStatus))
        {
            MemFree(lpBuffer);
            lpBuffer=NULL;
            break;
        }
    }
    while (dwStatus == STATUS_INFO_LENGTH_MISMATCH);

    if ((lpBuffer) && (lpProcCount))
    {
        DWORD dwProcessCount=1;
        PSYSTEM_PROCESS_INFORMATION lpProcesses=(PSYSTEM_PROCESS_INFORMATION)lpBuffer;
        do
        {
            if (!lpProcesses->NextEntryOffset)
                break;

            dwProcessCount++;
            lpProcesses=(PSYSTEM_PROCESS_INFORMATION)(((byte*)lpProcesses)+lpProcesses->NextEntryOffset);
        }
        while (true);
        *lpProcCount=dwProcessCount;
    }
    return lpBuffer;
}

SYSLIBFUNC(void) SysTerminateProcessByNameW(LPCWSTR lpName,UINT dwExitCode)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpName,MAX_PATH))
        return;

    void *lpBuffer=SysGetProcessList(NULL);
    if (lpBuffer)
    {
        PSYSTEM_PROCESS_INFORMATION lpProcesses=(PSYSTEM_PROCESS_INFORMATION)lpBuffer;
        do
        {
            if (!lstrcmpi(lpName,lpProcesses->ImageName.Buffer))
                SysTerminateProcess((DWORD)lpProcesses->UniqueProcessId,dwExitCode);

            if (!lpProcesses->NextEntryOffset)
                break;

            lpProcesses=(PSYSTEM_PROCESS_INFORMATION)(((byte*)lpProcesses)+lpProcesses->NextEntryOffset);
        }
        while (true);
        MemFree(lpBuffer);
    }
    return;
}

SYSLIBFUNC(void) SysTerminateProcessByNameA(LPCSTR lpName,UINT dwExitCode)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpName,0,NULL);

    SysTerminateProcessByNameW(lpFileNameW,dwExitCode);

    MemFree(lpFileNameW);
    return;
}

static PSYSTEM_PROCESS_INFORMATION FindProcess(DWORD dwProcessId,PSYSTEM_PROCESS_INFORMATION lpTable)
{
    PSYSTEM_PROCESS_INFORMATION lpProc=NULL;
    do
    {
        if ((DWORD)lpTable->UniqueProcessId == dwProcessId)
        {
            lpProc=lpTable;
            break;
        }

        if (!lpTable->NextEntryOffset)
            break;

        lpTable=(PSYSTEM_PROCESS_INFORMATION)(((byte*)lpTable)+lpTable->NextEntryOffset);
    }
    while (true);
    return lpProc;
}

static DWORD *BuildProcessesTree(DWORD dwProcessId)
{
    DWORD dwProcessCount=0;
    void *lpBuffer=SysGetProcessList(&dwProcessCount);
    DWORD *lpTree=NULL;
    if (lpBuffer)
    {
        DWORD *lpTmpTree=(DWORD*)MemAlloc(dwProcessCount*sizeof(DWORD)),*p=lpTmpTree;
        *p=dwProcessId;
        dwProcessCount=0;
        while (dwProcessId)
        {
            PSYSTEM_PROCESS_INFORMATION lpProc=FindProcess(dwProcessId,(PSYSTEM_PROCESS_INFORMATION)lpBuffer);
            if (!lpProc)
                break;
            dwProcessId=(DWORD)lpProc->InheritedFromUniqueProcessId;
            if (SysIsProcess(dwProcessId))
            {
                p++;
                *p=dwProcessId;
                dwProcessCount++;
            }
        }

        if (dwProcessCount)
        {
            lpTree=(DWORD*)MemAlloc(dwProcessCount*sizeof(DWORD));
            for (DWORD i=0; i <= dwProcessCount; i++)
                lpTree[i]=lpTmpTree[dwProcessCount-i];
        }

        MemFree(lpTmpTree);
        MemFree(lpBuffer);
    }
    return lpTree;
}

static DWORD CountArrayElements(DWORD *lpArray,DWORD dwFinalElement)
{
    DWORD dwCount=0;
    while (*lpArray != dwFinalElement)
    {
        dwCount++;
        lpArray++;
    }
    return dwCount;
}

SYSLIBFUNC(BOOL) SysCheckProcessesRelationships(DWORD dwProcessId1,DWORD dwProcessId2)
{
    if (dwProcessId1 == dwProcessId2)
        return true;

    if ((!SysIsProcess(dwProcessId1)) || (!SysIsProcess(dwProcessId2)))
        return false;

    BOOL bRet=false;
    DWORD *lpProcess1Tree=BuildProcessesTree(dwProcessId1);
    if (lpProcess1Tree)
    {
        DWORD *lpProcess2Tree=BuildProcessesTree(dwProcessId2);
        if (lpProcess2Tree)
        {
            if (lpProcess1Tree[0] == lpProcess2Tree[0])
            {
                DWORD *p1=&lpProcess1Tree[1],
                      *p2=&lpProcess2Tree[1],
                      dwP1Size=CountArrayElements(p1,dwProcessId1),
                      dwP2Size=CountArrayElements(p2,dwProcessId2);

                for (DWORD i=0; i <= dwP1Size; i++)
                {
                    for (DWORD j=0; j <= dwP2Size; j++)
                    {
                        if (p1[i] == p2[j])
                        {
                            bRet=true;
                            break;
                        }
                    }
                    if (bRet)
                        break;
                }
            }
            MemFree(lpProcess2Tree);
        }
        MemFree(lpProcess1Tree);
    }
    return bRet;
}

SYSLIBFUNC(void) SysReboot()
{
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken))
    {
        TOKEN_PRIVILEGES tkp;
        LookupPrivilegeValue(NULL,SE_SHUTDOWN_NAME,&tkp.Privileges[0].Luid);

        tkp.PrivilegeCount=1;
        tkp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken,FALSE,&tkp,0,NULL,0);

        if (GetLastError() == ERROR_SUCCESS)
            ExitWindowsEx(EWX_REBOOT|EWX_FORCE,0);
    }
    return;
}

SYSLIBFUNC(BOOL) SysIsWow64(HANDLE hProcess)
{
    BOOL bIsWow64=false;
    _IsWow64Process *fnIsWow64Process=(_IsWow64Process *)GetProcAddress(GetModuleHandleA(dcrA_24c7b2df("kernel32")),dcrA_cb420eba("IsWow64Process"));
    if (fnIsWow64Process)
        fnIsWow64Process(hProcess,&bIsWow64);
    return (bIsWow64 != FALSE);
}

SYSLIBFUNC(BOOL) SysIsWindows64()
{
    SYSTEM_INFO si={0};
    GetNativeSystemInfo(&si);
    return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
}

SYSLIBFUNC(BOOL) SysIsProcess64(HANDLE hProcess)
{
    BOOL bRet=false;
#ifdef _X86_
    if (SysIsWindows64())
#endif
        bRet=(SysIsWow64(hProcess) == false);
    return bRet;
}

SYSLIBFUNC(BOOL) SysIsWindowProcess64(HWND hWnd)
{
    BOOL bRet=false;

    DWORD dwPID;
    GetWindowThreadProcessId(hWnd,&dwPID);

    HANDLE hProc=SysOpenProcess(PROCESS_QUERY_INFORMATION,dwPID);
    if (hProc)
    {
        bRet=SysIsProcess64(hProc);
        SysCloseHandle(hProc);
    }
    return bRet;
}

SYSLIBFUNC(DWORD) SysGetCPUSpeed()
{
    DWORD dwSpeed;
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,dcr_cfc60bbe("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"),0,KEY_READ|KEY_WOW64_64KEY,&hKey) == ERROR_SUCCESS)
    {
        DWORD dwLen=sizeof(DWORD);
        RegQueryValueEx(hKey,dcr_5e64c5e8("~MHz"),NULL,NULL,(byte*)&dwSpeed,&dwLen);
        RegCloseKey(hKey);
    }
    return dwSpeed;
}

SYSLIBFUNC(DWORD) SysGetProcessorsCount()
{
    SYSTEM_INFO SysInfo;
    GetSystemInfo(&SysInfo);
    return SysInfo.dwNumberOfProcessors;
}

SYSLIBFUNC(DWORD) SysGetMemorySize()
{
    MEMORYSTATUSEX mem;
    mem.dwLength=sizeof(mem);
    GlobalMemoryStatusEx(&mem);

    return mem.ullTotalPhys/(1024*1024);
}

static DWORD dwLastThreadNotifyPID;
static PEB_LDR_MODULE *GetNTDLL()
{
	PPEB_LDR_DATA lpLdr=SysGetCurrentPeb()->Ldr;
	PEB_LDR_MODULE *lpModule=(PEB_LDR_MODULE *)lpLdr->InLoadOrderModuleList.Flink;
	lpModule=(PEB_LDR_MODULE *)lpModule->InLoadOrderModuleList.Flink;
	return (PEB_LDR_MODULE *)lpModule->InLoadOrderModuleList.Flink;
}

static bool IsNotificatorSet()
{
    return (dwLastThreadNotifyPID == GetCurrentProcessId());
}

static __DllMain *lpRealDllEntryPoint;
static __NewThreadNotify *lpNotify;
static BOOL WINAPI NewDllEntryPoint(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved)
{
    if (fdwReason == DLL_THREAD_ATTACH)
    {
        PTEB lpTeb=SysGetCurrentTeb();

        LPTHREAD_START_ROUTINE lpRoutine=NULL;
        void *lpParam=NULL;

    #ifdef _X86_
            STACK_FRAME *lpStackFrame=(STACK_FRAME*)((ULONG_PTR)&hinstDLL-sizeof(STACK_FRAME));
            while ((lpTeb->NtTib.StackBase > lpStackFrame->lpNext) &&
                   (lpTeb->NtTib.StackLimit < lpStackFrame->lpNext))
                lpStackFrame=lpStackFrame->lpNext;

            lpStackFrame++;
            if (*(ULONG_PTR*)lpStackFrame)
                lpStackFrame=lpStackFrame->lpNext;
            else
                lpStackFrame=(STACK_FRAME*)((ULONG_PTR)lpStackFrame+sizeof(ULONG_PTR)*3);
            PCONTEXT lpContext=(PCONTEXT)lpStackFrame;

            lpRoutine=(LPTHREAD_START_ROUTINE)lpContext->Eax;
            lpParam=(void *)lpContext->Ebx;
    #else
            ULONG_PTR *lpStack=(ULONG_PTR*)&hinstDLL;
            while (lpTeb->NtTib.StackBase > lpStack)
            {
                if (*(ULONG*)lpStack == 0x10001b) /// context.ContextFlags
                {
                    PCONTEXT lpContext=(PCONTEXT)((ULONG_PTR)lpStack-offsetof(CONTEXT,ContextFlags));

                    lpRoutine=(LPTHREAD_START_ROUTINE)lpContext->Rcx;
                    lpParam=(void*)lpContext->Rdx;
                    break;
                }
                lpStack++;
            }
    #endif

        if (lpNotify(lpRoutine,lpParam))
            return TRUE;
    }
    return lpRealDllEntryPoint(hinstDLL,fdwReason,lpvReserved);
}

SYSLIBFUNC(BOOL) SysSetThreadCreateNotify(__NewThreadNotify *lpNotifyProc)
{
    if ((SYSLIB_SAFE::CheckCodePtr(lpNotifyProc)) && (!IsNotificatorSet()))
    {
        PEB_LDR_MODULE *lpNTDLL=GetNTDLL();
        if (lpNTDLL)
        {
            lpNotify=lpNotifyProc;
            lpRealDllEntryPoint=(__DllMain *)lpNTDLL->EntryPoint;
            lpNTDLL->EntryPoint=NewDllEntryPoint;
            dwLastThreadNotifyPID=GetCurrentProcessId();
        }
    }
    return IsNotificatorSet();
}

SYSLIBFUNC(void) SysRemoveThreadCreateNotify()
{
    if (IsNotificatorSet())
    {
        dwLastThreadNotifyPID=0;
        PEB_LDR_MODULE *lpNTDLL=GetNTDLL();
        if (lpNTDLL)
            lpNTDLL->EntryPoint=lpRealDllEntryPoint;
    }
    return;
}

SYSLIBFUNC(DWORD) SysGetThreadState(DWORD dwThreadId,LPDWORD lpWaitReason)
{
    if (!SYSLIB_SAFE::CheckParamWrite(lpWaitReason,sizeof(*lpWaitReason)))
        lpWaitReason=NULL;

    DWORD dwState=ThreadStateUnknown;

    void *lpBuffer=SysGetProcessList(NULL);
    if (lpBuffer)
    {
        PSYSTEM_PROCESS_INFORMATION lpProcesses=(PSYSTEM_PROCESS_INFORMATION)lpBuffer;
        do
        {
            bool bFound=false;
            for (DWORD i=0; i < lpProcesses->NumberOfThreads-1; i++)
            {
                if (lpProcesses->Threads[i].ClientId.UniqueThread == (HANDLE)dwThreadId)
                {
                    bFound=true;
                    dwState=lpProcesses->Threads[i].ThreadState;
                    if (lpWaitReason)
                        *lpWaitReason=lpProcesses->Threads[i].WaitReason;
                    break;
                }
            }
            if (bFound)
                break;
            if (!lpProcesses->NextEntryOffset)
                break;

            lpProcesses=(PSYSTEM_PROCESS_INFORMATION)(((byte*)lpProcesses)+lpProcesses->NextEntryOffset);
        }
        while (true);
        MemFree(lpBuffer);
    }
    return dwState;
}

SYSLIBFUNC(DWORD) SysGetCurrentSessionId()
{
    return SysGetProcessSessionId(GetCurrentProcessId());
}

SYSLIBFUNC(void) SysNtStatusToWin32Error(NTSTATUS dwStatus)
{
    DWORD dwWin32Error;
    if (NT_NTWIN32(dwStatus))
        dwWin32Error=WIN32_FROM_NTSTATUS(dwStatus);
    else
    {
        __RtlNtStatusToDosError *RtlNtStatusToDosError=(__RtlNtStatusToDosError*)GetProcAddress(GetModuleHandleA(dcrA_91764d8a("ntdll.dll")),dcrA_8a58a5cf("RtlNtStatusToDosError"));
        dwWin32Error=RtlNtStatusToDosError(dwStatus);
    }
    SetLastError(dwWin32Error);
    return;
}

SYSLIBFUNC(BOOL) SysIsProcessSuspended(DWORD dwPID)
{
    BOOL bRet=false;
    void *lpBuffer=SysGetProcessList(NULL);
    if (lpBuffer)
    {
        PSYSTEM_PROCESS_INFORMATION lpProcesses=(PSYSTEM_PROCESS_INFORMATION)lpBuffer;
        do
        {
            bRet=true;
            if (lpProcesses->UniqueProcessId == (HANDLE)dwPID)
            {
                for (DWORD i=0; i < lpProcesses->NumberOfThreads-1; i++)
                {
                    if ((lpProcesses->Threads[i].ThreadState != ThreadStateWait) ||
                        (lpProcesses->Threads[i].WaitReason != Suspended))
                    {
                        bRet=false;
                        break;
                    }
                }
                break;
            }
            lpProcesses=(PSYSTEM_PROCESS_INFORMATION)(((byte*)lpProcesses)+lpProcesses->NextEntryOffset);
        }
        while (true);
        MemFree(lpBuffer);
    }
    return bRet;
}

static BOOL CALLBACK EnumWindowStationProc(LPTSTR lpszWindowStation,HWINSTA *lpWinsta)
{
    BOOL bRet=TRUE;
    HWINSTA hWinsta=OpenWindowStation(lpszWindowStation,false,WINSTA_ALL_ACCESS);
    if (hWinsta)
    {
        HWINSTA hCurWinsta=GetProcessWindowStation();
        SetProcessWindowStation(hWinsta);
        if (OpenInputDesktop(0,false,GENERIC_READ))
        {
            bRet=FALSE;
            *lpWinsta=hWinsta;
        }
        SetProcessWindowStation(hCurWinsta);
    }
    return bRet;
}

SYSLIBFUNC(HWINSTA) SysGetInputWindowStation()
{
    HWINSTA hWinsta=NULL;
    EnumWindowStations((WINSTAENUMPROC)EnumWindowStationProc,(LPARAM)&hWinsta);
    return hWinsta;
}

static void WINAPI DllWaitingThread(DLL_ENTRY_THREAD *lpInfo)
{
    DLL_ENTRY_THREAD Info;
    memcpy(&Info,lpInfo,sizeof(Info));
    MemFree(lpInfo);
    WaitForSingleObject(Info.hThread,INFINITE);
    SysCloseHandle(Info.hThread);
    Info.lpFunc(Info.lpParam);
    return;
}

SYSLIBFUNC(BOOL) SysStartThreadFromDllEntry(LPTHREAD_START_ROUTINE lpFunc,LPVOID lpParam)
{
    if (!SYSLIB_SAFE::CheckCodePtr(lpFunc))
        return false;

    BOOL bRet=false;
    DLL_ENTRY_THREAD *lpInfo=(DLL_ENTRY_THREAD*)MemAlloc(sizeof(DLL_ENTRY_THREAD));
    if (lpInfo)
    {
        if (DuplicateHandle(GetCurrentProcess(),GetCurrentThread(),GetCurrentProcess(),&lpInfo->hThread,0,FALSE,0))
        {
            lpInfo->lpParam=lpParam;
            lpInfo->lpFunc=lpFunc;
            SysCloseHandle(CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)DllWaitingThread,lpInfo,0,NULL));
            bRet=true;
        }
        else
            MemFree(lpInfo);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) SysGenerateUniqueMachineGuidA(LPCSTR lpUniquePostfix,LPSTR lpOutBuf)
{
    if (!SYSLIB_SAFE::CheckStrParamA(lpUniquePostfix,255))
        return false;

    if (!SYSLIB_SAFE::CheckParamWrite(lpOutBuf,40))
        return false;

    BOOL bRet=false;
    char szCompName[MAX_COMPUTERNAME_LENGTH+1];
	DWORD dwLen=ARRAYSIZE(szCompName);
    if (GetComputerNameA(szCompName,&dwLen))
    {
        LPSTR lpTmpBuf;
        DWORD dwNewLen=StrFormatExA(&lpTmpBuf,dcrA_4f072b6d("%s\\%s"),szCompName,lpUniquePostfix);
        if (dwNewLen)
        {
            byte bMD6[64];
            bRet=hash_CalcMD6((byte*)lpTmpBuf,dwNewLen,bMD6);
            if (bRet)
            {
                GUID *lpGUID=(GUID*)bMD6;
                StrFormatA(lpOutBuf,dcrA_a9c1cd7a("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"),lpGUID->Data1,
                                                                                                        lpGUID->Data2,
                                                                                                        lpGUID->Data3,
                                                                                                        lpGUID->Data4[0],lpGUID->Data4[1],
                                                                                                        lpGUID->Data4[2],lpGUID->Data4[3],lpGUID->Data4[4],lpGUID->Data4[5],lpGUID->Data4[6],lpGUID->Data4[7]);
            }
            MemFree(lpTmpBuf);
        }
    }
    return bRet;
}

SYSLIBFUNC(BOOL) SysGenerateUniqueMachineGuidW(LPCWSTR lpUniquePostfix,LPWSTR lpOutBuf)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpUniquePostfix,255))
        return false;

    if (!SYSLIB_SAFE::CheckParamWrite(lpOutBuf,40*sizeof(WCHAR)))
        return false;

    BOOL bRet=false;
    LPSTR lpUniquePostfixA=StrUnicodeToAnsiEx(lpUniquePostfix,0,NULL);
    if (lpUniquePostfixA)
    {
        char szGuidA[100];
        bRet=SysGenerateUniqueMachineGuidA(lpUniquePostfixA,szGuidA);
        if (bRet)
            bRet=(StrAnsiToUnicode(szGuidA,0,lpOutBuf,0) != 0);
        MemFree(lpUniquePostfixA);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) SysEnablePrivilegeW(LPCWSTR lpPrivilege,BOOL bEnable)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpPrivilege,255))
        return false;

    BOOL bRet=false;
    HANDLE hToken=NULL;
    do
    {
        if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken))
            break;

        TOKEN_PRIVILEGES tp={0};
        if (!LookupPrivilegeValueW(NULL,lpPrivilege,&tp.Privileges[0].Luid))
            break;

        tp.PrivilegeCount=1;
        if (bEnable)
            tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL))
            break;

        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
            break;

        bRet=true;
    }
    while (false);

    SysCloseHandle(hToken);
	return bRet;
}

SYSLIBFUNC(BOOL) SysEnablePrivilegeA(LPCSTR lpPrivilege,BOOL bEnable)
{
    LPWSTR lpPrivilegeW=StrAnsiToUnicodeEx(lpPrivilege,0,NULL);

    BOOL bRet=SysEnablePrivilegeW(lpPrivilegeW,bEnable);

    MemFree(lpPrivilegeW);
    return bRet;
}

static bool EnableRequiredImpersonationPrivileges()
{
	const TCHAR *lpPrivileges[]={dcr_bb7d5db2("SeImpersonatePrivilege"),
                                 dcr_efdd2bc7("SeTcbPrivilege"),
                                 dcr_ce01bcf7("SeDebugPrivilege"),
                                 dcr_891eddf1("SeChangeNotifyPrivilege"),
                                 dcr_ccfe7541("SeCreateTokenPrivilege"),
                                 dcr_ee70d137("SeBackupPrivilege"),
                                 dcr_80798328("SeRestorePrivilege"),
                                 dcr_00fc4762("SeIncreaseQuotaPrivilege"),
                                 dcr_55a57d7f("SeAssignPrimaryTokenPrivilege")};

    DWORD dwRet=0;
    for (int i=0; i < ARRAYSIZE(lpPrivileges); i++)
        dwRet+=(DWORD)SysEnablePrivilege(lpPrivileges[i],true);
    return (dwRet != 0);
}

SYSLIBFUNC(BOOL) ImpersonateLocalSystemUser(DWORD dwPID,LPHANDLE lpToken)
{
    BOOL bRet=false;
    if (EnableRequiredImpersonationPrivileges())
    {
        HANDLE hProc=SysOpenProcess(MAXIMUM_ALLOWED,dwPID);
        if (hProc)
        {
            HANDLE hToken;
            if (OpenProcessToken(hProc,TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_IMPERSONATE,&hToken))
            {
                if (ImpersonateLoggedOnUser(hToken))
                {
                    bRet=true;
                    if (lpToken)
                        *lpToken=hToken;
                    else
                        SysCloseHandle(hToken);
                }
                else
                    SysCloseHandle(hToken);
            }
            SysCloseHandle(hProc);
        }
    }
    return bRet;
}

SYSLIBFUNC(HANDLE) SysGetProcessToken(DWORD dwPID)
{
    HANDLE hToken=NULL;
    if (EnableRequiredImpersonationPrivileges())
    {
        HANDLE hProc=SysOpenProcess(MAXIMUM_ALLOWED,dwPID);
        if (hProc)
        {
            HANDLE hProcToken=NULL;
            if (OpenProcessToken(hProc,TOKEN_DUPLICATE,&hProcToken))
            {
                DuplicateTokenEx(hProcToken,TOKEN_IMPERSONATE|TOKEN_READ|TOKEN_ASSIGN_PRIMARY|TOKEN_DUPLICATE,NULL,SecurityImpersonation,TokenPrimary,&hToken);
                RevertToSelf();
                SysCloseHandle(hProcToken);
            }
            SysCloseHandle(hProc);
        }
    }
    return hToken;
}

SYSLIBFUNC(DWORD) SysStartProcessAsShellUserW(LPCWSTR lpCommandLine,DWORD dwFlags)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpCommandLine,MAX_PATH))
        return 0;

    DWORD dwPID=0,
          dwShellPID=SysFindSessionProcess(NULL,WTSGetActiveConsoleSessionId());
    if (dwShellPID)
    {
        HANDLE hToken=SysGetProcessToken(dwShellPID);
        if (hToken)
        {
            STARTUPINFOW siInfo= {0};
            PROCESS_INFORMATION piInfo= {0};
            siInfo.cb=sizeof(siInfo);

            PVOID pEnv;
            CreateEnvironmentBlock(&pEnv,hToken,false);

            if (CreateProcessAsUserW(hToken,NULL,(LPWSTR)lpCommandLine,NULL,NULL,false,dwFlags|CREATE_UNICODE_ENVIRONMENT,pEnv,NULL,&siInfo,&piInfo))
            {
                dwPID=piInfo.dwProcessId;

                SysCloseHandle(piInfo.hProcess);
                SysCloseHandle(piInfo.hThread);
            }

            DestroyEnvironmentBlock(pEnv);
            SysCloseHandle(hToken);
        }
    }
    return dwPID;
}

SYSLIBFUNC(DWORD) SysStartProcessAsShellUserA(LPCSTR lpCommandLine,DWORD dwFlags)
{
    LPWSTR lpCommandLineW=StrAnsiToUnicodeEx(lpCommandLine,0,NULL);

    DWORD dwProcessId=SysStartProcessAsShellUserW(lpCommandLineW,dwFlags);

    MemFree(lpCommandLineW);
    return dwProcessId;
}

SYSLIBFUNC(BOOL) SetObjectToLowIntegrity(HANDLE hObject,SE_OBJECT_TYPE dwObjectType)
{
	BOOL bRet=false;
	SysEnablePrivilege(dcr_a926e7c8("SeSecurityPrivilege"),true);

	PSECURITY_DESCRIPTOR pSD;
	if (ConvertStringSecurityDescriptorToSecurityDescriptor(dcr_b9f5eb90("S:(ML;;NW;;;LW)"),SDDL_REVISION_1,&pSD,NULL))
    {
		BOOL bSaclPresent=FALSE,bSaclDefaulted=FALSE;
		PACL pSacl=NULL;
		if (GetSecurityDescriptorSacl(pSD,&bSaclPresent,&pSacl,&bSaclDefaulted))
			bRet=(SetSecurityInfo(hObject,dwObjectType,LABEL_SECURITY_INFORMATION,NULL,NULL,NULL,pSacl) == ERROR_SUCCESS);
		LocalFree(pSD);
    }
	return bRet;
}

SYSLIBFUNC(HANDLE) SysCreateSharedSection(HANDLE hProc,DWORD dwMappingSize,DWORD dwProtection,LPVOID *lppLocalMap,LPVOID *lppRemoteMap)
{
    LARGE_INTEGER a={0};
    a.LowPart=dwMappingSize;

    HANDLE hSection=NULL;
    *lppLocalMap=NULL;
    *lppRemoteMap=NULL;

    bool bRet=false;
    if (NT_SUCCESS(ZwCreateSection(&hSection,SECTION_ALL_ACCESS,NULL,&a,dwProtection,SEC_COMMIT,NULL)))
    {
        SIZE_T dwSize=dwMappingSize;
        if (NT_SUCCESS(ZwMapViewOfSection(hSection,hProc,lppRemoteMap,NULL,NULL,NULL,&dwSize,ViewShare,NULL,dwProtection)))
            bRet=(NT_SUCCESS(ZwMapViewOfSection(hSection,GetCurrentProcess(),lppLocalMap,NULL,NULL,NULL,&dwSize,ViewShare,NULL,dwProtection)));
    }

    if (!bRet)
    {
        if (*lppLocalMap)
        {
            ZwUnmapViewOfSection(GetCurrentProcess(),*lppLocalMap);
            *lppLocalMap=NULL;
        }
        if (*lppRemoteMap)
        {
            ZwUnmapViewOfSection(hProc,*lppRemoteMap);
            *lppRemoteMap=NULL;
        }
        SysCloseHandle(hSection);
        hSection=NULL;
    }
    return hSection;
}

#ifdef _X86_
SYSLIBFUNC(HANDLE) SysCreateSharedSection64(HANDLE hProc,DWORD dwMappingSize,DWORD dwProtection,LPVOID *lppLocalMap,DWORD64 *lppRemoteMap)
{
    LARGE_INTEGER a={0};
    a.LowPart=dwMappingSize;

    HANDLE hSection=NULL;
    *lppLocalMap=NULL;
    *lppRemoteMap=NULL;


    bool bRet=false;
    if (NT_SUCCESS(ZwCreateSection(&hSection,SECTION_ALL_ACCESS,NULL,&a,dwProtection,SEC_COMMIT,NULL)))
    {
        DWORD64 dwSize64=dwMappingSize;
        if (NT_SUCCESS(NtMapViewOfSection64(hSection,hProc,lppRemoteMap,NULL,NULL,NULL,&dwSize64,ViewShare,NULL,dwProtection)))
        {
            DWORD dwSize=dwMappingSize;
            bRet=(NT_SUCCESS(ZwMapViewOfSection(hSection,GetCurrentProcess(),lppLocalMap,NULL,NULL,NULL,&dwSize,ViewShare,NULL,dwProtection)));
        }
    }

    if (!bRet)
    {
        if (*lppLocalMap)
        {
            ZwUnmapViewOfSection(GetCurrentProcess(),*lppLocalMap);
            *lppLocalMap=NULL;
        }
        if (*lppRemoteMap)
        {
            NtUnmapViewOfSection64(hProc,*lppRemoteMap);
            *lppRemoteMap=NULL;
        }
        SysCloseHandle(hSection);
        hSection=NULL;
    }
    return hSection;
}
#endif

SYSLIBFUNC(BOOL) SysProtectMe()
{
    BOOL bRet=false;
    HANDLE hProc=SysOpenProcess(PROCESS_ALL_ACCESS,GetCurrentProcessId());
    if (hProc)
    {
        SECURITY_ATTRIBUTES sa={0};
        sa.nLength=sizeof(sa);
        do
        {
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(dcr_2f717059("D:P"),SDDL_REVISION_1,&sa.lpSecurityDescriptor,0))
                break;
            if (SetKernelObjectSecurity(hProc,DACL_SECURITY_INFORMATION,sa.lpSecurityDescriptor))
                break;

            bRet=true;
        }
        while (false);
        SysCloseHandle(hProc);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) SysProcNameByPIDW(DWORD dwPID,LPWSTR lpBuf,DWORD dwBufSize)
{
    if (!SYSLIB_SAFE::CheckParamWrite(lpBuf,dwBufSize*sizeof(WCHAR)))
        return false;

    BOOL bRet=false;
    HANDLE hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W ppe={0};
        ppe.dwSize=sizeof(PROCESSENTRY32);
        Process32FirstW(hSnap,&ppe);

        do
        {
            if (ppe.th32ProcessID == dwPID)
            {
                StrCpyNW(lpBuf,ppe.szExeFile,dwBufSize);
                bRet=true;
                break;
            }
        }
        while(Process32Next(hSnap,&ppe));

        SysCloseHandle(hSnap);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) SysProcNameByPIDA(DWORD dwPID,LPSTR lpBuf,DWORD dwBufSize)
{
    BOOL bRet=false;
    LPWSTR lpNameW=WCHAR_QuickAlloc(dwBufSize);
    if (lpNameW)
    {
        bRet=SysProcNameByPIDW(dwPID,lpNameW,dwBufSize);
        if (bRet)
            StrUnicodeToAnsi(lpNameW,0,lpBuf,0);

        MemFree(lpNameW);
    }
    return bRet;
}

SYSLIBFUNC(DWORD) SysExecuteFileA(LPSTR lpFile,LPSTR lpCommandLine,LPSTR lpDesktop,BOOL bHideWindow,BOOL bWait)
{
    if (!SYSLIB_SAFE::CheckStrParamA(lpFile,MAX_PATH))
        lpFile=NULL;

    if (!SYSLIB_SAFE::CheckStrParamA(lpCommandLine,MAX_PATH))
        lpCommandLine=NULL;

    if ((!lpFile) && (!lpCommandLine))
        return 0;

    if (!SYSLIB_SAFE::CheckStrParamA(lpDesktop,100))
        lpDesktop=NULL;

    DWORD dwPID=0;
    STARTUPINFOA sinf={0};
    PROCESS_INFORMATION pinf={0};
    sinf.cb=sizeof(sinf);

    if (lpDesktop)
        sinf.lpDesktop=lpDesktop;

    if (bHideWindow)
    {
        sinf.dwFlags=STARTF_USESHOWWINDOW;
        sinf.wShowWindow=SW_HIDE;
    }
    do
    {
        if (!CreateProcessA(lpFile,lpCommandLine,NULL,NULL,FALSE,(bHideWindow ? CREATE_NO_WINDOW : 0),NULL,NULL,&sinf,&pinf))
            break;

        SysCloseHandle(pinf.hThread);

        if (bWait)
            WaitForSingleObject(pinf.hProcess,INFINITE);

        SysCloseHandle(pinf.hProcess);

        dwPID=pinf.dwProcessId;
    }
    while (false);

    return dwPID;
}

SYSLIBFUNC(DWORD) SysExecuteFileW(LPWSTR lpFile,LPWSTR lpCommandLine,LPWSTR lpDesktop,BOOL bHideWindow,BOOL bWait)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
        lpFile=NULL;

    if (!SYSLIB_SAFE::CheckStrParamW(lpCommandLine,MAX_PATH))
        lpCommandLine=NULL;

    if ((!lpFile) && (!lpCommandLine))
        return 0;

    if (!SYSLIB_SAFE::CheckStrParamW(lpDesktop,100))
        lpDesktop=NULL;

    DWORD dwPID=0;
    STARTUPINFOW sinf={0};
    PROCESS_INFORMATION pinf={0};
    sinf.cb=sizeof(sinf);

    if (lpDesktop)
        sinf.lpDesktop=lpDesktop;

    if (bHideWindow)
    {
        sinf.dwFlags=STARTF_USESHOWWINDOW;
        sinf.wShowWindow=SW_HIDE;
    }
    do
    {
        if (!CreateProcessW(lpFile,lpCommandLine,NULL,NULL,FALSE,0,NULL,NULL,&sinf,&pinf))
            break;

        SysCloseHandle(pinf.hThread);

        if (bWait)
            WaitForSingleObject(pinf.hProcess,INFINITE);

        SysCloseHandle(pinf.hProcess);

        dwPID=pinf.dwProcessId;
    }
    while (false);

    return dwPID;
}

SYSLIBFUNC(LARGE_INTEGER) SysGetFileMappingSize(HANDLE hMapping)
{
    SECTION_BASIC_INFORMATION SectionInfo={0};
    ZwQuerySection(hMapping,SectionBasicInformation,&SectionInfo,sizeof(SectionInfo),0);
    return SectionInfo.MaximumSize;
}

SYSLIBFUNC(BOOL) SysIsPtrInside(LPVOID lpMem,LPVOID lpPtr)
{
    BOOL bRet=false;

	MEMORY_BASIC_INFORMATION mbi={0};
	if (VirtualQuery(lpMem,&mbi,sizeof(mbi)))
	{
        if (((ULONG_PTR)mbi.AllocationBase <= (ULONG_PTR)lpPtr) && (((ULONG_PTR)mbi.AllocationBase+mbi.RegionSize) >= (ULONG_PTR)lpPtr))
            bRet=true;
	}
    return bRet;
}

static BOOL PreventDllUsageInt(HMODULE hModule)
{
    BOOL bRet=false;
    PIMAGE_DOS_HEADER lpDosHdr=(PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS lpHdrs=(PIMAGE_NT_HEADERS)((LPBYTE)hModule+lpDosHdr->e_lfanew);
    LPVOID lpAddr=&lpHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    DWORD dwOld;
    if (VirtualProtect(lpAddr,sizeof(IMAGE_DATA_DIRECTORY),PAGE_EXECUTE_READWRITE,&dwOld))
    {
        memset(lpAddr,0,sizeof(IMAGE_DATA_DIRECTORY));
        VirtualProtect(lpAddr,sizeof(IMAGE_DATA_DIRECTORY),dwOld,&dwOld);
        bRet=true;
    }
    return bRet;
}

SYSLIBFUNC(BOOL) SysPreventDllUsageW(LPCWSTR lpName)
{
    BOOL bRet=false;
    HMODULE hModule=LoadLibraryW(lpName);
    if (hModule)
        bRet=PreventDllUsageInt(hModule);
    return bRet;
}

SYSLIBFUNC(BOOL) SysPreventDllUsageA(LPCSTR lpName)
{
    BOOL bRet=false;
    HMODULE hModule=LoadLibraryA(lpName);
    if (hModule)
        bRet=PreventDllUsageInt(hModule);
    return bRet;
}

SYSLIBFUNC(void) SysRemoveDllFromPEBW(LPCWSTR lpName)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpName,MAX_PATH))
        return;

    PPEB lpPEB=SysGetCurrentPeb();
    PPEB_LDR_DATA lpLdr=lpPEB->Ldr;
    PLIST_ENTRY lpHead=&lpLdr->InLoadOrderModuleList,
                lpEntry=lpHead->Flink;
    while (lpHead != lpEntry)
    {
        PLDR_DATA_TABLE_ENTRY lpLdrEntry=(PLDR_DATA_TABLE_ENTRY)lpEntry;
        if (lpLdrEntry->FullDllName.Buffer)
        {
            if ((StrStrIW(lpLdrEntry->FullDllName.Buffer,lpName)) || (!lstrcmpiW(lpLdrEntry->FullDllName.Buffer,lpName)))
            {
                lpEntry->Flink->Blink=lpEntry->Blink;
                lpEntry->Blink->Flink=lpEntry->Flink;
                break;
            }
        }
        lpEntry=lpEntry->Flink;
    }
    return;
}

SYSLIBFUNC(void) SysRemoveDllFromPEBA(LPCSTR lpName)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpName,0,NULL);

    SysRemoveDllFromPEBW(lpFileNameW);

    MemFree(lpFileNameW);
    return;
}

