#ifndef SYSLIB_SYSTEM_H_INCLUDED
#define SYSLIB_SYSTEM_H_INCLUDED

#include <aclapi.h>
#include "syslib_exp.h"

SYSLIBEXP(BOOL) SysCloseHandle(HANDLE hHandle);
SYSLIBEXP(BOOL) SysCheckProcessGroup(DWORD dwProcessId);

SYSLIBEXP(DWORD) SysGetProcessSessionId(DWORD dwPID);

SYSLIBEXP(DWORD) SysFindProcessW(LPCWSTR lpFileName);
SYSLIBEXP(DWORD) SysFindProcessA(LPCSTR lpFileName);

#ifdef UNICODE
#define SysFindProcess SysFindProcessW
#else
#define SysFindProcess SysFindProcessA
#endif

SYSLIBEXP(DWORD) SysFindSessionProcessW(LPCWSTR lpFileName,DWORD dwSessionId);
SYSLIBEXP(DWORD) SysFindSessionProcessA(LPCSTR lpFileName,DWORD dwSessionId);

#ifdef UNICODE
#define SysFindSessionProcess SysFindSessionProcessW
#else
#define SysFindSessionProcess SysFindSessionProcessA
#endif


SYSLIBEXP(BOOL) SysIsUserAdmin();
SYSLIBEXP(BOOL) SysIsProcess(DWORD_PTR ProcessId);
SYSLIBEXP(HANDLE) SysOpenProcess(DWORD dwAccess,DWORD_PTR dwPID);
SYSLIBEXP(HANDLE) SysCreateThreadSafe(LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,DWORD dwCreationFlags,LPDWORD lpThreadId);
SYSLIBEXP(void) SysReboot();

#ifdef __cplusplus
SYSLIBEXP(BOOL) SysIsWow64(HANDLE hProcess=GetCurrentProcess());
#else
SYSLIBEXP(BOOL) SysIsWow64(HANDLE hProcess);
#endif

SYSLIBEXP(BOOL) SysIsWindows64();
SYSLIBEXP(BOOL) SysCheckProcessesRelationships(DWORD dwProcessId1,DWORD dwProcessId2);
SYSLIBEXP(BOOL) SysTerminateProcess(DWORD dwProcessId,UINT dwExitCode);
SYSLIBEXP(void) SysTerminateProcessTree(DWORD dwProcessId,UINT dwExitCode);
SYSLIBEXP(void) SysTerminateProcessTreeExceptParent(DWORD dwProcessId,UINT dwExitCode);

SYSLIBEXP(void) SysTerminateProcessByNameW(LPCWSTR lpName,UINT dwExitCode);
SYSLIBEXP(void) SysTerminateProcessByNameA(LPCSTR lpName,UINT dwExitCode);

#ifdef UNICODE
#define SysTerminateProcessByName SysTerminateProcessByNameW
#else
#define SysTerminateProcessByName SysTerminateProcessByNameA
#endif


SYSLIBEXP(DWORD) SysGetCurrentSessionId();
SYSLIBEXP(void) SysNtStatusToWin32Error(NTSTATUS dwStatus);
SYSLIBEXP(BOOL) SysIsProcessSuspended(DWORD dwPID);
SYSLIBEXP(BOOL) SysIsProcess64(HANDLE hProcess);
SYSLIBEXP(BOOL) SysIsWindowProcess64(HWND hWnd);

SYSLIBEXP(DWORD) SysGetCPUSpeed();
SYSLIBEXP(DWORD) SysGetProcessorsCount();
SYSLIBEXP(DWORD) SysGetMemorySize();

SYSLIBEXP(DWORD) SysGetThreadProcessId(DWORD dwThreadId);

/// 0 - вызвать оригинальный нотификатор
typedef ULONG WINAPI __NewThreadNotify(LPTHREAD_START_ROUTINE lpRoutine,LPVOID lpParam);

SYSLIBEXP(BOOL) SysSetThreadCreateNotify(__NewThreadNotify *lpNotify);
SYSLIBEXP(void) SysRemoveThreadCreateNotify();


enum
{
    ThreadStateInitialized,
    ThreadStateReady,
    ThreadStateRunning,
    ThreadStateStandby,
    ThreadStateTerminated,
    ThreadStateWait,
    ThreadStateTransition,
    ThreadStateUnknown
};

SYSLIBEXP(DWORD) SysGetThreadState(DWORD dwThreadId,LPDWORD lpWaitReason);

SYSLIBEXP(HWINSTA) SysGetInputWindowStation();

SYSLIBEXP(BOOL) SysStartThreadFromDllEntry(LPTHREAD_START_ROUTINE lpFunc,LPVOID lpParam);

SYSLIBEXP(BOOL) SysGenerateUniqueMachineGuidA(LPCSTR lpUniquePostfix,LPSTR lpOutBuf);
SYSLIBEXP(BOOL) SysGenerateUniqueMachineGuidW(LPCWSTR lpUniquePostfix,LPWSTR lpOutBuf);

#ifdef UNICODE
#define SysGenerateUniqueMachineGuid SysGenerateUniqueMachineGuidW
#else
#define SysGenerateUniqueMachineGuid SysGenerateUniqueMachineGuidA
#endif

SYSLIBEXP(BOOL) SysEnablePrivilegeW(LPCWSTR lpPrivilege,BOOL bEnable);
SYSLIBEXP(BOOL) SysEnablePrivilegeA(LPCSTR lpPrivilege,BOOL bEnable);

#ifdef UNICODE
#define SysEnablePrivilege SysEnablePrivilegeW
#else
#define SysEnablePrivilege SysEnablePrivilegeA
#endif

SYSLIBEXP(BOOL) ImpersonateLocalSystemUser(DWORD dwPID,LPHANDLE lpToken);
SYSLIBEXP(HANDLE) SysGetProcessToken(DWORD dwPID);

SYSLIBEXP(DWORD) SysStartProcessAsShellUserW(LPCWSTR lpCommandLine,DWORD dwFlags);
SYSLIBEXP(DWORD) SysStartProcessAsShellUserA(LPCSTR lpCommandLine,DWORD dwFlags);

#ifdef UNICODE
#define SysStartProcessAsShellUser SysStartProcessAsShellUserW
#else
#define SysStartProcessAsShellUser SysStartProcessAsShellUserA
#endif


SYSLIBEXP(DWORD) SysGetSystemVersionW(LPWSTR lpOut,DWORD dwSize);
SYSLIBEXP(DWORD) SysGetSystemVersionA(LPSTR lpOut,DWORD dwSize);

#ifdef UNICODE
#define SysGetSystemVersion SysGetSystemVersionW
#else
#define SysGetSystemVersion SysGetSystemVersionA
#endif


SYSLIBEXP(LPWSTR) SysGetSystemVersionExW();
SYSLIBEXP(LPSTR) SysGetSystemVersionExA();

#ifdef UNICODE
#define SysGetSystemVersionEx SysGetSystemVersionExW
#else
#define SysGetSystemVersionEx SysGetSystemVersionExW
#endif

#ifdef __cplusplus
SYSLIBEXP(BOOL) SetObjectToLowIntegrity(HANDLE hObject,SE_OBJECT_TYPE dwObjectType=SE_KERNEL_OBJECT);
#else
SYSLIBEXP(BOOL) SetObjectToLowIntegrity(HANDLE hObject,SE_OBJECT_TYPE dwObjectType);
#endif


#define DisableErrors() SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOALIGNMENTFAULTEXCEPT|SEM_NOOPENFILEERRORBOX)

SYSLIBEXP(HANDLE) SysCreateSharedSection(HANDLE hProc,DWORD dwMappingSize,DWORD dwProtection,LPVOID *lppLocalMap,LPVOID *lppRemoteMap);
#ifdef _X86_
SYSLIBEXP(HANDLE) SysCreateSharedSection64(HANDLE hProc,DWORD dwMappingSize,DWORD dwProtection,LPVOID *lppLocalMap,DWORD64 *lppRemoteMap);
#endif

SYSLIBEXP(BOOL) SysProtectMe();

SYSLIBEXP(LPVOID) SysGetProcessList(LPDWORD lpProcCount);

SYSLIBEXP(BOOL) SysProcNameByPIDW(DWORD dwPID,LPWSTR lpBuf,DWORD dwBufSize);
SYSLIBEXP(BOOL) SysProcNameByPIDA(DWORD dwPID,LPSTR szBuf,DWORD dwBufSize);

#ifdef UNICODE
#define SysProcNameByPID SysProcNameByPIDW
#else
#define SysProcNameByPID SysProcNameByPIDA
#endif


SYSLIBEXP(DWORD) SysExecuteFileW(LPWSTR lpFile,LPWSTR lpCommandLine,LPWSTR lpDesktop,BOOL bHideWindow,BOOL bWait);
SYSLIBEXP(DWORD) SysExecuteFileA(LPSTR lpFile,LPSTR lpCommandLine,LPSTR lpDesktop,BOOL bHideWindow,BOOL bWait);

#ifdef UNICODE
#define SysExecuteFile SysExecuteFileW
#else
#define SysExecuteFile SysExecuteFileA
#endif


SYSLIBEXP(BOOL) SysIsTokenIn();

SYSLIBEXP(LARGE_INTEGER) SysGetFileMappingSize(HANDLE hMapping);

SYSLIBEXP(DWORD) SysWaitForMultipleObjects(DWORD nCount,const PHANDLE lpHandles,BOOL bWaitAll,DWORD dwMilliseconds);

SYSLIBEXP(void) SysSetThreadNameW(DWORD dwThreadId,LPCWSTR lpThreadName);
SYSLIBEXP(void) SysSetThreadNameA(DWORD dwThreadId,LPCSTR lpThreadName);

#ifdef UNICODE
#define SysSetThreadName SysSetThreadNameW
#else
#define SysSetThreadName SysSetThreadNameA
#endif


SYSLIBEXP(BOOL) SysIsKernel32Loaded(DWORD ProcessId);
SYSLIBEXP(BOOL) SysWaitForKernel32(DWORD ProcessId);

SYSLIBEXP(BOOL) SysIsPtrInside(LPVOID lpMem,LPVOID lpPtr);


SYSLIBEXP(BOOL) SysPreventDllUsageW(LPCWSTR lpName);
SYSLIBEXP(BOOL) SysPreventDllUsageA(LPCSTR lpName);

#ifdef UNICODE
#define SysPreventDllUsage SysPreventDllUsageW
#else
#define SysPreventDllUsage SysPreventDllUsageA
#endif


SYSLIBEXP(void) SysCauseBSOD();

SYSLIBEXP(void) SysRemoveDllFromPEBW(LPCWSTR lpName);
SYSLIBEXP(void) SysRemoveDllFromPEBA(LPCSTR lpName);

#ifdef UNICODE
#define SysRemoveDllFromPEB SysRemoveDllFromPEBW
#else
#define SysRemoveDllFromPEB SysRemoveDllFromPEBA
#endif


enum SYSTEM_TYPE
{
    SYSTEM_TYPE_UNKNOWN,
    SYSTEM_TYPE_WIN32s,
    SYSTEM_TYPE_95,
    SYSTEM_TYPE_95_OSR2,
    SYSTEM_TYPE_98,
    SYSTEM_TYPE_98_SE,
    SYSTEM_TYPE_ME,
    SYSTEM_TYPE_NT,
    SYSTEM_TYPE_NT_SRV_4,
    SYSTEM_TYPE_2000,
    SYSTEM_TYPE_SRV_2000,
    SYSTEM_TYPE_XP,
    SYSTEM_TYPE_SRV_2003,
    SYSTEM_TYPE_SRV_2003_R2,
    SYSTEM_TYPE_VISTA,
    SYSTEM_TYPE_SRV_2008,
    SYSTEM_TYPE_7,
    SYSTEM_TYPE_SRV_2008_R2,
    SYSTEM_TYPE_8,
    SYSTEM_TYPE_SRV_2012,
    SYSTEM_TYPE_8_1,
    SYSTEM_TYPE_SRV_2012_R2
};

SYSLIBEXP(SYSTEM_TYPE) SysGetSystemType();

#endif // SYSLIB_SYSTEM_H_INCLUDED
