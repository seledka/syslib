#ifndef PE_FIX_H_INCLUDED
#define PE_FIX_H_INCLUDED

#include "system\system.h"
#include "ldr\ldr.h"

#define SYSINJ_WAIT_ATTEMPTS 3
#define SYSINJ_WAIT_TIMEOUT 10

typedef VOID WINAPI __Sleep(DWORD dwMilliseconds);
typedef BOOL WINAPI __VirtualFree(LPVOID lpAddress,SIZE_T dwSize,DWORD dwFreeType);
typedef BOOL WINAPI __GetExitCodeThread(HANDLE hThread,LPDWORD lpExitCode);
typedef NTSTATUS NTAPI __ZwUnmapViewOfSection(HANDLE ProcessHandle,PVOID BaseAddress);

struct MEMINFO
{
    LPVOID lpStartingAddress;
    __VirtualFree *lpVirtualFree;
    __GetExitCodeThread *lpGetExitCodeThread;
    __ZwUnmapViewOfSection *lpZwUnmapViewOfSection;
    __Sleep *lpSleep;
    HANDLE hThread;
};

struct REMOTE_THREAD_INFO
{
    LPTHREAD_START_ROUTINE lpFunc;
    LPVOID lpParam;
};

struct INJECT_PARAMS
{
    DWORD dwProcessId;
    union
    {
        LPTHREAD_START_ROUTINE lpFunc;
        byte *lpDll;
    };
    LPVOID lpParam;
};

typedef NTSTATUS WINAPI __ZwQueryInformationProcess(HANDLE ProcessHandle,PROCESS_INFORMATION_CLASS ProcessInformationClass,PVOID ProcessInformation,ULONG ProcessInformationLength,PULONG ReturnLength);

#define ProcessExecuteFlags 0x22
#define MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE 0x20

struct INJECT_REAL_THREAD_INFO
{
    LPTHREAD_START_ROUTINE lpFunc;
    void *lpParam;
    byte bOriginalEntryPointBytes[50];
    byte *lpOEP;
};

struct NEW_PROC_INJ_STRUCT
{
    LPTHREAD_START_ROUTINE lpThreadRoutine;
    DWORD dwEventCode;
};

#endif // PE_FIX_H_INCLUDED
