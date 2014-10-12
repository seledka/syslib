#ifndef SYSTEM_H_INCLUDED
#define SYSTEM_H_INCLUDED

#include <windows.h>
#include <tlhelp32.h>

PPEB SysGetCurrentPeb();
PTEB SysGetCurrentTeb();

#define ALIGN(x,y) (((x)+(y)-1)&(~((y)-1)))
#define RVATOVA(base,offset) (((ULONG_PTR)(base)+(ULONG_PTR)(offset)))

typedef struct
{
    DWORD_PTR ExitStatus;
    LPVOID PebBaseAddress;
    DWORD_PTR AffinityMask;
    DWORD_PTR BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
}   MYPROCESS_BASIC_INFORMATION;

typedef BOOL WINAPI __DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved);

typedef ULONG WINAPI __NewThreadNotify(LPTHREAD_START_ROUTINE lpRoutine,void *lpParam);


struct STACK_FRAME
{
    STACK_FRAME *lpNext;
    void *lpIP;
};


#define FACILITY_NTWIN32                 0x7

#define NT_FACILITY_MASK 0xfff
#define NT_FACILITY_SHIFT 16
#define NT_FACILITY(Status) ((((ULONG)(Status)) >> NT_FACILITY_SHIFT) & NT_FACILITY_MASK)

#define NT_NTWIN32(Status) (NT_FACILITY(Status) == FACILITY_NTWIN32)
#define WIN32_FROM_NTSTATUS(Status) (((ULONG)(Status)) & 0xffff)

typedef ULONG NTAPI __RtlNtStatusToDosError(NTSTATUS Status);

typedef BOOL WINAPI _IsWow64Process(HANDLE hProcess,PBOOL Wow64Process);


struct DLL_ENTRY_THREAD
{
    HANDLE hThread;
    void *lpParam;
    LPTHREAD_START_ROUTINE lpFunc;
};

#endif // SYSTEM_H_INCLUDED
