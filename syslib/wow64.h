#ifndef SYSLIB_WOW64_H_INCLUDED
#define SYSLIB_WOW64_H_INCLUDED

#ifdef _X86_
#include "syslib_exp.h"

SYSLIBEXP(DWORD64) X64Call(DWORD64 func,int nArgc, ...);
SYSLIBEXP(DWORD64) GetModuleHandle64(LPCWSTR lpModuleName);
SYSLIBEXP(DWORD64) GetProcAddress64(DWORD64 hModule,char *lpFuncName);

SYSLIBEXP(HANDLE) CreateRemoteThread64(HANDLE hProcess,DWORD64 lpStartAddress,DWORD64 lpParameter);
SYSLIBEXP(DWORD64) VirtualAllocEx64(HANDLE hProcess,DWORD64 lpAddress,SIZE_T dwSize,DWORD flAllocationType,DWORD flProtect);
SYSLIBEXP(BOOL) VirtualFreeEx64(HANDLE hProcess,DWORD64 lpAddress,SIZE_T dwSize,DWORD dwFreeType);
SYSLIBEXP(BOOL) WriteProcessMemory64(HANDLE hProcess,DWORD64 lpBaseAddress,LPVOID lpBuffer,SIZE_T nSize,DWORD64 *lpNumberOfBytesWritten);
SYSLIBEXP(BOOL) ReadProcessMemory64(HANDLE hProcess,DWORD64 lpBaseAddress,LPVOID lpBuffer,SIZE_T nSize,DWORD64 *lpNumberOfBytesRead);
SYSLIBEXP(NTSTATUS) NtQueryInformationProcess64(HANDLE ProcessHandle,DWORD ProcessInformationClass,LPVOID ProcessInformation,SIZE_T ProcessInformationLength,DWORD64 *ReturnLength);
SYSLIBEXP(NTSTATUS) NtMapViewOfSection64(HANDLE SectionHandle,HANDLE ProcessHandle,DWORD64 *BaseAddress,DWORD64 ZeroBits,DWORD64 CommitSize,PLARGE_INTEGER SectionOffset,DWORD64 *ViewSize,ULONG InheritDisposition,ULONG AllocationType,ULONG Protect);
SYSLIBEXP(NTSTATUS) NtUnmapViewOfSection64(HANDLE ProcessHandle,DWORD64 BaseAddress);

SYSLIBEXP(BOOL) SysWow64DisableWow64FsRedirection(PVOID *OldValue);
SYSLIBEXP(BOOL) SysWow64RevertWow64FsRedirection(PVOID OldValue);

SYSLIBEXP(DWORD64) SetWindowLongPtr64(HWND hWnd,DWORD dwIdx,DWORD64 dwNewValue);
SYSLIBEXP(DWORD64) GetWindowLongPtr64(HWND hWnd,DWORD dwIdx);

SYSLIBEXP(NTSTATUS) ZwTrueReplyWaitReceivePort(HANDLE PortHandle,PVOID *PortContext,PPORT_MESSAGE ReplyMessage,PPORT_MESSAGE ReceiveMessage);
SYSLIBEXP(NTSTATUS) ZwTrueAcceptConnectPort(PHANDLE PortHandle,PVOID PortContext,PPORT_MESSAGE ConnectionRequest,BOOLEAN AcceptConnection,PPORT_VIEW ServerView,PREMOTE_PORT_VIEW ClientView);
SYSLIBEXP(NTSTATUS) ZwTrueReplyPort(HANDLE PortHandle,PPORT_MESSAGE ReplyMessage);

SYSLIBEXP(BOOL) SysIsKernel64Loaded(DWORD dwPID);
SYSLIBEXP(BOOL) SysWaitForKernel64(DWORD dwPID);

#else

#define ZwTrueReplyWaitReceivePort ZwReplyWaitReceivePort
#define ZwTrueAcceptConnectPort ZwAcceptConnectPort
#define ZwTrueReplyPort ZwReplyPort
#endif

#endif // SYSLIB_WOW64_H_INCLUDED
