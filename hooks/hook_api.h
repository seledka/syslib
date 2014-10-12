#ifndef HOOK_API_H_INCLUDED
#define HOOK_API_H_INCLUDED

#define HOOK_MAX_RECURSE 100

#define HOOK_API_PSEUDO_RETADDR (LPVOID) 0xDEADC0DE

typedef struct _THREAD_HOOK_INFO
{
    DWORD dwRefs;
    DWORD_PTR dwThreadId;
    LPVOID lpRetAddr[HOOK_MAX_RECURSE];

    _THREAD_HOOK_INFO *lpNext;
} THREAD_HOOK_INFO, *PTHREAD_HOOK_INFO;

typedef struct _HOOK_INFO
{
    BOOL bHookEnabled;

    LPVOID lpRealFunc;
    LPVOID lpHandler;

    LPVOID lpStub;
    LPVOID lpBridge;
    LPVOID lpBackup;
    SIZE_T dwBackupCodeSize;

#ifdef _AMD64_
    LPVOID lpRelay;
    LPVOID lpTable;
#endif

    PTHREAD_HOOK_INFO lpThreads;

    _HOOK_INFO *lpNext;
} HOOK_INFO, *PHOOK_INFO;

#define PROTECTION_SLEEP 150

namespace SYSLIB
{
    LPVOID __fastcall GetHandlerAddress(LPVOID lpFunc,LPVOID lpRetAddr);
    LPVOID __fastcall EnableHookForCallingThread(LPVOID lpFunc);
};

#endif // HOOK_API_H_INCLUDED
