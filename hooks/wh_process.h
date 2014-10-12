#ifndef WH_PROCESS_H_INCLUDED
#define WH_PROCESS_H_INCLUDED

struct HOOKED_THREAD_INFO
{
    DWORD_PTR dwThreadId;
    HHOOK hHook;

    HOOKED_THREAD_INFO *lpNext;
};

struct WIN_HOOK_INFO
{
    int idHook;
    HOOKPROC lpfn;
    HOOKED_THREAD_INFO *lpThreads;

    WIN_HOOK_INFO *lpNext;
};

typedef LRESULT WINAPI __DispatchMessageA(MSG *lpMsg);
typedef LRESULT WINAPI __DispatchMessageW(MSG *lpMsg);
typedef BOOL WINAPI __WaitMessage();

#endif // WH_PROCESS_H_INCLUDED
