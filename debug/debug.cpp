#include "sys_includes.h"

#include "syslib\debug.h"
#include "syslib\mem.h"
#include "syslib\system.h"
#include "syslib\str.h"

#include "str\wsprintf.h"
#include "debug.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

static HANDLE hMutex;
static DWORD dwInit;
static WCHAR szPipeNameW[256],
             szMutexNameW[256];
static bool bStarted;

static bool IsInit()
{
    bool bRet=(dwInit == GetCurrentProcessId());
    if (!bRet)
        bStarted=false;
    return bRet;
}

static bool SendEventInt(DEBUGDATAW *lpData)
{
    bool bRet=false;
    WaitForSingleObject(hMutex,INFINITE);
    {
        #ifndef _X86_
            lpData->x64=true;
        #endif
        for (int i=0; i < 4; i++)
        {
            HANDLE hPipe=CreateFileW(szPipeNameW,GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
            if (hPipe != INVALID_HANDLE_VALUE)
            {
                ///DWORD dwMode=PIPE_READMODE_MESSAGE|PIPE_WAIT;
                ///SetNamedPipeHandleState(hPipe,&dwMode,NULL,NULL);

                DWORD dwSize=sizeof(*lpData)+lpData->dwBodySize*sizeof(WCHAR);
                WriteFile(hPipe,lpData,dwSize,&dwSize,0);

                /// вызывать из процесса-сервера нельзя
                if (!bStarted)
                    FlushFileBuffers(hPipe);

                SysCloseHandle(hPipe);
                bRet=true;

                break;
            }
            else
            {
                if (GetLastError() == ERROR_PIPE_BUSY)
                    Sleep(10);
                else
                    break;
            }
        }
    }
    ReleaseMutex(hMutex);
    return bRet;
}

SYSLIBFUNC(BOOL) DbgLog_SendEventA(LPCSTR lpFunc,LPCSTR lpFile,DWORD dwLine,LOG_TYPE bType,LPCSTR lpFormat,...)
{
    BOOL bRet=false;
    DWORD dwLastError=GetLastError(),
          dwTickCount=GetTickCount();

    if (IsInit())
    {
        LPSTR lpBody=(LPSTR)MemQuickAlloc(MAX_DBG_BODY_SIZE);
        if (lpBody)
        {
            va_list mylist;
            va_start(mylist,lpFormat);
            DWORD dwBodySize=SYSLIB::StrFmt_FormatStringA(lpBody,lpFormat,mylist);
            va_end(mylist);

            DEBUGDATAW *lpDataW=(DEBUGDATAW *)MemQuickAlloc(MAX_DBG_LOG_SIZE);
            if (lpDataW)
            {
                GetLocalTime(&lpDataW->lt);

                lpDataW->dwTickCount=dwTickCount;
                lpDataW->dwLastError=dwLastError;
                lpDataW->dwTID=GetCurrentThreadId();
                lpDataW->dwPID=GetCurrentProcessId();
                lpDataW->bLogType=bType;
                lpDataW->dwBodySize=dwBodySize;
                if (dwBodySize)
                    StrAnsiToUnicode(lpBody,0,lpDataW->szBody,0);

                StrAnsiToUnicode(lpFunc,0,lpDataW->szFunc,0);
                StrAnsiToUnicode(lpFile,0,lpDataW->szFile,0);
                lpDataW->dwLineNumber=dwLine;

                bRet=SendEventInt(lpDataW);
                MemFree(lpDataW);
            }
            MemFree(lpBody);
        }
    }
    return bRet;
}

SYSLIBFUNC(BOOL) DbgLog_SendEventW(LPCWSTR lpFunc,LPCWSTR lpFile,DWORD dwLine,LOG_TYPE bType,LPCWSTR lpFormat,...)
{
    BOOL bRet=false;
    DWORD dwLastError=GetLastError(),
          dwTickCount=GetTickCount();

    if (IsInit())
    {
        DEBUGDATAW *lpDataW=(DEBUGDATAW *)MemQuickAlloc(MAX_DBG_LOG_SIZE);
        if (lpDataW)
        {
            GetLocalTime(&lpDataW->lt);

            va_list mylist;
            va_start(mylist,lpFormat);
            DWORD dwBodySize=SYSLIB::StrFmt_FormatStringW(lpDataW->szBody,lpFormat,mylist);
            va_end(mylist);

            lpDataW->dwTickCount=dwTickCount;
            lpDataW->dwLastError=dwLastError;
            lpDataW->dwTID=GetCurrentThreadId();
            lpDataW->dwPID=GetCurrentProcessId();
            lpDataW->bLogType=bType;
            lpDataW->dwBodySize=dwBodySize;

            lstrcpyW(lpDataW->szFunc,lpFunc);
            lstrcpyW(lpDataW->szFile,lpFile);
            lpDataW->dwLineNumber=dwLine;

            bRet=SendEventInt(lpDataW);
            MemFree(lpDataW);
        }
    }
    return bRet;
}

static void WINAPI SendDbgLogAWThread(DBGLOGEVENTPROCAW_PARAMS *lpParams)
{
    lpParams->lpDbgLogEventProcAW(lpParams->lpDbgDataAW);
    MemFree(lpParams->lpDbgDataAW);
    MemFree(lpParams);
    return;
}

static void SendDbgLogA(DEBUGDATAW *lpDbgDataW,DBGLOGEVENTPROCA lpDbgLogEventProc)
{
    DEBUGDATAA *lpDbgDataA=(DEBUGDATAA *)MemQuickAlloc(sizeof(DEBUGDATAA)+lpDbgDataW->dwBodySize+1);
    if (lpDbgDataA)
    {
        lpDbgDataA->x64=lpDbgDataW->x64;
        lpDbgDataA->bLogType=lpDbgDataW->bLogType;

        lpDbgDataA->dwLastError=lpDbgDataW->dwLastError;
        lpDbgDataA->dwTickCount=lpDbgDataW->dwTickCount;
        lpDbgDataA->dwPID=lpDbgDataW->dwPID;
        lpDbgDataA->dwTID=lpDbgDataW->dwTID;

        lpDbgDataA->dwLineNumber=lpDbgDataW->dwLineNumber;
        lpDbgDataA->dwBodySize=lpDbgDataW->dwBodySize;

        memcpy(&lpDbgDataA->lt,&lpDbgDataW->lt,sizeof(lpDbgDataW->lt));

        StrUnicodeToAnsi(lpDbgDataW->szFunc,0,lpDbgDataA->szFunc,0);
        StrUnicodeToAnsi(lpDbgDataW->szFile,0,lpDbgDataA->szFile,0);
        StrUnicodeToAnsi(lpDbgDataW->szBody,0,lpDbgDataA->szBody,0);

        DBGLOGEVENTPROCAW_PARAMS *lpParams=(DBGLOGEVENTPROCAW_PARAMS *)MemAlloc(sizeof(DBGLOGEVENTPROCAW_PARAMS));
        if (lpParams)
        {
            lpParams->lpDbgLogEventProcAW=lpDbgLogEventProc;
            lpParams->lpDbgDataAW=lpDbgDataA;
            SysCloseHandle(CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)SendDbgLogAWThread,lpParams,0,NULL));
        }
        else
            MemFree(lpDbgDataA);
    }
    return;
}

static void SendDbgLogW(DEBUGDATAW *lpDbgDataW,DBGLOGEVENTPROCW lpDbgLogEventProc)
{
    DWORD dwSize=sizeof(DEBUGDATAW)+lpDbgDataW->dwBodySize*sizeof(WCHAR);
    DEBUGDATAW *lpTmpDbgDataW=(DEBUGDATAW *)MemQuickAlloc(dwSize+sizeof(WCHAR));
    if (lpTmpDbgDataW)
    {
        memcpy(lpTmpDbgDataW,lpDbgDataW,dwSize);
        lpTmpDbgDataW->szBody[lpDbgDataW->dwBodySize]=0;

        DBGLOGEVENTPROCAW_PARAMS *lpParams=(DBGLOGEVENTPROCAW_PARAMS *)MemAlloc(sizeof(DBGLOGEVENTPROCAW_PARAMS));
        if (lpParams)
        {
            lpParams->lpDbgLogEventProcAW=(DBGLOGEVENTPROCA)lpDbgLogEventProc;
            lpParams->lpDbgDataAW=(DEBUGDATAA*)lpTmpDbgDataW;
            SysCloseHandle(CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)SendDbgLogAWThread,lpParams,0,NULL));
        }
        else
            MemFree(lpTmpDbgDataW);
    }
    return;
}

static HANDLE hShutdownEvent,
              hServerThread;
static void WINAPI DbgLog_ServerThread(DBGLOG_SERVER *lpServer)
{
    if ((lpServer) && (IsInit()) && (!bStarted))
    {
        DBGLOGEVENTPROCA lpDbgLogEventProcA=NULL;
        DBGLOGEVENTPROCW lpDbgLogEventProcW=NULL;

        if (lpServer->bUnicode)
            lpDbgLogEventProcW=lpServer->lpDbgLogEventProcW;
        else
            lpDbgLogEventProcA=lpServer->lpDbgLogEventProcA;

        HANDLE hPipe=lpServer->hPipe;

        OVERLAPPED ol={0};
        ol.hEvent=CreateEvent(NULL,true,false,NULL);
        ConnectNamedPipe(hPipe,&ol);

        SetEvent(lpServer->hEvent);
        MemFree(lpServer);

        DEBUGDATAW *lpDbgDataW=(DEBUGDATAW*)MemQuickAlloc(MAX_DBG_LOG_SIZE);
        if (lpDbgDataW)
        {
            while (WaitForSingleObject(hShutdownEvent,1) == WAIT_TIMEOUT)
            {
                if (WaitForSingleObject(ol.hEvent,0) == WAIT_OBJECT_0)
                {
                    DWORD dwReaded=0;

                    if ((ReadFile(hPipe,lpDbgDataW,MAX_DBG_LOG_SIZE,&dwReaded,NULL)) && (dwReaded > 0))
                    {
                        if (lpDbgLogEventProcA)
                            SendDbgLogA(lpDbgDataW,lpDbgLogEventProcA);
                        else if (lpDbgLogEventProcW)
                            SendDbgLogW(lpDbgDataW,lpDbgLogEventProcW);
                    }

                    memset(lpDbgDataW,0,dwReaded);

                    DisconnectNamedPipe(hPipe);
                    ResetEvent(ol.hEvent);
                    ConnectNamedPipe(hPipe,&ol);
                }
            }
            MemFree(lpDbgDataW);
        }

        SysCloseHandle(ol.hEvent);
        SysCloseHandle(hPipe);
    }
    else
    {
        SetEvent(lpServer->hEvent);
        MemFree(lpServer);
    }
    return;
}

static bool DbgLog_StartEventsServerInt(void *lpDbgLogEventProc,bool bUnicode)
{
    if (IsInit())
    {
        if (!bStarted)
        {
            HANDLE hPipe=CreateNamedPipeW(szPipeNameW,PIPE_ACCESS_INBOUND|FILE_FLAG_OVERLAPPED|WRITE_DAC|WRITE_OWNER,PIPE_TYPE_MESSAGE|PIPE_WAIT|PIPE_READMODE_MESSAGE,PIPE_UNLIMITED_INSTANCES,MAX_DBG_LOG_SIZE,MAX_DBG_LOG_SIZE,NMPWAIT_USE_DEFAULT_WAIT,NULL);
            if (hPipe != INVALID_HANDLE_VALUE)
            {
                SetObjectToLowIntegrity(hPipe);

                DBGLOG_SERVER *lpServer=(DBGLOG_SERVER*)MemAlloc(sizeof(DBGLOG_SERVER));
                if (lpServer)
                {
                    lpServer->hPipe=hPipe;
                    lpServer->bUnicode=bUnicode;
                    lpServer->lpDbgLogEventProcA=(DBGLOGEVENTPROCA)lpDbgLogEventProc;
                    hShutdownEvent=CreateEvent(NULL,true,false,NULL);
                    HANDLE hEvent=lpServer->hEvent=CreateEvent(NULL,true,false,NULL);
                    hServerThread=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)DbgLog_ServerThread,lpServer,0,NULL);
                    WaitForSingleObject(hEvent,INFINITE);
                    SysCloseHandle(hEvent);
                    bStarted=true;
                }
                else
                    SysCloseHandle(hPipe);
            }
        }
    }
    return bStarted;
}

SYSLIBFUNC(BOOL) DbgLog_StartEventsServerA(DBGLOGEVENTPROCA lpDbgLogEventProc)
{
    return DbgLog_StartEventsServerInt(lpDbgLogEventProc,false);
}

SYSLIBFUNC(BOOL) DbgLog_StartEventsServerW(DBGLOGEVENTPROCW lpDbgLogEventProc)
{
    return DbgLog_StartEventsServerInt(lpDbgLogEventProc,true);
}

SYSLIBFUNC(void) DbgLog_StopEventsServer()
{
    if ((IsInit()) && (bStarted))
    {
        SetEvent(hShutdownEvent);
        WaitForSingleObject(hServerThread,INFINITE);
        SysCloseHandle(hServerThread);
        hServerThread=NULL;
        SysCloseHandle(hShutdownEvent);
        hShutdownEvent=NULL;
        bStarted=false;
        dwInit=0;
    }
    return;
}

SYSLIBFUNC(BOOL) DbgLog_InitW(LPCWSTR lpPrefix)
{
    if (!SYSLIB_SAFE::CheckStrParamW(lpPrefix,0))
        return false;

    if (IsInit())
        return true;

    WCHAR szTmpBuf[100];
    SysGenerateUniqueMachineGuidW(lpPrefix,szTmpBuf);
    StrFormatW(szPipeNameW,dcrW_6df88834("\\\\.\\pipe\\%s"),szTmpBuf);

    WCHAR szPrefix2[256];
    StrFormatW(szPrefix2,dcrW_bad73664("%s100500"),lpPrefix);
    SysGenerateUniqueMachineGuidW(lpPrefix,szTmpBuf);
    StrFormatW(szMutexNameW,dcrW_a8e4f316("CTF.Compart.Mutex.%s"),szTmpBuf);

    hMutex=OpenMutexW(SYNCHRONIZE,false,szMutexNameW);
    if (!hMutex)
    {
        hMutex=CreateMutexW(NULL,false,szMutexNameW);
        if (hMutex)
        {
            SetObjectToLowIntegrity(hMutex);
            dwInit=GetCurrentProcessId();
        }
    }
    else
        dwInit=GetCurrentProcessId();

    return IsInit();
}

SYSLIBFUNC(BOOL) DbgLog_InitA(LPCSTR lpPrefix)
{
    LPWSTR lpPrefixW=StrAnsiToUnicodeEx(lpPrefix,0,NULL);

    BOOL bRet=DbgLog_InitW(lpPrefixW);

    MemFree(lpPrefixW);
    return bRet;
}

