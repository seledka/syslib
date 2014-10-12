#include "sys_includes.h"

#include "syslib\system.h"
#include "syslib\mem.h"
#include "syslib\str.h"

#include "ipc.h"
#include "common.h"

/**
    поток для отправки исходящих сообщений серверу
**/
static void WINAPI IPC_ServerOutputEventsServer(CLIENT_HANDLE *lpHandle)
{
    IPC_PREPARED_TO_SEND_BUFFER PreparedBuffer={0};

    while (WaitForSingleObject(lpHandle->SharedObjects.hStopEvent,0) == WAIT_TIMEOUT)
    {
        if (PreparedBuffer.bSendMePlease)
        {
            SYSLIB::IPC_SendPreparedBuffer(&lpHandle->SharedObjects,&PreparedBuffer,IPC_MESSAGE_FROM_CLI_TO_SRV);
            continue;
        }

        if (SYSLIB::IPC_WaitEvent(&lpHandle->PostedMsgs.Event,1) == WAIT_OBJECT_0)
        {
            PreparedBuffer.lpRc4Key=lpHandle->lpRc4Key;
            PreparedBuffer.dwRc4KeySize=lpHandle->dwRc4KeySize;

            SYSLIB::IPC_HandlePostedMessage(&lpHandle->PostedMsgs,&lpHandle->SentMsgs,&PreparedBuffer);
        }
    }

    if (PreparedBuffer.bSendMePlease)
        MemFree(PreparedBuffer.lpMsgToSend);

    SYSLIB::IPC_CleanupMessagesList(&lpHandle->PostedMsgs);
    SYSLIB::IPC_CleanupSentMessagesList(&lpHandle->SentMsgs);
    return;
}

/**
    поток для приема входящих сообщений от сервера
**/
static void WINAPI IPC_ServerInputEventsServer(IPC_HANDLE *lpHandle)
{
    CLIENT_HANDLE *lpClient=&lpHandle->Cli;

    SYSLIB::IPC_InitMessagesList(&lpClient->ReceivedMsgs);
    SYSLIB::IPC_InitMessagesList(&lpClient->PostedMsgs);

    InitializeSafeCriticalSection(&lpClient->SentMsgs.csSent);
    InitializeSafeCriticalSection(&lpClient->LastMsg.csLastMsg);

    HANDLE hServerOutputThread=SysCreateThreadSafe(NULL,0,(LPTHREAD_START_ROUTINE)IPC_ServerOutputEventsServer,lpClient,0,NULL);
    SetEvent(lpClient->hThreadInitEvent);

    while (WaitForSingleObject(lpClient->SharedObjects.hStopEvent,0) == WAIT_TIMEOUT)
    {
        if (WaitForSingleObject(lpClient->hServerProc,0) != WAIT_TIMEOUT)
        {
            /// серверный процесс помер
            SetEvent(lpClient->SharedObjects.hStopEvent);
            break;
        }

        if (WaitForSingleObject(lpClient->SharedObjects.hSrv2CliEvent,1) == WAIT_OBJECT_0)
        {
            /// получена команда от сервера
            WaitForSingleObject(lpClient->SharedObjects.hProtectionMutex,INFINITE);
            {
                if (lpClient->SharedObjects.lpSharedMapping->bDirection == IPC_MESSAGE_FROM_SRV_TO_CLI)
                {
                    lpClient->TmpRecvBuf.lpRc4Key=lpClient->lpRc4Key;
                    lpClient->TmpRecvBuf.dwRc4KeySize=lpClient->dwRc4KeySize;
                    SYSLIB::IPC_RecvMessage(&lpClient->SentMsgs,lpClient->SharedObjects.lpSharedMapping,&lpClient->TmpRecvBuf,&lpClient->ReceivedMsgs,NULL);
                }
            }
            ReleaseMutex(lpClient->SharedObjects.hProtectionMutex);
        }
    }

    WaitForSingleObject(hServerOutputThread,INFINITE);
    SysCloseHandle(hServerOutputThread);

    MemFree(lpClient->TmpRecvBuf.lpTmpBuffer);

    SysCloseHandle(lpClient->hServerProc);

    SYSLIB::IPC_CleanupMessagesList(&lpClient->ReceivedMsgs);
    SYSLIB::IPC_FreeLastMsg((HANDLE)lpHandle,&lpClient->LastMsg,true);
    SYSLIB::IPC_CloseSharedHandles(&lpClient->SharedObjects);
    MemFree(lpClient->lpRc4Key);
    return;
}

static bool IPC_InitClientConnectionInfo(IPC_CONNECTION_INFO *lpConnInfo)
{
    bool bRet=false;
    do
    {
        lpConnInfo->hSrv2CliEvent=CreateEvent(NULL,false,false,NULL);
        if (!lpConnInfo->hSrv2CliEvent)
            break;

        lpConnInfo->hCli2SrvEvent=CreateEvent(NULL,false,false,NULL);
        if (!lpConnInfo->hCli2SrvEvent)
            break;

        lpConnInfo->hStopEvent=CreateEvent(NULL,true,false,NULL);
        if (!lpConnInfo->hStopEvent)
            break;

        lpConnInfo->hSharedMapping=CreateFileMapping(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,sizeof(IPC_COMMUNICATION_BUFFER),NULL);
        if (!lpConnInfo->hSharedMapping)
            break;

        lpConnInfo->hProtectionMutex=CreateMutex(NULL,false,NULL);
        if (!lpConnInfo->hProtectionMutex)
            break;

        bRet=true;
    }
    while (false);
    return bRet;
}

static void IPC_CleanupClientConnectionInfo(IPC_CONNECTION_INFO *lpConnInfo)
{
    if (lpConnInfo->hSrv2CliEvent)
        SysCloseHandle(lpConnInfo->hSrv2CliEvent);

    if (lpConnInfo->hCli2SrvEvent)
        SysCloseHandle(lpConnInfo->hCli2SrvEvent);

    if (lpConnInfo->hStopEvent)
        SysCloseHandle(lpConnInfo->hStopEvent);

    if (lpConnInfo->hSharedMapping)
        SysCloseHandle(lpConnInfo->hSharedMapping);

    if (lpConnInfo->hProtectionMutex)
        SysCloseHandle(lpConnInfo->hProtectionMutex);

    if (lpConnInfo->hServerProcess)
        SysCloseHandle(lpConnInfo->hServerProcess);

    return;
}

SYSLIBFUNC(HANDLE) IPC_ConnectServerW(LPCWSTR lpName)
{
    HANDLE hServer=NULL;

    LPWSTR lpPipe=SYSLIB::IPC_FormatPipeName(lpName);
    if (lpPipe)
    {
        IPC_CONNECTION_INFO IpcConnInfo={0};
        if (IPC_InitClientConnectionInfo(&IpcConnInfo))
        {
            while (true)
            {
                HANDLE hPipe=CreateFileW(lpPipe,GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
                if (hPipe != INVALID_HANDLE_VALUE)
                {
                    IPC_PIPE_CONNECTION_INFO PipeConnInfo;
                    PipeConnInfo.dwNewClientPID=GetCurrentProcessId();
                    PipeConnInfo.hEvent=CreateEvent(NULL,true,false,NULL);
                    PipeConnInfo.lpConnectionInfo=&IpcConnInfo;

                    DWORD dwSize=sizeof(PipeConnInfo);
                    WriteFile(hPipe,&PipeConnInfo,dwSize,&dwSize,0);
                    SysCloseHandle(hPipe);

                    bool bFailed=(WaitForSingleObject(PipeConnInfo.hEvent,IPC_SERVER_ANSWER_WAIT_TIMEOUT) == WAIT_TIMEOUT);
                    SysCloseHandle(PipeConnInfo.hEvent);
                    if (bFailed)
                        break;

                    IPC_HANDLE *lpHandle=SYSLIB::IPC_CreateHandle(IPC_CLIENT_HANDLE);
                    if (!lpHandle)
                    {
                        bFailed=true;
                        break;
                    }

                    CLIENT_HANDLE *lpClient=&lpHandle->Cli;

                    if (IpcConnInfo.dwRc4KeySize)
                    {
                        lpClient->lpRc4Key=(PCHAR)MemCopyEx(IpcConnInfo.szRc4Key,IpcConnInfo.dwRc4KeySize);
                        lpClient->dwRc4KeySize=IpcConnInfo.dwRc4KeySize;
                    }

                    lpClient->SharedObjects.hSrv2CliEvent=IpcConnInfo.hSrv2CliEvent;
                    lpClient->SharedObjects.hCli2SrvEvent=IpcConnInfo.hCli2SrvEvent;
                    lpClient->SharedObjects.hStopEvent=IpcConnInfo.hStopEvent;
                    lpClient->SharedObjects.hSharedMapping=IpcConnInfo.hSharedMapping;
                    lpClient->SharedObjects.hProtectionMutex=IpcConnInfo.hProtectionMutex;
                    lpClient->SharedObjects.lpSharedMapping=(IPC_COMMUNICATION_BUFFER*)MapViewOfFile(lpClient->SharedObjects.hSharedMapping,FILE_MAP_WRITE|FILE_MAP_READ,0,0,0);

                    lpClient->hServerProc=IpcConnInfo.hServerProcess;
                    lpClient->hThreadInitEvent=CreateEvent(NULL,false,false,NULL);

                    lpClient->hEventsThread=SysCreateThreadSafe(NULL,0,(LPTHREAD_START_ROUTINE)IPC_ServerInputEventsServer,lpHandle,0,NULL);

                    WaitForSingleObject(lpClient->hThreadInitEvent,INFINITE);
                    SysCloseHandle(lpClient->hThreadInitEvent);

                    hServer=(HANDLE)lpHandle;
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

        if (!hServer)
            IPC_CleanupClientConnectionInfo(&IpcConnInfo);
        MemFree(lpPipe);
    }

    return hServer;
}

SYSLIBFUNC(HANDLE) IPC_ConnectServerA(LPCSTR lpName)
{
    LPWSTR lpNameW=StrAnsiToUnicodeEx(lpName,0,NULL);

    HANDLE hServer=IPC_ConnectServerW(lpNameW);

    MemFree(lpNameW);
    return hServer;
}

