#include "sys_includes.h"

#include "syslib\threadsgroup.h"
#include "syslib\system.h"
#include "syslib\mem.h"
#include "syslib\str.h"
#include "syslib\debug.h"
#include "syslib\utils.h"

#include "ipc.h"
#include "common.h"

static void IPC_AppendSystemMsg(SERVER_HANDLE *lpServer,IPC_ACCEPTED_CLIENT_INFO *lpClient,IPC_MESSAGE_TYPE dwMsg)
{
    IPC_MESSAGES_LIST *lpMsg=(IPC_MESSAGES_LIST*)MemAlloc(sizeof(IPC_MESSAGES_LIST));
    if (lpMsg)
    {
        lpMsg->Msg.dwTime=GetTickCount();
        lpMsg->Msg.dwMsg=dwMsg;

        lpMsg->Msg.hSender=(HANDLE)lpClient->lpHandle;
        lpMsg->Msg.dwSenderProcessId=IPC_GetProcessId(lpMsg->Msg.hSender);

        EnterSafeCriticalSection(&lpServer->ReceivedMsgs.csMsg);
        {
            IPC_MESSAGES_LIST *lpCur=lpServer->ReceivedMsgs.lpMsg;
            if (lpCur)
            {
                while (lpCur->lpNext)
                    lpCur=lpCur->lpNext;

                lpCur->lpNext=lpMsg;
            }
            else
                lpServer->ReceivedMsgs.lpMsg=lpMsg;
        }
        LeaveSafeCriticalSection(&lpServer->ReceivedMsgs.csMsg);

        SYSLIB::IPC_SetEvent(&lpServer->ReceivedMsgs.Event);
    }
    return;
}

static void IPC_DeleteClient(IPC_ACCEPTED_CLIENT_INFO *lpClient)
{
    SERVER_HANDLE *lpServer=(SERVER_HANDLE*)lpClient->lpServer;

    (((IPC_HANDLE*)lpClient->lpHandle))->SrvClient.bCalledFromClientThread=true;
    IPC_CloseHandle((HANDLE)lpClient->lpHandle);

    IPC_AppendSystemMsg(lpServer,lpClient,IPC_MSG_CLIENT_DISCONNECTED);

    EnterSafeCriticalSection(&lpServer->csClients);
    {
        IPC_ACCEPTED_CLIENT_INFO *lpCur=lpServer->lpClients,*lpPrev=NULL;
        while (lpCur != lpClient)
        {
            lpPrev=lpCur;
            lpCur=lpCur->lpNext;
        }

        if (lpPrev)
            lpPrev->lpNext=lpCur->lpNext;
        else
            lpServer->lpClients=lpCur->lpNext;
    }
    LeaveSafeCriticalSection(&lpServer->csClients);

    SysCloseHandle(lpClient->hClientProc);
    MemFree(lpClient->TmpRecvBuf.lpTmpBuffer);

    SYSLIB::IPC_CloseSharedHandles(&lpClient->SharedObjects);

    MemFree(lpClient->lpRc4Key);

    MemFree(lpClient);
    return;
}

/**
    поток для отправки исходящих сообщений клиенту
**/
static void WINAPI IPC_ClientOutputEventsServer(IPC_ACCEPTED_CLIENT_INFO *lpHandle)
{
    IPC_PREPARED_TO_SEND_BUFFER PreparedBuffer={0};

    while (WaitForSingleObject(lpHandle->SharedObjects.hStopEvent,0) == WAIT_TIMEOUT)
    {
        if (PreparedBuffer.bSendMePlease)
        {
            SYSLIB::IPC_SendPreparedBuffer(&lpHandle->SharedObjects,&PreparedBuffer,IPC_MESSAGE_FROM_SRV_TO_CLI);
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
    поток для приема входящих сообщений от клиента
**/
static void WINAPI IPC_ClientInputEventsServer(IPC_ACCEPTED_CLIENT_INFO *lpClient)
{
    SERVER_HANDLE *lpServer=(SERVER_HANDLE*)lpClient->lpServer;

    SYSLIB::IPC_InitMessagesList(&lpClient->PostedMsgs);
    InitializeSafeCriticalSection(&lpClient->SentMsgs.csSent);

    HANDLE hClientOutputThread=SysCreateThreadSafe(NULL,0,(LPTHREAD_START_ROUTINE)IPC_ClientOutputEventsServer,lpClient,0,NULL);
    SetEvent(lpClient->hThreadInitEvent);

    while (WaitForSingleObject(lpClient->SharedObjects.hStopEvent,0) == WAIT_TIMEOUT)
    {
        if (WaitForSingleObject(lpClient->hClientProc,0) != WAIT_TIMEOUT)
        {
            /// клиентский процесс помер
            SetEvent(lpClient->SharedObjects.hStopEvent);
            break;
        }

        if (WaitForSingleObject(lpClient->SharedObjects.hCli2SrvEvent,1) == WAIT_OBJECT_0)
        {
            /// получена команда от клиента
            WaitForSingleObject(lpClient->SharedObjects.hProtectionMutex,INFINITE);
            {
                if (lpClient->SharedObjects.lpSharedMapping->bDirection == IPC_MESSAGE_FROM_CLI_TO_SRV)
                {
                    lpClient->TmpRecvBuf.lpRc4Key=lpClient->lpRc4Key;
                    lpClient->TmpRecvBuf.dwRc4KeySize=lpClient->dwRc4KeySize;
                    SYSLIB::IPC_RecvMessage(&lpClient->SentMsgs,lpClient->SharedObjects.lpSharedMapping,&lpClient->TmpRecvBuf,&lpServer->ReceivedMsgs,(HANDLE)lpClient->lpHandle);
                }
            }
            ReleaseMutex(lpClient->SharedObjects.hProtectionMutex);
        }
    }

    WaitForSingleObject(hClientOutputThread,INFINITE);
    SysCloseHandle(hClientOutputThread);

    IPC_DeleteClient(lpClient);
    return;
}

static bool IPC_AddNewClient(SERVER_HANDLE *lpServer,HANDLE hProc,IPC_CONNECTION_INFO *lpConnInfo)
{
    bool bRet=false;
    EnterSafeCriticalSection(&lpServer->csClients);
    {
        IPC_ACCEPTED_CLIENT_INFO *lpClient=(IPC_ACCEPTED_CLIENT_INFO*)MemAlloc(sizeof(IPC_ACCEPTED_CLIENT_INFO));
        do
        {
            if (!lpClient)
                break;

            if (!DuplicateHandle(hProc,lpConnInfo->hSrv2CliEvent,GetCurrentProcess(),&lpClient->SharedObjects.hSrv2CliEvent,0,false,DUPLICATE_SAME_ACCESS))
                break;

            if (!DuplicateHandle(hProc,lpConnInfo->hCli2SrvEvent,GetCurrentProcess(),&lpClient->SharedObjects.hCli2SrvEvent,0,false,DUPLICATE_SAME_ACCESS))
                break;

            if (!DuplicateHandle(hProc,lpConnInfo->hStopEvent,GetCurrentProcess(),&lpClient->SharedObjects.hStopEvent,0,false,DUPLICATE_SAME_ACCESS))
                break;

            if (!DuplicateHandle(hProc,lpConnInfo->hProtectionMutex,GetCurrentProcess(),&lpClient->SharedObjects.hProtectionMutex,0,false,DUPLICATE_SAME_ACCESS))
                break;

            if (!DuplicateHandle(hProc,lpConnInfo->hSharedMapping,GetCurrentProcess(),&lpClient->SharedObjects.hSharedMapping,0,false,DUPLICATE_SAME_ACCESS))
                break;

            lpClient->SharedObjects.lpSharedMapping=(IPC_COMMUNICATION_BUFFER*)MapViewOfFile(lpClient->SharedObjects.hSharedMapping,FILE_MAP_WRITE|FILE_MAP_READ,0,0,0);
            if (!lpClient->SharedObjects.lpSharedMapping)
                break;

            lpClient->SharedObjects.lpSharedMapping->bDirection=IPC_MESSAGE_BAD_DIRECTION;

            lpClient->lpServer=lpServer;
            lpClient->hClientProc=hProc;

            if (!lpServer->lpClients)
                lpServer->lpClients=lpClient;
            else
            {
                IPC_ACCEPTED_CLIENT_INFO *lpCur=lpServer->lpClients;
                while (lpCur->lpNext)
                    lpCur=lpCur->lpNext;

                lpCur->lpNext=lpClient;
            }

            if (lpServer->bSecure)
            {
                DWORD dwKeySize;
                do
                {
                    dwKeySize=xor128(256);
                }
                while (dwKeySize <= 20);

                StrGenerateA(lpConnInfo->szRc4Key,dwKeySize,STRGEN_STRONGPASS);
                lpConnInfo->dwRc4KeySize=dwKeySize;

                lpClient->lpRc4Key=(PCHAR)MemCopyEx(lpConnInfo->szRc4Key,dwKeySize);
                lpClient->dwRc4KeySize=dwKeySize;
            }

            IPC_HANDLE *lpHandle=SYSLIB::IPC_CreateHandle(IPC_ACCEPTED_CLIENT);
            lpClient->lpHandle=lpHandle;
            lpHandle->SrvClient.lpClient=lpClient;

            lpClient->hThreadInitEvent=CreateEvent(NULL,false,false,NULL);

            ThreadsGroup_CreateThread(lpServer->hEventsThreadsGroup,0,(LPTHREAD_START_ROUTINE)IPC_ClientInputEventsServer,lpClient,NULL,NULL);

            WaitForSingleObject(lpClient->hThreadInitEvent,INFINITE);
            SysCloseHandle(lpClient->hThreadInitEvent);

            IPC_AppendSystemMsg(lpServer,lpClient,IPC_MSG_CLIENT_CONNECTED);

            bRet=true;
        }
        while (false);

        if ((!bRet) && (lpClient))
        {
            SYSLIB::IPC_CloseSharedHandles(&lpClient->SharedObjects);

            MemFree(lpClient);
        }
    }
    LeaveSafeCriticalSection(&lpServer->csClients);
    return bRet;
}

static void WINAPI IPC_PipeServerThread(SERVER_HANDLE *lpHandle)
{
    OVERLAPPED ol={0};
    ol.hEvent=CreateEvent(NULL,true,false,NULL);
    ConnectNamedPipe(lpHandle->hPipe,&ol);

    SetEvent(lpHandle->hServerInitEvent);

    lpHandle->hEventsThreadsGroup=ThreadsGroup_Create();
    InitializeSafeCriticalSection(&lpHandle->csClients);

    SYSLIB::IPC_InitMessagesList(&lpHandle->ReceivedMsgs);

    InitializeSafeCriticalSection(&lpHandle->LastMsg.csLastMsg);

    IPC_PIPE_CONNECTION_INFO PipeConnInfo;
    while (WaitForSingleObject(lpHandle->hStopEvent,1) == WAIT_TIMEOUT)
    {
        if (WaitForSingleObject(ol.hEvent,0) == WAIT_OBJECT_0)
        {
            DWORD dwReaded=0;

            if ((ReadFile(lpHandle->hPipe,&PipeConnInfo,sizeof(PipeConnInfo),&dwReaded,NULL)) && (dwReaded > 0))
            {
                HANDLE hProc=SysOpenProcess(PROCESS_DUP_HANDLE|PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION|SYNCHRONIZE|PROCESS_QUERY_INFORMATION,PipeConnInfo.dwNewClientPID);
                if (hProc)
                {
                    bool bDone=false;
                    HANDLE hEvent;
                    if (DuplicateHandle(hProc,PipeConnInfo.hEvent,GetCurrentProcess(),&hEvent,0,false,DUPLICATE_SAME_ACCESS))
                    {
                        IPC_CONNECTION_INFO IpcConnInfo={0};
                        SIZE_T dwRead;
                        ReadProcessMemory(hProc,PipeConnInfo.lpConnectionInfo,&IpcConnInfo,sizeof(IpcConnInfo),&dwRead);

                        bDone=IPC_AddNewClient(lpHandle,hProc,&IpcConnInfo);
                        if (bDone)
                        {
                            DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),hProc,&IpcConnInfo.hServerProcess,0,false,DUPLICATE_SAME_ACCESS);
                            SIZE_T dwWrite;
                            WriteProcessMemory(hProc,PipeConnInfo.lpConnectionInfo,&IpcConnInfo,sizeof(IpcConnInfo),&dwWrite);
                        }

                        SetEvent(hEvent);
                        SysCloseHandle(hEvent);
                    }

                    if (!bDone)
                        SysCloseHandle(hProc);
                }
            }

            DisconnectNamedPipe(lpHandle->hPipe);
            ResetEvent(ol.hEvent);
            ConnectNamedPipe(lpHandle->hPipe,&ol);
        }
    }

    SysCloseHandle(ol.hEvent);
    SysCloseHandle(lpHandle->hPipe);

    /// останавливаем добавленных клиентов
    EnterSafeCriticalSection(&lpHandle->csClients);
    {
        IPC_ACCEPTED_CLIENT_INFO *lpClient=lpHandle->lpClients;
        while (lpClient)
        {
            SetEvent(lpClient->SharedObjects.hStopEvent);
            lpClient=lpClient->lpNext;
        }
    }
    LeaveSafeCriticalSection(&lpHandle->csClients);

    ThreadsGroup_WaitForAllExit(lpHandle->hEventsThreadsGroup,INFINITE);
    ThreadsGroup_CloseGroup(lpHandle->hEventsThreadsGroup);

    DeleteSafeCriticalSection(&lpHandle->csClients);

    /// очищаем очередь сообщений
    SYSLIB::IPC_CleanupMessagesList(&lpHandle->ReceivedMsgs);
    if (lpHandle->LastMsg.lpLastMsg)
        SYSLIB::IPC_FreeLastMsg(lpHandle->LastMsg.lpLastMsg->Msg.hSender,&lpHandle->LastMsg,true);
    return;
}

SYSLIBFUNC(HANDLE) IPC_CreateServerW(LPCWSTR lpName,BOOL bSecure)
{
    HANDLE hServer=NULL;
    LPWSTR lpPipe=SYSLIB::IPC_FormatPipeName(lpName);
    if (lpPipe)
    {
        HANDLE hPipe=CreateNamedPipeW(lpPipe,PIPE_ACCESS_INBOUND|FILE_FLAG_OVERLAPPED|WRITE_DAC|WRITE_OWNER,PIPE_TYPE_MESSAGE|PIPE_WAIT|PIPE_READMODE_MESSAGE,PIPE_UNLIMITED_INSTANCES,sizeof(IPC_PIPE_CONNECTION_INFO),sizeof(IPC_PIPE_CONNECTION_INFO),NMPWAIT_USE_DEFAULT_WAIT,NULL);
        if (hPipe != INVALID_HANDLE_VALUE)
        {
            SetObjectToLowIntegrity(hPipe);

            IPC_HANDLE *lpServer=SYSLIB::IPC_CreateHandle(IPC_SERVER_HANDLE);
            if (lpServer)
            {
                lpServer->Srv.hPipe=hPipe;
                lpServer->Srv.bSecure=bSecure;
                lpServer->Srv.hStopEvent=CreateEvent(NULL,true,false,NULL);
                lpServer->Srv.hServerInitEvent=CreateEvent(NULL,true,false,NULL);
                lpServer->Srv.hServerThread=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)IPC_PipeServerThread,&lpServer->Srv,0,NULL);
                WaitForSingleObject(lpServer->Srv.hServerInitEvent,INFINITE);
                SysCloseHandle(lpServer->Srv.hServerInitEvent);
                lpServer->Srv.hServerInitEvent=NULL;

                hServer=(HANDLE)lpServer;
            }
            else
                SysCloseHandle(hPipe);
        }
        MemFree(lpPipe);
    }
    return hServer;
}

SYSLIBFUNC(HANDLE) IPC_CreateServerA(LPCSTR lpName,BOOL bSecure)
{
    LPWSTR lpNameW=StrAnsiToUnicodeEx(lpName,0,NULL);

    HANDLE hServer=IPC_CreateServerW(lpNameW,bSecure);

    MemFree(lpNameW);
    return hServer;
}

