#include "sys_includes.h"

#include "syslib\criticalsections.h"
#include "syslib\system.h"
#include "syslib\str.h"
#include "syslib\mem.h"
#include "syslib\debug.h"
#include "syslib\chksum.h"
#include "syslib\rc4.h"

#include "ipc.h"
#include "common.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

static SAFE_CRITICAL_SECTION csHandles;
static IPC_HANDLE *lpHandles;
static DWORD dwInit;

namespace SYSLIB
{
    static void IPC_Init()
    {
        if (GetCurrentProcessId() != dwInit)
        {
            lpHandles=NULL;
            InitializeSafeCriticalSection(&csHandles);
            dwInit=GetCurrentProcessId();
        }
        return;
    }

    bool IPC_IsValidHandle(HANDLE hHandle)
    {
        bool bRet=false;
        IPC_Init();
        if (lpHandles)
        {
            IPC_HANDLE *lpHandle=lpHandles;
            while (lpHandle)
            {
                if (lpHandle == (IPC_HANDLE*)hHandle)
                {
                    bRet=true;
                    break;
                }

                lpHandle=lpHandle->lpNext;
            }
        }
        return bRet;
    }

    void IPC_SetEvent(IPC_EVENT *lpEvent)
    {
        InterlockedIncrement(&lpEvent->dwCount);
        SetEvent(lpEvent->hEvent);
        return;
    }

    DWORD IPC_WaitEvent(IPC_EVENT *lpEvent,DWORD dwMilliseconds)
    {
        DWORD dwRet=WaitForSingleObject(lpEvent->hEvent,dwMilliseconds);
        if (dwRet != WAIT_TIMEOUT)
        {
            DWORD dwCount=InterlockedCompareExchange(&lpEvent->dwCount,0,0);
            if (dwCount > 0)
                dwCount=InterlockedDecrement(&lpEvent->dwCount);

            if (!dwCount)
                ResetEvent(lpEvent->hEvent);
        }
        return dwRet;
    }

    IPC_HANDLE *IPC_CreateHandle(IPC_HANDLE_TYPE dwType)
    {
        IPC_HANDLE *lpHandle=(IPC_HANDLE*)MemAlloc(sizeof(IPC_HANDLE));
        if (lpHandle)
        {
            IPC_Init();
            lpHandle->dwType=dwType;
            EnterSafeCriticalSection(&csHandles);
            {
                if (!lpHandles)
                    lpHandles=lpHandle;
                else
                {
                    IPC_HANDLE *lpCur=lpHandles;
                    while (lpCur->lpNext)
                        lpCur=lpCur->lpNext;

                    lpCur->lpNext=lpHandle;
                }
            }
            LeaveSafeCriticalSection(&csHandles);
        }
        return lpHandle;
    }

    LPWSTR IPC_FormatPipeName(LPCWSTR lpName)
    {
        WCHAR szTmpBuf[100],*lpPort=NULL;
        SysGenerateUniqueMachineGuidW(lpName,szTmpBuf);
        StrFormatExW(&lpPort,dcrW_6df88834("\\\\.\\pipe\\%s"),szTmpBuf);
        return lpPort;
    }

    static void IPC_FreeQueuedMessage(PIPC_QUEUED_MESSAGE lpMsg)
    {
        if (lpMsg->dwMsg == IPC_MSG_DATA_RECEIVED)
            MemFree(lpMsg->ReceivedDataInfo.lpData);
        return;
    }

    void IPC_CleanupMessagesList(IPC_QUEUED_MESSAGES_LIST *lpMsg)
    {
        EnterSafeCriticalSection(&lpMsg->csMsg);
        {
            IPC_MESSAGES_LIST *lpCur=lpMsg->lpMsg;
            while (lpCur)
            {
                IPC_MESSAGES_LIST *lpPrev=lpCur;
                lpCur=lpCur->lpNext;

                IPC_FreeQueuedMessage(&lpPrev->Msg);

                if (lpPrev->hEvent)
                {
                    if (lpPrev->lpReply)
                    {
                        lpPrev->lpReply->dwReplySize=-1;
                        lpPrev->lpReply->lpReply=NULL;
                        lpPrev->lpReply->dwTime=GetTickCount();
                    }

                    SetEvent(lpPrev->hEvent);
                    SysCloseHandle(lpPrev->hEvent);
                }

                MemFree(lpPrev);
            }
        }
        LeaveSafeCriticalSection(&lpMsg->csMsg);

        DeleteSafeCriticalSection(&lpMsg->csMsg);

        IPC_SetEvent(&lpMsg->Event);
        SysCloseHandle(lpMsg->Event.hEvent);
        return;
    }

    void IPC_InitMessagesList(IPC_QUEUED_MESSAGES_LIST *lpMsg)
    {
        lpMsg->Event.hEvent=CreateEvent(NULL,true,false,NULL);
        InitializeSafeCriticalSection(&lpMsg->csMsg);
        return;
    }

    static void IPC_FreeMsgListItem(HANDLE hHandle,IPC_MESSAGES_LIST **lppMsg)
    {
        IPC_MESSAGES_LIST *lpMsg=*lppMsg;

        if (lpMsg->Msg.dwMsg == IPC_MSG_DATA_RECEIVED)
            MemFree(lpMsg->Msg.ReceivedDataInfo.lpData);

        if (lpMsg->bReplyNeeded)
            IPC_ReplyMessage(hHandle,NULL,0,0);

        MemFree(lpMsg);
        *lppMsg=NULL;
        return;
    }

    static bool IPC_GetQueuedMessageInt(IPC_QUEUED_MESSAGES_LIST *lpReceivedMsgs,LAST_MSG_INFO *lpLastMsg,PIPC_QUEUED_MESSAGE lpMsg,DWORD dwMilliseconds)
    {
        bool bRet=false;

        DWORD dwRes=IPC_WaitEvent(&lpReceivedMsgs->Event,dwMilliseconds);
        if (dwRes == WAIT_OBJECT_0)
        {
            IPC_MESSAGES_LIST *lpIPCMsg;
            EnterSafeCriticalSection(&lpReceivedMsgs->csMsg);
            {
                lpIPCMsg=lpReceivedMsgs->lpMsg;

                if (lpIPCMsg)
                    lpReceivedMsgs->lpMsg=lpIPCMsg->lpNext;
            }
            LeaveSafeCriticalSection(&lpReceivedMsgs->csMsg);

            if (lpIPCMsg)
            {
                bRet=true;
                memcpy(lpMsg,&lpIPCMsg->Msg,sizeof(*lpMsg));
                lpMsg->dwSize=sizeof(*lpMsg);

                EnterSafeCriticalSection(&lpLastMsg->csLastMsg);
                    lpLastMsg->lpLastMsg=lpIPCMsg;
                LeaveSafeCriticalSection(&lpLastMsg->csLastMsg);
            }
        }
        else if (dwRes == WAIT_TIMEOUT)
        {
            bRet=true;
            memset(lpMsg,0,sizeof(*lpMsg));
            lpMsg->dwMsg=IPC_MSG_IDLE;
            lpMsg->dwTime=GetTickCount();
            lpMsg->dwSize=sizeof(*lpMsg);
        }
        return bRet;
    }

    void IPC_FreeLastMsg(HANDLE hHandle,LAST_MSG_INFO *lpLastMsg,bool bDelete)
    {
        EnterSafeCriticalSection(&lpLastMsg->csLastMsg);
        {
            if (lpLastMsg->lpLastMsg)
            {
                IPC_FreeMsgListItem(hHandle,&lpLastMsg->lpLastMsg);
                lpLastMsg->lpLastMsg=NULL;
            }

            if (lpLastMsg->lpLastReply)
            {
                MemFree(lpLastMsg->lpLastReply);
                lpLastMsg->lpLastReply=NULL;
            }
        }
        LeaveSafeCriticalSection(&lpLastMsg->csLastMsg);

        if (bDelete)
            DeleteSafeCriticalSection(&lpLastMsg->csLastMsg);
        return;
    }

    void IPC_CloseSharedHandles(CLIENTSERVER_SHARED_OBJECTS *lpHandles)
    {
        if (lpHandles->hSrv2CliEvent)
            SysCloseHandle(lpHandles->hSrv2CliEvent);

        if (lpHandles->hCli2SrvEvent)
            SysCloseHandle(lpHandles->hCli2SrvEvent);

        if (lpHandles->hStopEvent)
            SysCloseHandle(lpHandles->hStopEvent);

        if (lpHandles->hProtectionMutex)
            SysCloseHandle(lpHandles->hProtectionMutex);

        if (lpHandles->lpSharedMapping)
            UnmapViewOfFile(lpHandles->lpSharedMapping);

        if (lpHandles->hSharedMapping)
            SysCloseHandle(lpHandles->hSharedMapping);

        return;
    }

    static DWORD IPC_GetUniqueCmdId(CLIENTSERVER_SHARED_OBJECTS *lpHandles)
    {
        WaitForSingleObject(lpHandles->hProtectionMutex,INFINITE);
            DWORD dwRet=lpHandles->lpSharedMapping->dwLastCmdId++;
        ReleaseMutex(lpHandles->hProtectionMutex);

        return dwRet;
    }

    static bool IPC_SendDataInt(CLIENTSERVER_SHARED_OBJECTS *lpHandles,IPC_QUEUED_MESSAGES_LIST *lpPostedMsgs,const LPVOID lpData,DWORD dwDataSize,DWORD dwParam,bool bWait=false,PIPC_MESSAGE_REPLY lpReply=NULL,IPC_SYSTEM_COMMAND bCmd=IPC_SYSCMD_NEW_MESSAGE,DWORD dwUniqueMsgId=0)
    {
        bool bRet=false;
        HANDLE hEvent=NULL;
        EnterSafeCriticalSection(&lpPostedMsgs->csMsg);
        {
            IPC_MESSAGES_LIST *lpNewMsg=(IPC_MESSAGES_LIST*)MemAlloc(sizeof(IPC_MESSAGES_LIST));
            if (lpNewMsg)
            {
                lpNewMsg->bCmd=bCmd;

                if (bCmd == IPC_SYSCMD_MESSAGE_REPLY)
                    lpNewMsg->dwUniqueMsgId=dwUniqueMsgId;
                else
                {
                    lpNewMsg->dwUniqueMsgId=IPC_GetUniqueCmdId(lpHandles);
                    lpNewMsg->bReplyNeeded=bWait;
                }

                lpNewMsg->Msg.dwMsg=IPC_MSG_DATA_RECEIVED;
                lpNewMsg->lpReply=lpReply;
                lpNewMsg->Msg.ReceivedDataInfo.dwParam=dwParam;
                if (dwDataSize)
                {
                    lpNewMsg->Msg.ReceivedDataInfo.dwDataSize=dwDataSize;
                    lpNewMsg->Msg.ReceivedDataInfo.lpData=MemCopyEx(lpData,dwDataSize);
                }

                bRet=((!dwDataSize) || (lpNewMsg->Msg.ReceivedDataInfo.lpData));

                if (bRet)
                {
                    if (bWait)
                        hEvent=lpNewMsg->hEvent=CreateEvent(NULL,false,false,NULL);

                    if (lpPostedMsgs->lpMsg)
                    {
                        IPC_MESSAGES_LIST *lpCur=lpPostedMsgs->lpMsg;
                        while (lpCur->lpNext)
                            lpCur=lpCur->lpNext;

                        lpCur->lpNext=lpNewMsg;
                    }
                    else
                        lpPostedMsgs->lpMsg=lpNewMsg;
                }
                else
                    MemFree(lpNewMsg);
            }
        }
        LeaveSafeCriticalSection(&lpPostedMsgs->csMsg);

        if (bRet)
        {
            IPC_SetEvent(&lpPostedMsgs->Event);

            if (bWait)
            {
                if (lpReply)
                    memset(lpReply,0,sizeof(*lpReply));

                bRet=(WaitForSingleObject(hEvent,INFINITE) == WAIT_OBJECT_0);
                if (bRet)
                {
                    if ((lpReply) && (lpReply->dwReplySize == -1))
                    {
                        lpReply->dwReplySize=0;
                        bRet=false;
                    }
                }
            }
        }

        if (hEvent)
            SysCloseHandle(hEvent);

        return bRet;
    }

    static void IPC_MessageReceived(IPC_QUEUED_MESSAGES_LIST *lpReceivedMessagesList,LPVOID lpMessage,DWORD dwSize,DWORD dwParam,HANDLE hSender,DWORD dwTime,bool bReplyNeeded,DWORD dwUniqueMsgId)
    {
        EnterSafeCriticalSection(&lpReceivedMessagesList->csMsg);
        {
            IPC_MESSAGES_LIST *lpMsg=(IPC_MESSAGES_LIST*)MemAlloc(sizeof(IPC_MESSAGES_LIST));
            if (lpMsg)
            {
                if (dwSize)
                {
                    lpMsg->bReplyNeeded=bReplyNeeded;
                    lpMsg->dwUniqueMsgId=dwUniqueMsgId;

                    lpMsg->Msg.ReceivedDataInfo.lpData=MemQuickAlloc(dwSize);
                    if (lpMsg->Msg.ReceivedDataInfo.lpData)
                    {
                        lpMsg->Msg.ReceivedDataInfo.dwDataSize=dwSize;
                        memcpy(lpMsg->Msg.ReceivedDataInfo.lpData,lpMessage,dwSize);
                    }
                }

                if ((!dwSize) || (lpMsg->Msg.ReceivedDataInfo.lpData))
                {
                    lpMsg->Msg.dwTime=dwTime;

                    lpMsg->Msg.dwMsg=IPC_MSG_DATA_RECEIVED;
                    lpMsg->Msg.hSender=hSender;
                    lpMsg->Msg.dwSenderProcessId=IPC_GetProcessId(hSender);
                    lpMsg->Msg.ReceivedDataInfo.dwParam=dwParam;

                    if (lpReceivedMessagesList->lpMsg)
                    {
                        IPC_MESSAGES_LIST *lpCur=lpReceivedMessagesList->lpMsg;
                        while (lpCur->lpNext)
                            lpCur=lpCur->lpNext;

                        lpCur->lpNext=lpMsg;
                    }
                    else
                        lpReceivedMessagesList->lpMsg=lpMsg;

                    IPC_SetEvent(&lpReceivedMessagesList->Event);
                }
                else
                    MemFree(lpMsg);
            }
        }
        LeaveSafeCriticalSection(&lpReceivedMessagesList->csMsg);
        return;
    }

    static void IPC_FreeTmpBuffer(TEMPLATE_MESSAGE_BUFFER *lpTmpBuffer)
    {
        MemFree(lpTmpBuffer->lpDecryptedBuf);
        MemFree(lpTmpBuffer->lpTmpBuffer);
        memset(lpTmpBuffer,0,sizeof(*lpTmpBuffer));
        return;
    }

    static void IPC_MessageReplyReceived(SENT_MESSAGES_LIST *lpList,DWORD dwUniqueMsgId,DWORD dwTime,LPVOID lpReply,DWORD dwReplySize,DWORD dwParam)
    {
        EnterSafeCriticalSection(&lpList->csSent);
        {
            bool bFound=false;

            IPC_MESSAGES_LIST *lpCur=lpList->lpSent,*lpPrev=NULL;
            while (lpCur)
            {
                if (lpCur->dwUniqueMsgId == dwUniqueMsgId)
                {
                    bFound=true;

                    if (lpCur->lpReply)
                    {
                        LPVOID lpNewBuf=MemQuickAlloc(dwReplySize);
                        if (lpNewBuf)
                        {
                            lpCur->lpReply->dwReplySize=dwReplySize;
                            lpCur->lpReply->lpReply=lpNewBuf;
                            memcpy(lpNewBuf,lpReply,dwReplySize);
                        }
                        else
                        {
                            lpCur->lpReply->dwReplySize=-1;
                            lpCur->lpReply->lpReply=NULL;
                        }

                        lpCur->lpReply->dwTime=dwTime;
                        lpCur->lpReply->dwParam=dwParam;
                    }

                    if (lpPrev)
                        lpPrev->lpNext=lpCur->lpNext;
                    else
                        lpList->lpSent=lpCur->lpNext;

                    SetEvent(lpCur->hEvent);

                    if (lpPrev)
                        lpPrev->lpNext=lpCur->lpNext;
                    else
                        lpList->lpSent=lpCur->lpNext;

                    MemFree(lpCur);
                    break;
                }

                lpPrev=lpCur;
                lpCur=lpCur->lpNext;
            }
        }
        LeaveSafeCriticalSection(&lpList->csSent);
        return;
    }

    void IPC_RecvMessage(SENT_MESSAGES_LIST *lpSentList,IPC_COMMUNICATION_BUFFER *lpCommBuffer,TEMPLATE_MESSAGE_BUFFER *lpTmpBuffer,IPC_QUEUED_MESSAGES_LIST *lpReceivedMessagesList,HANDLE hClient)
    {
        bool bCompleted=false;
        switch (lpCommBuffer->dwSysCmd)
        {
            case IPC_SYSCMD_MESSAGE_REPLY:
            case IPC_SYSCMD_NEW_MESSAGE:
            {
                if (lpTmpBuffer->lpTmpBuffer)
                {
                    /**
                        есть недополученное сообщение -
                        очищаем буфер
                    **/
                    IPC_FreeTmpBuffer(lpTmpBuffer);
                }

                if (lpCommBuffer->dwFullMessageSize > MAX_IPC_MESSAGE_SIZE)
                {
                    /**
                        передан слишком жирный кусок данных -
                        резервируем место под данные
                    **/
                    lpTmpBuffer->lpTmpBuffer=MemQuickAlloc(lpCommBuffer->dwFullMessageSize);
                    if (!lpTmpBuffer->lpTmpBuffer)
                        break;

                    LPBYTE lpDecryptedBuf=lpCommBuffer->bMessage;
                    if (lpTmpBuffer->dwRc4KeySize)
                    {
                        lpDecryptedBuf=(LPBYTE)lpTmpBuffer->lpTmpBuffer;
                        rc4Full(lpTmpBuffer->lpRc4Key,lpTmpBuffer->dwRc4KeySize,lpCommBuffer->bMessage,MAX_IPC_MESSAGE_SIZE,lpDecryptedBuf);
                    }

                    if (MurmurHash3(lpDecryptedBuf,MAX_IPC_MESSAGE_SIZE) != lpCommBuffer->dwCheckSum)
                    {
                        /// wtf?!
                        bCompleted=true;
                        break;
                    }

                    lpTmpBuffer->bIsReply=(lpCommBuffer->dwSysCmd == IPC_SYSCMD_MESSAGE_REPLY);
                    lpTmpBuffer->dwUniqueMsgId=lpCommBuffer->dwUniqueMsgId;
                    lpTmpBuffer->bReplyNeeded=lpCommBuffer->bReplyNeeded;
                    lpTmpBuffer->dwTime=lpCommBuffer->dwTime;
                    lpTmpBuffer->dwRestBytes=lpCommBuffer->dwFullMessageSize;
                    lpTmpBuffer->dwParam=lpCommBuffer->dwParam;

                    if (!lpTmpBuffer->dwRc4KeySize)
                        memcpy(lpTmpBuffer->lpTmpBuffer,lpCommBuffer->bMessage,MAX_IPC_MESSAGE_SIZE);

                    lpTmpBuffer->lpTmpBufferPosition=(LPVOID)((LPBYTE)lpTmpBuffer->lpTmpBuffer+MAX_IPC_MESSAGE_SIZE);
                    lpTmpBuffer->dwRestBytes-=MAX_IPC_MESSAGE_SIZE;
                }
                else
                {
                    bCompleted=true;

                    LPBYTE lpDecryptedBuf=lpCommBuffer->bMessage;
                    if (lpTmpBuffer->dwRc4KeySize)
                        lpTmpBuffer->lpDecryptedBuf=lpDecryptedBuf=rc4FullEx(lpTmpBuffer->lpRc4Key,lpTmpBuffer->dwRc4KeySize,lpCommBuffer->bMessage,lpCommBuffer->dwFullMessageSize);

                    if (MurmurHash3(lpDecryptedBuf,lpCommBuffer->dwFullMessageSize) != lpCommBuffer->dwCheckSum)
                    {
                        /// wtf?!
                        break;
                    }

                    if (lpCommBuffer->dwSysCmd != IPC_SYSCMD_MESSAGE_REPLY)
                        IPC_MessageReceived(lpReceivedMessagesList,lpDecryptedBuf,lpCommBuffer->dwFullMessageSize,lpCommBuffer->dwParam,hClient,lpCommBuffer->dwTime,lpCommBuffer->bReplyNeeded,lpCommBuffer->dwUniqueMsgId);
                    else
                        IPC_MessageReplyReceived(lpSentList,lpCommBuffer->dwUniqueMsgId,lpCommBuffer->dwTime,lpDecryptedBuf,lpCommBuffer->dwFullMessageSize,lpCommBuffer->dwParam);
                }
                break;
            }
            case IPC_SYSCMD_NEXT_MESSAGE_PART:
            {
                if (!lpTmpBuffer->lpTmpBuffer)
                    break;

                LPBYTE lpDecryptedBuf=lpCommBuffer->bMessage;
                if (lpTmpBuffer->dwRc4KeySize)
                {
                    lpDecryptedBuf=(LPBYTE)lpTmpBuffer->lpTmpBufferPosition;
                    rc4Full(lpTmpBuffer->lpRc4Key,lpTmpBuffer->dwRc4KeySize,lpCommBuffer->bMessage,lpCommBuffer->dwDataPartSize,lpTmpBuffer->lpTmpBufferPosition);
                }

                if (MurmurHash3(lpDecryptedBuf,lpCommBuffer->dwDataPartSize) != lpCommBuffer->dwCheckSum)
                {
                    /// wtf?!
                    bCompleted=true;
                    break;
                }

                if (!lpTmpBuffer->dwRc4KeySize)
                    memcpy(lpTmpBuffer->lpTmpBufferPosition,lpCommBuffer->bMessage,lpCommBuffer->dwDataPartSize);

                lpTmpBuffer->lpTmpBufferPosition=(LPVOID)((LPBYTE)lpTmpBuffer->lpTmpBufferPosition+lpCommBuffer->dwDataPartSize);
                lpTmpBuffer->dwRestBytes-=lpCommBuffer->dwDataPartSize;

                if (!lpTmpBuffer->dwRestBytes)
                {
                    /**
                        все данные прочитаны - добавляем в
                        очередь на отдачу
                    **/
                    DWORD dwSize=(DWORD_PTR)lpTmpBuffer->lpTmpBufferPosition-(DWORD_PTR)lpTmpBuffer->lpTmpBuffer;

                    if (!lpTmpBuffer->bIsReply)
                        IPC_MessageReceived(lpReceivedMessagesList,lpTmpBuffer->lpTmpBuffer,dwSize,lpTmpBuffer->dwParam,hClient,lpTmpBuffer->dwTime,lpTmpBuffer->bReplyNeeded,lpTmpBuffer->dwUniqueMsgId);
                    else
                        IPC_MessageReplyReceived(lpSentList,lpTmpBuffer->dwUniqueMsgId,lpTmpBuffer->dwTime,lpTmpBuffer->lpTmpBuffer,dwSize,lpTmpBuffer->dwParam);

                    bCompleted=true;
                }
                break;
            }
        }

        if (bCompleted)
            IPC_FreeTmpBuffer(lpTmpBuffer);

        lpCommBuffer->bDirection=IPC_MESSAGE_BAD_DIRECTION;
        lpCommBuffer->dwSysCmd=IPC_SYSCMD_BAD_CMD;
        lpCommBuffer->dwFullMessageSize=0;
        lpCommBuffer->bReplyNeeded=false;
        lpCommBuffer->dwUniqueMsgId=0;
        lpCommBuffer->dwCheckSum=0;
        return;
    }

    static void IPC_FreePreparedBuffer(IPC_PREPARED_TO_SEND_BUFFER *lpBuffer,bool bFail)
    {
        if (lpBuffer->lpMsgToSend)
            MemFree(lpBuffer->lpMsgToSend);

        if (lpBuffer->hEvent)
        {
            if (bFail)
            {
                if (lpBuffer->lpReply)
                {
                    lpBuffer->lpReply->dwReplySize=-1;
                    lpBuffer->lpReply->lpReply=NULL;
                    lpBuffer->lpReply->dwTime=GetTickCount();
                }

                SetEvent(lpBuffer->hEvent);
            }
        }

        memset(lpBuffer,0,sizeof(*lpBuffer));
        return;
    }

    void IPC_SendPreparedBuffer(CLIENTSERVER_SHARED_OBJECTS *lpSharedObjects,IPC_PREPARED_TO_SEND_BUFFER *lpBuffer,IPC_MESSAGE_DIRECTION bDirection)
    {
        do
        {
            if (bDirection == IPC_MESSAGE_BAD_DIRECTION)
            {
                /// WTF?!
                IPC_FreePreparedBuffer(lpBuffer,true);
                break;
            }

            if ((lpBuffer->bDataSent) && (!lpBuffer->dwBytesToSend))
            {
                /// все данные отправлены, збс :)
                IPC_FreePreparedBuffer(lpBuffer,false);
                break;
            }

            WaitForSingleObject(lpSharedObjects->hProtectionMutex,INFINITE);
            {
                IPC_COMMUNICATION_BUFFER *lpSharedMapping=lpSharedObjects->lpSharedMapping;
                if (lpSharedMapping->bDirection == IPC_MESSAGE_BAD_DIRECTION)
                {
                    lpSharedMapping->bDirection=bDirection;

                    DWORD dwBytesSent=min(MAX_IPC_MESSAGE_SIZE,lpBuffer->dwBytesToSend);

                    if (lpBuffer->bDataSent)
                    {
                        lpSharedMapping->dwSysCmd=IPC_SYSCMD_NEXT_MESSAGE_PART;
                        lpSharedMapping->dwDataPartSize=dwBytesSent;
                    }
                    else
                    {
                        lpSharedMapping->dwTime=GetTickCount();
                        lpSharedMapping->dwSysCmd=lpBuffer->bCmd;
                        lpSharedMapping->dwFullMessageSize=lpBuffer->dwBytesToSend;
                        lpSharedMapping->dwUniqueMsgId=lpBuffer->dwUniqueMsgId;
                        lpSharedMapping->bReplyNeeded=lpBuffer->bReplyNeeded;
                        lpSharedMapping->dwParam=lpBuffer->dwParam;

                        lpBuffer->bDataSent=true;
                    }

                    if (dwBytesSent)
                    {
                        if (lpBuffer->dwRc4KeySize)
                            rc4Full(lpBuffer->lpRc4Key,lpBuffer->dwRc4KeySize,lpBuffer->lpPtr,dwBytesSent,lpSharedMapping->bMessage);
                        else
                            memcpy(lpSharedMapping->bMessage,lpBuffer->lpPtr,dwBytesSent);

                        lpSharedMapping->dwCheckSum=MurmurHash3(lpBuffer->lpPtr,dwBytesSent);

                        lpBuffer->dwBytesToSend-=dwBytesSent;
                        lpBuffer->lpPtr+=dwBytesSent;
                    }

                    if (bDirection == IPC_MESSAGE_FROM_CLI_TO_SRV)
                        SetEvent(lpSharedObjects->hCli2SrvEvent);
                    else if (bDirection == IPC_MESSAGE_FROM_SRV_TO_CLI)
                        SetEvent(lpSharedObjects->hSrv2CliEvent);
                }
            }
            ReleaseMutex(lpSharedObjects->hProtectionMutex);
        }
        while (false);
        return;
    }

    void IPC_CleanupSentMessagesList(SENT_MESSAGES_LIST *lpSentMsgs)
    {
        EnterSafeCriticalSection(&lpSentMsgs->csSent);
        {
            IPC_MESSAGES_LIST *lpCur=lpSentMsgs->lpSent;
            while (lpCur)
            {
                if (lpCur->lpReply)
                {
                    lpCur->lpReply->dwReplySize=-1;
                    lpCur->lpReply->lpReply=NULL;
                    lpCur->lpReply->dwTime=GetTickCount();
                }

                SetEvent(lpCur->hEvent);
                MemFree(lpCur->Msg.ReceivedDataInfo.lpData);

                IPC_MESSAGES_LIST *lpPrev=lpCur;
                lpCur=lpCur->lpNext;

                MemFree(lpPrev);
            }
        }
        LeaveSafeCriticalSection(&lpSentMsgs->csSent);

        DeleteSafeCriticalSection(&lpSentMsgs->csSent);
        return;
    }

    void IPC_HandlePostedMessage(IPC_QUEUED_MESSAGES_LIST *lpPostedMsgs,SENT_MESSAGES_LIST *lpSentMsgs,IPC_PREPARED_TO_SEND_BUFFER *lpPreparedBuffer)
    {
        IPC_MESSAGES_LIST *lpMsg;
        EnterSafeCriticalSection(&lpPostedMsgs->csMsg);
        {
            lpMsg=lpPostedMsgs->lpMsg;
            if (lpMsg)
                lpPostedMsgs->lpMsg=lpMsg->lpNext;
        }
        LeaveSafeCriticalSection(&lpPostedMsgs->csMsg);

        if (lpMsg)
        {
            lpPreparedBuffer->bSendMePlease=true;
            lpPreparedBuffer->bCmd=lpMsg->bCmd;
            lpPreparedBuffer->dwUniqueMsgId=lpMsg->dwUniqueMsgId;
            lpPreparedBuffer->lpPtr=lpPreparedBuffer->lpMsgToSend=(byte*)lpMsg->Msg.ReceivedDataInfo.lpData;
            lpPreparedBuffer->hEvent=lpMsg->hEvent;
            lpPreparedBuffer->dwBytesToSend=lpMsg->Msg.ReceivedDataInfo.dwDataSize;
            lpPreparedBuffer->dwParam=lpMsg->Msg.ReceivedDataInfo.dwParam;

            if (!lpMsg->bReplyNeeded)
                MemFree(lpMsg);
            else
            {
                lpPreparedBuffer->lpReply=lpMsg->lpReply;
                lpPreparedBuffer->bReplyNeeded=lpMsg->bReplyNeeded;

                /**
                    функция-отправитель висит в ожидании ответа -
                    заносим сообщение в список ожидающих ответа
                **/
                EnterSafeCriticalSection(&lpSentMsgs->csSent);
                {
                    if (lpSentMsgs->lpSent)
                    {
                        IPC_MESSAGES_LIST *lpCur=lpSentMsgs->lpSent;
                        while (lpCur->lpNext)
                            lpCur=lpCur->lpNext;

                        lpCur->lpNext=lpMsg;
                    }
                    else
                        lpSentMsgs->lpSent=lpMsg;
                }
                LeaveSafeCriticalSection(&lpSentMsgs->csSent);
            }
        }
        return;
    }
}

static void WaitMessageQueue(IPC_QUEUED_MESSAGES_LIST *lpPostedMsgs)
{
    while (WaitForSingleObject(lpPostedMsgs->Event.hEvent,1) == WAIT_OBJECT_0) ;
    return;
}

SYSLIBFUNC(void) IPC_CloseHandle(HANDLE hHandle)
{
    if (SYSLIB::IPC_IsValidHandle(hHandle))
    {
        IPC_HANDLE *lpHandle=(IPC_HANDLE*)hHandle;
        EnterSafeCriticalSection(&csHandles);
        {
            IPC_HANDLE *lpCur=lpHandles,*lpPrev=NULL;
            while (lpCur != lpHandle)
            {
                lpPrev=lpCur;
                lpCur=lpCur->lpNext;
            }

            if (lpPrev)
                lpPrev->lpNext=lpCur->lpNext;
            else
                lpHandles=lpCur->lpNext;
        }
        LeaveSafeCriticalSection(&csHandles);

        switch (lpHandle->dwType)
        {
            case IPC_SERVER_HANDLE:
            {
                SetEvent(lpHandle->Srv.hStopEvent);
                WaitForSingleObject(lpHandle->Srv.hServerThread,INFINITE);
                SysCloseHandle(lpHandle->Srv.hServerThread);
                break;
            }
            case IPC_ACCEPTED_CLIENT:
            {
                if (lpHandle->SrvClient.bCalledFromClientThread)
                    break;

                /// ждем отправки всех сообщений перед закрытием
                WaitMessageQueue(&lpHandle->SrvClient.lpClient->PostedMsgs);

                SetEvent(lpHandle->SrvClient.lpClient->SharedObjects.hStopEvent);
                break;
            }
            case IPC_CLIENT_HANDLE:
            {
                /// ждем отправки всех сообщений перед закрытием
                WaitMessageQueue(&lpHandle->Cli.PostedMsgs);

                SetEvent(lpHandle->Cli.SharedObjects.hStopEvent);
                WaitForSingleObject(lpHandle->Cli.hEventsThread,INFINITE);
                SysCloseHandle(lpHandle->Cli.hEventsThread);
                break;
            }
        }
        MemFree(lpHandle);
    }
    return;
}

SYSLIBFUNC(BOOL) IPC_ReplyMessage(HANDLE hHandle,const LPVOID lpReply,DWORD dwReplySize,DWORD dwParam)
{
    bool bRet=false;
    do
    {
        if (!SYSLIB::IPC_IsValidHandle(hHandle))
            break;

        if ((lpReply) || (dwReplySize))
        {
            if (!SYSLIB_SAFE::CheckParamRead(lpReply,dwReplySize))
                break;
        }

        /**
            проверяем последнее полученное сообщение,
            если требует ответа - отправляем ответ
        **/
        IPC_HANDLE *lpHandle=(IPC_HANDLE*)hHandle;
        if (lpHandle->dwType == IPC_ACCEPTED_CLIENT)
        {
            DWORD dwUniqueCmdId;
            SERVER_HANDLE *lpServer=(SERVER_HANDLE *)lpHandle->SrvClient.lpClient->lpServer;
            EnterSafeCriticalSection(&lpServer->LastMsg.csLastMsg);
            {
                if ((lpServer->LastMsg.lpLastMsg) && (lpServer->LastMsg.lpLastMsg->bReplyNeeded))
                {
                    dwUniqueCmdId=lpServer->LastMsg.lpLastMsg->dwUniqueMsgId;
                    bRet=true;
                }
            }
            LeaveSafeCriticalSection(&lpServer->LastMsg.csLastMsg);

            CLIENTSERVER_SHARED_OBJECTS *lpHandles=&lpHandle->SrvClient.lpClient->SharedObjects;
            if (bRet)
                bRet=SYSLIB::IPC_SendDataInt(lpHandles,&lpHandle->SrvClient.lpClient->PostedMsgs,lpReply,dwReplySize,dwParam,false,NULL,IPC_SYSCMD_MESSAGE_REPLY,dwUniqueCmdId);
            else
            {
                /**
                    если отвечать не на что - отправляем
                    новое сообщение
                **/
                bRet=SYSLIB::IPC_SendDataInt(lpHandles,&lpHandle->SrvClient.lpClient->PostedMsgs,lpReply,dwReplySize,dwParam,false);
            }
        }
        else if (lpHandle->dwType == IPC_CLIENT_HANDLE)
        {
            DWORD dwUniqueCmdId;
            CLIENT_HANDLE *lpClient=&lpHandle->Cli;
            EnterSafeCriticalSection(&lpClient->LastMsg.csLastMsg);
            {
                if ((lpClient->LastMsg.lpLastMsg) && (lpClient->LastMsg.lpLastMsg->bReplyNeeded))
                {
                    dwUniqueCmdId=lpClient->LastMsg.lpLastMsg->dwUniqueMsgId;
                    bRet=true;
                }
            }
            LeaveSafeCriticalSection(&lpClient->LastMsg.csLastMsg);

            CLIENTSERVER_SHARED_OBJECTS *lpHandles=&lpHandle->Cli.SharedObjects;
            if (bRet)
                bRet=SYSLIB::IPC_SendDataInt(lpHandles,&lpHandle->Cli.PostedMsgs,lpReply,dwReplySize,dwParam,false,NULL,IPC_SYSCMD_MESSAGE_REPLY,dwUniqueCmdId);
            else
                bRet=SYSLIB::IPC_SendDataInt(lpHandles,&lpHandle->Cli.PostedMsgs,lpReply,dwReplySize,dwParam,false);
        }
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) IPC_GetQueuedMessage(HANDLE hHandle,PIPC_QUEUED_MESSAGE lpMsg,DWORD dwMilliseconds)
{
    bool bRet=false;
    do
    {
        if (!SYSLIB::IPC_IsValidHandle(hHandle))
            break;

        if (!SYSLIB_SAFE::CheckParamWrite(lpMsg,sizeof(*lpMsg)))
            break;

        if (lpMsg->dwSize != sizeof(*lpMsg))
            break;

        IPC_HANDLE *lpHandle=(IPC_HANDLE*)hHandle;
        if (lpHandle->dwType == IPC_SERVER_HANDLE)
        {
            if (lpHandle->Srv.LastMsg.lpLastMsg)
                SYSLIB::IPC_FreeLastMsg(lpHandle->Srv.LastMsg.lpLastMsg->Msg.hSender,&lpHandle->Srv.LastMsg,false);

            bRet=SYSLIB::IPC_GetQueuedMessageInt(&lpHandle->Srv.ReceivedMsgs,&lpHandle->Srv.LastMsg,lpMsg,dwMilliseconds);
        }
        else if (lpHandle->dwType == IPC_CLIENT_HANDLE)
        {
            SYSLIB::IPC_FreeLastMsg(hHandle,&lpHandle->Cli.LastMsg,false);

            bRet=SYSLIB::IPC_GetQueuedMessageInt(&lpHandle->Cli.ReceivedMsgs,&lpHandle->Cli.LastMsg,lpMsg,dwMilliseconds);
        }
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) IPC_SendMessage(HANDLE hHandle,const LPVOID lpData,DWORD dwDataSize,DWORD dwParam,PIPC_MESSAGE_REPLY lpReply)
{
    bool bRet=false;
    do
    {
        if (!SYSLIB::IPC_IsValidHandle(hHandle))
            break;

        if ((lpData) || (dwDataSize))
        {
            if (!SYSLIB_SAFE::CheckParamRead(lpData,dwDataSize))
                break;
        }

        LAST_MSG_INFO *lpLastMsg=NULL;
        IPC_HANDLE *lpHandle=(IPC_HANDLE*)hHandle;
        if (lpHandle->dwType == IPC_ACCEPTED_CLIENT)
        {
            CLIENTSERVER_SHARED_OBJECTS *lpHandles=&lpHandle->SrvClient.lpClient->SharedObjects;
            bRet=SYSLIB::IPC_SendDataInt(lpHandles,&lpHandle->SrvClient.lpClient->PostedMsgs,lpData,dwDataSize,dwParam,true,lpReply);
            if ((bRet) && (lpReply) && (lpReply->lpReply))
                lpLastMsg=&((SERVER_HANDLE*)lpHandle->SrvClient.lpClient->lpServer)->LastMsg;
        }
        else if (lpHandle->dwType == IPC_CLIENT_HANDLE)
        {
            CLIENTSERVER_SHARED_OBJECTS *lpHandles=&lpHandle->Cli.SharedObjects;
            bRet=SYSLIB::IPC_SendDataInt(lpHandles,&lpHandle->Cli.PostedMsgs,lpData,dwDataSize,dwParam,true,lpReply);
            if ((bRet) && (lpReply) && (lpReply->lpReply))
                lpLastMsg=&lpHandle->Cli.LastMsg;
        }

        if (lpLastMsg)
        {
            EnterSafeCriticalSection(&lpLastMsg->csLastMsg);
                lpLastMsg->lpLastReply=lpReply->lpReply;
            LeaveSafeCriticalSection(&lpLastMsg->csLastMsg);
        }
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) IPC_PostMessage(HANDLE hHandle,const LPVOID lpData,DWORD dwDataSize,DWORD dwParam)
{
    bool bRet=false;
    do
    {
        if (!SYSLIB::IPC_IsValidHandle(hHandle))
            break;

        if ((lpData) || (dwDataSize))
        {
            if (!SYSLIB_SAFE::CheckParamRead(lpData,dwDataSize))
                break;
        }

        IPC_HANDLE *lpHandle=(IPC_HANDLE*)hHandle;
        if (lpHandle->dwType == IPC_ACCEPTED_CLIENT)
        {
            CLIENTSERVER_SHARED_OBJECTS *lpHandles=&lpHandle->SrvClient.lpClient->SharedObjects;
            bRet=SYSLIB::IPC_SendDataInt(lpHandles,&lpHandle->SrvClient.lpClient->PostedMsgs,lpData,dwDataSize,dwParam);
        }
        else if (lpHandle->dwType == IPC_CLIENT_HANDLE)
        {
            CLIENTSERVER_SHARED_OBJECTS *lpHandles=&lpHandle->Cli.SharedObjects;
            bRet=SYSLIB::IPC_SendDataInt(lpHandles,&lpHandle->Cli.PostedMsgs,lpData,dwDataSize,dwParam);
        }
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(DWORD) IPC_GetProcessId(HANDLE hHandle)
{
    DWORD dwPID=0;
    do
    {
        if (!SYSLIB::IPC_IsValidHandle(hHandle))
            break;

        IPC_HANDLE *lpHandle=(IPC_HANDLE*)hHandle;
        if (lpHandle->dwType == IPC_ACCEPTED_CLIENT)
        {
            dwPID=GetProcessId(lpHandle->SrvClient.lpClient->hClientProc);
            break;
        }
        else if (lpHandle->dwType == IPC_CLIENT_HANDLE)
        {
            dwPID=GetProcessId(lpHandle->Cli.hServerProc);
            break;
        }
        else if (lpHandle->dwType == IPC_SERVER_HANDLE)
        {
            dwPID=GetCurrentProcessId();
            break;
        }
    }
    while (false);
    return dwPID;
}

