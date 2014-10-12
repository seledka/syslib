#ifndef COMMON_H_INCLUDED
#define COMMON_H_INCLUDED

struct IPC_PREPARED_TO_SEND_BUFFER
{
    bool bSendMePlease;

    DWORD dwUniqueMsgId;
    PIPC_MESSAGE_REPLY lpReply;
    DWORD dwParam;
    bool bReplyNeeded;

    IPC_SYSTEM_COMMAND bCmd;
    byte *lpMsgToSend;
    byte *lpPtr;
    DWORD dwBytesToSend;
    HANDLE hEvent;
    bool bDataSent;

    char *lpRc4Key;
    DWORD dwRc4KeySize;
};

namespace SYSLIB
{
    LPWSTR IPC_FormatPipeName(LPCWSTR lpName);

    IPC_HANDLE *IPC_CreateHandle(IPC_HANDLE_TYPE);
    bool IPC_IsValidHandle(HANDLE hHandle);

    void IPC_CloseSharedHandles(CLIENTSERVER_SHARED_OBJECTS *lpHandles);

    void IPC_CleanupMessagesList(IPC_QUEUED_MESSAGES_LIST *lpMsg);
    void IPC_InitMessagesList(IPC_QUEUED_MESSAGES_LIST *lpMsg);

    void IPC_RecvMessage(SENT_MESSAGES_LIST *lpSentList,IPC_COMMUNICATION_BUFFER *lpCommBuffer,TEMPLATE_MESSAGE_BUFFER *lpTmpBuffer,IPC_QUEUED_MESSAGES_LIST *lpReceivedMessagesList,HANDLE hClient);

    void IPC_SendPreparedBuffer(CLIENTSERVER_SHARED_OBJECTS *lpSharedObjects,IPC_PREPARED_TO_SEND_BUFFER *lpBuffer,IPC_MESSAGE_DIRECTION bDirection);

    void IPC_FreeLastMsg(HANDLE hHandle,LAST_MSG_INFO *lpLastMsg,bool bDelete);

    void IPC_CleanupSentMessagesList(SENT_MESSAGES_LIST *lpSentMsgs);

    void IPC_SetEvent(IPC_EVENT *lpEvent);
    DWORD IPC_WaitEvent(IPC_EVENT *lpEvent,DWORD dwMilliseconds);

    void IPC_HandlePostedMessage(IPC_QUEUED_MESSAGES_LIST *lpPostedMsgs,SENT_MESSAGES_LIST *lpSentMsgs,IPC_PREPARED_TO_SEND_BUFFER *lpPreparedBuffer);
};

#endif // COMMON_H_INCLUDED
