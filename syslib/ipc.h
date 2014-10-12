#ifndef SYSLIB_IPC_H_INCLUDED
#define SYSLIB_IPC_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(HANDLE) IPC_CreateServerW(LPCWSTR lpName,BOOL bSecure);
SYSLIBEXP(HANDLE) IPC_CreateServerA(LPCSTR lpName,BOOL bSecure);

#ifdef UNICODE
#define IPC_CreateServer IPC_CreateServerW
#else
#define IPC_CreateServer IPC_CreateServerA
#endif


SYSLIBEXP(HANDLE) IPC_ConnectServerW(LPCWSTR lpName);
SYSLIBEXP(HANDLE) IPC_ConnectServerA(LPCSTR lpName);

#ifdef UNICODE
#define IPC_ConnectServer IPC_ConnectServerW
#else
#define IPC_ConnectServer IPC_ConnectServerA
#endif


SYSLIBEXP(void) IPC_CloseHandle(HANDLE hHandle);

typedef struct _IPC_MESSAGE_REPLY
{
    DWORD dwTime;
    DWORD dwParam;
    LPVOID lpReply;
    DWORD dwReplySize;
} IPC_MESSAGE_REPLY, *PIPC_MESSAGE_REPLY;

SYSLIBEXP(BOOL) IPC_SendMessage(HANDLE hHandle,const LPVOID lpMessage,DWORD dwMessageSize,DWORD dwParam,PIPC_MESSAGE_REPLY lpReply);
SYSLIBEXP(BOOL) IPC_PostMessage(HANDLE hHandle,const LPVOID lpMessage,DWORD dwMessageSize,DWORD dwParam);
SYSLIBEXP(BOOL) IPC_ReplyMessage(HANDLE hHandle,const LPVOID lpReply,DWORD dwReplySize,DWORD dwParam);

enum IPC_MESSAGE_TYPE
{
    IPC_MSG_IDLE,
    IPC_MSG_DATA_RECEIVED,

    /**
        Серверные сообщения
    **/
    IPC_MSG_CLIENT_CONNECTED,
    IPC_MSG_CLIENT_DISCONNECTED
};

typedef struct _IPC_QUEUED_MESSAGE
{
    DWORD dwSize;

    DWORD dwSenderProcessId;
    HANDLE hSender;

    IPC_MESSAGE_TYPE dwMsg;
    DWORD dwTime;
    union
    {
        struct /// IPC_MSG_DATA_RECEIVED
        {
            DWORD dwParam;
            LPVOID lpData;
            DWORD dwDataSize;
        } ReceivedDataInfo;
    };
} IPC_QUEUED_MESSAGE, *PIPC_QUEUED_MESSAGE;

SYSLIBEXP(BOOL) IPC_GetQueuedMessage(HANDLE hHandle,PIPC_QUEUED_MESSAGE lpMsg,DWORD dwMilliseconds);

SYSLIBEXP(DWORD) IPC_GetProcessId(HANDLE hHandle);

#endif // SYSLIB_IPC_H_INCLUDED
