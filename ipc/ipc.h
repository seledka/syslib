#ifndef IPC_H_INCLUDED
#define IPC_H_INCLUDED

#include "syslib\criticalsections.h"
#include "syslib\ipc.h"

enum IPC_MESSAGE_DIRECTION
{
    IPC_MESSAGE_BAD_DIRECTION=-1,
    IPC_MESSAGE_FROM_SRV_TO_CLI,
    IPC_MESSAGE_FROM_CLI_TO_SRV
};

enum IPC_SYSTEM_COMMAND
{
    IPC_SYSCMD_BAD_CMD,
    IPC_SYSCMD_NEW_MESSAGE,
    IPC_SYSCMD_MESSAGE_REPLY,
    IPC_SYSCMD_NEXT_MESSAGE_PART
};

#define MAX_IPC_MESSAGE_SIZE 10*1024

struct IPC_COMMUNICATION_BUFFER
{
    DWORD dwLastCmdId;

    IPC_MESSAGE_DIRECTION bDirection;
    IPC_SYSTEM_COMMAND dwSysCmd;
    DWORD dwTime;
    DWORD dwParam;

    DWORD dwUniqueMsgId;
    bool bReplyNeeded;

    union
    {
        DWORD dwFullMessageSize; /// -> IPC_SYSCMD_NEW_MESSAGE/IPC_SYSCMD_MESSAGE_REPLY
        DWORD dwDataPartSize;
    };

    DWORD dwCheckSum;

    byte bMessage[MAX_IPC_MESSAGE_SIZE];
};

#define IPC_SERVER_ANSWER_WAIT_TIMEOUT 100500

struct IPC_CONNECTION_INFO
{
    union
    {
        HANDLE hSrv2CliEvent;
        DWORD64 tmp0;
    };
    union
    {
        HANDLE hCli2SrvEvent;
        DWORD64 tmp1;
    };
    union
    {
        HANDLE hStopEvent;
        DWORD64 tmp2;
    };
    union
    {
        HANDLE hSharedMapping;
        DWORD64 tmp3;
    };
    union
    {
        HANDLE hProtectionMutex;
        DWORD64 tmp4;
    };

    union
    {
        HANDLE hServerProcess;
        DWORD64 tmp5;
    };

    char szRc4Key[256];
    DWORD dwRc4KeySize;
};

struct IPC_PIPE_CONNECTION_INFO
{
    DWORD dwNewClientPID;

    union
    {
        HANDLE hEvent;
        DWORD64 tmp0;
    };
    union
    {
        IPC_CONNECTION_INFO *lpConnectionInfo;
        DWORD64 tmp1;
    };
};

struct CLIENTSERVER_SHARED_OBJECTS
{
    HANDLE hSrv2CliEvent;
    HANDLE hCli2SrvEvent;
    HANDLE hStopEvent;

    HANDLE hSharedMapping;
    IPC_COMMUNICATION_BUFFER *lpSharedMapping;
    HANDLE hProtectionMutex;
};

struct IPC_MESSAGES_LIST
{
    bool bReplyNeeded;

    IPC_SYSTEM_COMMAND bCmd;
    DWORD dwUniqueMsgId;
    PIPC_MESSAGE_REPLY lpReply;

    HANDLE hEvent;
    IPC_QUEUED_MESSAGE Msg;

    IPC_MESSAGES_LIST *lpNext;
};

struct IPC_EVENT
{
    DWORD dwCount;
    HANDLE hEvent;
};

struct IPC_QUEUED_MESSAGES_LIST
{
    IPC_EVENT Event;
    SAFE_CRITICAL_SECTION csMsg;
    IPC_MESSAGES_LIST *lpMsg;
};

struct TEMPLATE_MESSAGE_BUFFER
{
    bool bIsReply;
    bool bReplyNeeded;
    DWORD dwUniqueMsgId;
    DWORD dwTime;
    DWORD dwParam;

    LPVOID lpTmpBuffer;
    LPVOID lpTmpBufferPosition;
    DWORD dwRestBytes;

    char *lpRc4Key;
    DWORD dwRc4KeySize;

    byte *lpDecryptedBuf;
};

struct SENT_MESSAGES_LIST
{
    SAFE_CRITICAL_SECTION csSent;
    IPC_MESSAGES_LIST *lpSent;
};

struct LAST_MSG_INFO
{
    SAFE_CRITICAL_SECTION csLastMsg;
    IPC_MESSAGES_LIST *lpLastMsg;
    LPVOID lpLastReply;
};

struct CLIENT_HANDLE
{
    HANDLE hThreadInitEvent;

    HANDLE hServerProc;

    CLIENTSERVER_SHARED_OBJECTS SharedObjects;

    HANDLE hEventsThread;

    TEMPLATE_MESSAGE_BUFFER TmpRecvBuf;

    char *lpRc4Key;
    DWORD dwRc4KeySize;

    LAST_MSG_INFO LastMsg;

    IPC_QUEUED_MESSAGES_LIST ReceivedMsgs; /// сообщения, полученные от сервера
    IPC_QUEUED_MESSAGES_LIST PostedMsgs;   /// очередь сообщений на отправку серверу
    SENT_MESSAGES_LIST SentMsgs;           /// список сообщений, ожидающих ответа
};

struct IPC_ACCEPTED_CLIENT_INFO
{
    HANDLE hThreadInitEvent;

    LPVOID lpServer;
    LPVOID lpHandle;

    HANDLE hClientProc;

    CLIENTSERVER_SHARED_OBJECTS SharedObjects;

    TEMPLATE_MESSAGE_BUFFER TmpRecvBuf;

    char *lpRc4Key;
    DWORD dwRc4KeySize;

    IPC_QUEUED_MESSAGES_LIST PostedMsgs; /// очередь сообщений на отправку клиенту
    SENT_MESSAGES_LIST SentMsgs;         /// список сообщений, ожидающих ответа

    IPC_ACCEPTED_CLIENT_INFO *lpNext;
};

struct ACCEPTED_CLIENT_HANDLE
{
    IPC_ACCEPTED_CLIENT_INFO *lpClient;

    bool bCalledFromClientThread;
};

struct SERVER_HANDLE
{
    HANDLE hPipe;

    HANDLE hServerInitEvent;

    HANDLE hStopEvent;
    HANDLE hServerThread;
    HANDLE hEventsThreadsGroup;

    BOOL bSecure;

    SAFE_CRITICAL_SECTION csClients;
    IPC_ACCEPTED_CLIENT_INFO *lpClients;

    LAST_MSG_INFO LastMsg;

    IPC_QUEUED_MESSAGES_LIST ReceivedMsgs; /// сообщения, полученные от клиентов
};

enum IPC_HANDLE_TYPE
{
    IPC_SERVER_HANDLE,
    IPC_ACCEPTED_CLIENT,
    IPC_CLIENT_HANDLE,
};

struct IPC_HANDLE
{
    IPC_HANDLE_TYPE dwType;

    union
    {
        SERVER_HANDLE Srv;
        ACCEPTED_CLIENT_HANDLE SrvClient;
        CLIENT_HANDLE Cli;
    };

    IPC_HANDLE *lpNext;
};

#endif // IPC_H_INCLUDED
