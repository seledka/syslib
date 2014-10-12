#ifndef DEBUG_H_INCLUDED
#define DEBUG_H_INCLUDED

struct DBGLOG_SERVER
{
    bool bUnicode;
    union
    {
        DBGLOGEVENTPROCA lpDbgLogEventProcA;
        DBGLOGEVENTPROCW lpDbgLogEventProcW;
    };
    HANDLE hPipe;
    HANDLE hEvent;
};

struct DBGLOGEVENTPROCAW_PARAMS
{
    DBGLOGEVENTPROCA lpDbgLogEventProcAW;
    DEBUGDATAA *lpDbgDataAW;
};

#define MAX_DBG_BODY_SIZE 1024
#define MAX_DBG_LOG_SIZE sizeof(DEBUGDATAW)+(MAX_DBG_BODY_SIZE)*sizeof(WCHAR)

#endif // DEBUG_H_INCLUDED
