#ifndef SYSLIB_DEBUG_H_INCLUDED
#define SYSLIB_DEBUG_H_INCLUDED

#include "syslib_exp.h"
#include <intrin.h>

#pragma warning(disable:4200)

#define WIDEN2(x) L ## x
#define WIDEN(x) WIDEN2(x)

SYSLIBEXP(void) dprintfA(LPCSTR msg, ...);
SYSLIBEXP(void) dprintfW(LPCWSTR msg, ...);

#ifdef UNICODE
#define dprintf dprintfW
#else
#define dprintf dprintfA
#endif


SYSLIBEXP(void) fdprintfW(LPCWSTR lpFile,LPCWSTR lpMsg, ...);
SYSLIBEXP(void) fdprintfA(LPCSTR lpFile,LPCSTR lpMsg, ...);

#ifdef UNICODE
#define fdprintf fdprintfW
#else
#define fdprintf fdprintfA
#endif


SYSLIBEXP(void) dprintf_wndA(HWND hWnd,LPCSTR lpStr);
SYSLIBEXP(void) dprintf_wndW(HWND hWnd,LPCWSTR lpStr);

#ifdef UNICODE
#define dprintf_wnd dprintf_wndW
#else
#define dprintf_wnd dprintf_wndA
#endif


typedef enum
{
    LOG_TYPE_INFO=0,
    LOG_TYPE_WARNING,
    LOG_TYPE_ERROR
} LOG_TYPE;

#pragma pack(push,1)
typedef struct
{
    BOOL x64;
    LOG_TYPE bLogType;

    DWORD dwLastError;
    DWORD dwTickCount;
    DWORD dwPID;
    DWORD dwTID;

    WCHAR szFunc[150];
    WCHAR szFile[150];
    DWORD dwLineNumber;

    SYSTEMTIME lt;

    DWORD dwBodySize;
    WCHAR szBody[0];
} DEBUGDATAW;

typedef struct
{
    BOOL x64;
    LOG_TYPE bLogType;

    DWORD dwLastError;
    DWORD dwTickCount;
    DWORD dwPID;
    DWORD dwTID;

    char szFunc[150];
    char szFile[150];
    DWORD dwLineNumber;

    SYSTEMTIME lt;

    DWORD dwBodySize;
    char szBody[0];
} DEBUGDATAA;
#pragma pack(pop)


SYSLIBEXP(BOOL) DbgLog_SendEventA(LPCSTR lpFunc,LPCSTR lpFile,DWORD dwLine,LOG_TYPE bType,LPCSTR lpFormat,...);
SYSLIBEXP(BOOL) DbgLog_SendEventW(LPCWSTR lpFunc,LPCWSTR lpFile,DWORD dwLine,LOG_TYPE bType,LPCWSTR lpFormat,...);

#define DbgLog_EventA(...) DbgLog_SendEventA(__FUNCTION__,__FILE__,__LINE__,__VA_ARGS__)
#define DbgLog_EventW(...) DbgLog_SendEventW(WIDEN(__FUNCTION__),WIDEN(__FILE__),__LINE__,__VA_ARGS__)

#ifdef UNICODE
#define DbgLog_SendEvent DbgLog_SendEventW
#define DbgLog_Event DbgLog_EventW
#else
#define DbgLog_SendEvent DbgLog_SendEventA
#define DbgLog_Event DbgLog_EventA
#endif


typedef void (CALLBACK* DBGLOGEVENTPROCA)(DEBUGDATAA *lpData);
typedef void (CALLBACK* DBGLOGEVENTPROCW)(DEBUGDATAW *lpData);

SYSLIBEXP(BOOL) DbgLog_StartEventsServerA(DBGLOGEVENTPROCA lpDbgLogEventProc);
SYSLIBEXP(BOOL) DbgLog_StartEventsServerW(DBGLOGEVENTPROCW lpDbgLogEventProc);

#ifdef UNICODE
#define DbgLog_StartEventsServer DbgLog_StartEventsServerW
#define DEBUGDATA DEBUGDATAW
#define DBGLOGEVENTPROC DBGLOGEVENTPROCW
#else
#define DbgLog_StartEventsServer DbgLog_StartEventsServerA
#define DEBUGDATA DEBUGDATAA
#define DBGLOGEVENTPROC DBGLOGEVENTPROCA
#endif


SYSLIBEXP(BOOL) DbgLog_InitA(LPCSTR lpPrefix);
SYSLIBEXP(BOOL) DbgLog_InitW(LPCWSTR lpPrefix);

#ifdef UNICODE
#define DbgLog_Init DbgLog_InitW
#else
#define DbgLog_Init DbgLog_InitA
#endif

SYSLIBEXP(void) DbgLog_StopEventsServer();


#define int3 __debugbreak()

#endif // SYSLIB_DEBUG_H_INCLUDED
