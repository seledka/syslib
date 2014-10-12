#ifndef SYSLIB_NET_H_INCLUDED
#define SYSLIB_NET_H_INCLUDED

#include <wininet.h>
#include "syslib_exp.h"

SYSLIBEXP(BOOL) NetIsConnectionEstablished(LPCSTR lpAddress,WORD wPort);
SYSLIBEXP(UINT) NetResolveAddress(LPCSTR lpHost);
SYSLIBEXP(LPCSTR) NetNtoA(int iAddr);
SYSLIBEXP(BOOL) NetRecvTimeout(SOCKET hSock,PCHAR lpData,int dwLen,int dwTimeout);
SYSLIBEXP(BOOL) NetRecvTimeoutUDP(SOCKET hSock,PCHAR lpData,int dwLen,int dwTimeout,sockaddr *lpClient);
SYSLIBEXP(BOOL) NetRecvToNull(SOCKET hSock,int dwLen,int dwTimeout);
SYSLIBEXP(BOOL) NetSendAll(SOCKET hSock,LPVOID lpData,int dwLen);
SYSLIBEXP(SOCKET) NetConnectToTcpAddr(LPCSTR lpHost,WORD wPort);
SYSLIBEXP(SOCKET) NetBCConnect(LPCSTR lpHost,WORD wBcPort,LPWORD lpClPort);
SYSLIBEXP(SOCKET) NetListen(WORD wPort);
SYSLIBEXP(void) NetCloseSocket(SOCKET hSock);
SYSLIBEXP(DWORD) NetGetExternalIP();

SYSLIBEXP(BOOL) NetUrlEncodeBufferW(LPCWSTR lpIn,DWORD dwSize,LPWSTR lpOut,DWORD dwOutSize);
SYSLIBEXP(BOOL) NetUrlEncodeBufferA(LPCSTR lpIn,DWORD dwSize,LPSTR lpOut,DWORD dwOutSize);

#ifdef UNICODE
#define NetUrlEncodeBuffer NetUrlEncodeBufferW
#else
#define NetUrlEncodeBuffer NetUrlEncodeBufferA
#endif


SYSLIBEXP(LPWSTR) NetUrlEncodeBufferExW(LPCWSTR lpIn,DWORD dwSize,LPDWORD lpOutSize);
SYSLIBEXP(LPSTR) NetUrlEncodeBufferExA(LPCSTR lpIn,DWORD dwSize,LPDWORD lpOutSize);

#ifdef UNICODE
#define NetUrlEncodeBufferEx NetUrlEncodeBufferExW
#else
#define NetUrlEncodeBufferEx NetUrlEncodeBufferExA
#endif


SYSLIBEXP(DWORD) NetUrlCalcEncodedSizeW(LPCWSTR lpIn,DWORD dwSize);
SYSLIBEXP(DWORD) NetUrlCalcEncodedSizeA(LPCSTR lpIn,DWORD dwSize);

#ifdef UNICODE
#define NetUrlCalcEncodedSize NetUrlCalcEncodedSizeW
#else
#define NetUrlCalcEncodedSize NetUrlCalcEncodedSizeA
#endif


SYSLIBEXP(BOOL) NetUrlDecodeBufferW(LPCWSTR lpIn,DWORD dwSize,LPWSTR lpOut,DWORD dwOutSize);
SYSLIBEXP(BOOL) NetUrlDecodeBufferA(LPCSTR lpIn,DWORD dwSize,LPSTR lpOut,DWORD dwOutSize);

#ifdef UNICODE
#define NetUrlDecodeBuffer NetUrlDecodeBufferW
#else
#define NetUrlDecodeBuffer NetUrlDecodeBufferA
#endif


SYSLIBEXP(LPWSTR) NetUrlDecodeBufferExW(LPCWSTR lpIn,DWORD dwSize,LPDWORD lpOutSize);
SYSLIBEXP(LPSTR) NetUrlDecodeBufferExA(LPCSTR lpIn,DWORD dwSize,LPDWORD lpOutSize);

#ifdef UNICODE
#define NetUrlDecodeBufferEx NetUrlDecodeBufferExW
#else
#define NetUrlDecodeBufferEx NetUrlDecodeBufferExA
#endif


SYSLIBEXP(DWORD) NetUrlCalcDecodedSizeW(LPCWSTR lpIn,DWORD dwSize);
SYSLIBEXP(DWORD) NetUrlCalcDecodedSizeA(LPCSTR lpIn,DWORD dwSize);

#ifdef UNICODE
#define NetUrlCalcDecodedSize NetUrlCalcDecodedSizeW
#else
#define NetUrlCalcDecodedSize NetUrlCalcDecodedSizeA
#endif


SYSLIBEXP(LPCWSTR) NetGetFileContentTypeW(LPCWSTR lpFileName);
SYSLIBEXP(LPCSTR) NetGetFileContentTypeA(LPCSTR lpFileName);

#ifdef UNICODE
#define NetGetFileContentType NetGetFileContentTypeW
#else
#define NetGetFileContentType NetGetFileContentTypeA
#endif


typedef enum
{
    HTTP_1_1=0,
    HTTP_1_0,
    HTTP_0_9
} INET_HTTP_VERSION;

typedef enum
{
    INET_PROXY_AUTO=0,
    INET_NO_PROXY,
    INET_PROXY_PREDEFINED,
    INET_PROXY_USER_DEFINED
} INET_PROXY_TYPE;

typedef struct _INET_PROXY_SETTINGSW
{
    LPCWSTR lpProxyServer;
    WORD wProxyPort;
    LPCWSTR lpProxyUser;
    LPCWSTR lpProxyPassword;
} INET_PROXY_SETTINGSW, *PINET_PROXY_SETTINGSW;

typedef struct _INET_PROXY_SETTINGSA
{
    LPCSTR lpProxyServer;
    WORD wProxyPort;
    LPCSTR lpProxyUser;
    LPCSTR lpProxyPassword;
} INET_PROXY_SETTINGSA, *PINET_PROXY_SETTINGSA;

#define INET_SESSION_FLAG_DONT_SAVE_NEW_COOKIES 1
#define INET_SESSION_FLAG_NO_CACHE_WRITE        2
#define INET_SESSION_FLAG_NO_CACHE_READ         4

SYSLIBEXP(HANDLE) InetCreateSessionW(LPCWSTR lpAgent,INET_HTTP_VERSION dwVersion,INET_PROXY_TYPE dwProxy,PINET_PROXY_SETTINGSW lpProxySettings,DWORD dwSessionFlags);
SYSLIBEXP(HANDLE) InetCreateSessionA(LPCSTR lpAgent,INET_HTTP_VERSION dwVersion,INET_PROXY_TYPE dwProxy,PINET_PROXY_SETTINGSA lpProxySettings,DWORD dwSessionFlags);

#ifdef UNICODE
#define INET_PROXY_SETTINGS INET_PROXY_SETTINGSW
#define PINET_PROXY_SETTINGS PINET_PROXY_SETTINGSW
#define InetCreateSession InetCreateSessionW
#else
#define INET_PROXY_SETTINGS INET_PROXY_SETTINGSA
#define PINET_PROXY_SETTINGS PINET_PROXY_SETTINGSA
#define InetCreateSession InetCreateSessionA
#endif


#define INET_REQUEST_FLAG_NO_COOKIES          0x1
#define INET_REQUEST_FLAG_NO_AUTO_REDIRECT    0x2
#define INET_REQUEST_FLAG_NO_REFERER          0x4
#define INET_REQUEST_FLAG_USE_UTF8            0x8
#define INET_REQUEST_FLAG_URL_ENCODE          0x10
#define INET_REQUEST_FLAG_BASE64_ENCODE       0x20
#define INET_REQUEST_FLAG_FREE_ARGS_IF_SENT   0x40

#define INET_URL_FLAG_DONT_FOLLOW_REDIRECT    0x80

SYSLIBEXP(HANDLE) InetOpenUrlW(HANDLE hSession,LPCWSTR lpUrl,LPCWSTR lpReferer,DWORD dwUrlFlags);
SYSLIBEXP(HANDLE) InetOpenUrlA(HANDLE hSession,LPCSTR lpUrl,LPCSTR lpReferer,DWORD dwUrlFlags);

#ifdef UNICODE
#define InetOpenUrl InetOpenUrlW
#else
#define InetOpenUrl InetOpenUrlW
#endif


typedef enum
{
    HTTP_METHOD_GET=0,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_TRACE,
    HTTP_METHOD_CONNECT
} HTTP_METHODS;

typedef enum
{
    HTTP_DATA_TYPE_UNKNOWN=0,
    HTTP_DATA_TYPE_TEXT,
    HTTP_DATA_TYPE_BINARY,
    HTTP_DATA_TYPE_FORM,
    HTTP_DATA_TYPE_FORM_MULTIPART
} HTTP_DATA_TYPE;

SYSLIBEXP(HANDLE) InetOpenRequest(HANDLE hUrl,HTTP_METHODS dwMethod,HTTP_DATA_TYPE dwDataType,DWORD dwRequestFlags);

SYSLIBEXP(BOOL) InetAddRequestBinaryArgumentW(HANDLE hReq,LPCWSTR lpName,LPVOID lpValue,DWORD dwValueSize);
SYSLIBEXP(BOOL) InetAddRequestBinaryArgumentA(HANDLE hReq,LPCSTR lpName,LPVOID lpValue,DWORD dwValueSize);

#ifdef UNICODE
#define InetAddRequestBinaryArgument InetAddRequestBinaryArgumentW
#else
#define InetAddRequestBinaryArgument InetAddRequestBinaryArgumentA
#endif


SYSLIBEXP(BOOL) InetAddRequestFileArgumentW(HANDLE hReq,LPCWSTR lpName,LPCWSTR lpFileName);
SYSLIBEXP(BOOL) InetAddRequestFileArgumentA(HANDLE hReq,LPCSTR lpName,LPCSTR lpFileName);

#ifdef UNICODE
#define InetAddRequestFileArgument InetAddRequestFileArgumentW
#else
#define InetAddRequestFileArgument InetAddRequestFileArgumentA
#endif


SYSLIBEXP(BOOL) InetAddRequestBinaryArgumentAsFileW(HANDLE hReq,LPCWSTR lpName,LPVOID lpValue,DWORD dwValueSize,LPCWSTR lpFileName);
SYSLIBEXP(BOOL) InetAddRequestBinaryArgumentAsFileA(HANDLE hReq,LPCSTR lpName,LPVOID lpValue,DWORD dwValueSize,LPCSTR lpFileName);

#ifdef UNICODE
#define InetAddRequestBinaryArgumentAsFile InetAddRequestBinaryArgumentAsFileW
#else
#define InetAddRequestBinaryArgumentAsFile InetAddRequestBinaryArgumentAsFileA
#endif


SYSLIBEXP(BOOL) InetAddRequestStringArgumentW(HANDLE hReq,LPCWSTR lpName,LPCWSTR lpValue);
SYSLIBEXP(BOOL) InetAddRequestStringArgumentA(HANDLE hReq,LPCSTR lpName,LPCSTR lpValue);

#ifdef UNICODE
#define InetAddRequestStringArgument InetAddRequestStringArgumentW
#else
#define InetAddRequestStringArgument InetAddRequestStringArgumentA
#endif


SYSLIBEXP(BOOL) InetAddRequestIntArgumentW(HANDLE hReq,LPCWSTR lpName,int dwValue);
SYSLIBEXP(BOOL) InetAddRequestIntArgumentA(HANDLE hReq,LPCSTR lpName,int dwValue);

#ifdef UNICODE
#define InetAddRequestIntArgument InetAddRequestIntArgumentW
#else
#define InetAddRequestIntArgument InetAddRequestIntArgumentA
#endif


SYSLIBEXP(void) InetFreeRequestArguments(HANDLE hReq);

SYSLIBEXP(BOOL) InetAddRequestHeaderW(HANDLE hReq,LPCWSTR lpName,LPCWSTR lpValue);
#define InetRemoveRequestHeaderW(hReq,lpName) InetAddRequestHeaderW(hReq,lpName,NULL)
SYSLIBEXP(BOOL) InetAddRequestHeaderA(HANDLE hReq,LPCSTR lpName,LPCSTR lpValue);
#define InetRemoveRequestHeaderA(hReq,lpName) InetAddRequestHeaderA(hReq,lpName,NULL)

#ifdef UNICODE
#define InetAddRequestHeader InetAddRequestHeaderW
#define InetRemoveRequestHeader InetRemoveRequestHeaderW
#else
#define InetAddRequestHeader InetAddRequestHeaderA
#define InetRemoveRequestHeader InetRemoveRequestHeaderA
#endif


SYSLIBEXP(BOOL) InetSendRequest(HANDLE hReq);

#define INET_RESULT_FLAG_READ_RESPONSE   1
#define INET_RESULT_FLAG_GET_REQUEST_URL 2
#define INET_RESULT_FLAG_GET_STATUS_CODE 4
#define INET_RESULT_FLAG_GET_ALL_HEADERS 8

typedef struct
{
    DWORD dwResultFlags;

    LPVOID lpResponse;
    DWORD dwResponseSize;

    LPWSTR lpRedirectedUrl;
    DWORD dwRedirectedUrlLen;

    LPWSTR lpHeaders;
    DWORD dwHeadersLen;

    DWORD dwStatusCode;
} REQUEST_RESULTW, *PREQUEST_RESULTW;

typedef struct
{
    DWORD dwResultFlags;

    LPVOID lpResponse;
    DWORD dwResponseSize;

    LPSTR lpRedirectedUrl;
    DWORD dwRedirectedUrlLen;

    LPSTR lpHeaders;
    DWORD dwHeadersLen;

    DWORD dwStatusCode;
} REQUEST_RESULTA, *PREQUEST_RESULTA;

SYSLIBEXP(HANDLE) InetSendRequestExW(HANDLE hUrl,HTTP_METHODS dwMethod,HTTP_DATA_TYPE dwDataType,LPCWSTR lpHeaders,HANDLE hArgumentsList,PREQUEST_RESULTW lpResult,DWORD dwFlags);
SYSLIBEXP(HANDLE) InetSendRequestExA(HANDLE hUrl,HTTP_METHODS dwMethod,HTTP_DATA_TYPE dwDataType,LPCSTR lpHeaders,HANDLE hArgumentsList,PREQUEST_RESULTA lpResult,DWORD dwFlags);

#ifdef UNICODE
#define InetSendRequestEx InetSendRequestExW
#define REQUEST_RESULT REQUEST_RESULTW
#define PREQUEST_RESULT PREQUEST_RESULTW
#else
#define InetSendRequestEx InetSendRequestExA
#define REQUEST_RESULT REQUEST_RESULTA
#define PREQUEST_RESULT PREQUEST_RESULTA
#endif


SYSLIBEXP(DWORD) InetReadRequestResponse(HANDLE hReq,LPVOID *lppData);
SYSLIBEXP(void) InetReadRequestResponseToNull(HANDLE hReq);
SYSLIBEXP(DWORD) InetReadRequestResponsePartial(HANDLE hReq,LPVOID lpData,DWORD dwBufSize);

SYSLIBEXP(BOOL) InetReadRequestResponseToFileW(HANDLE hReq,LPCWSTR lpFileName);
SYSLIBEXP(BOOL) InetReadRequestResponseToFileA(HANDLE hReq,LPCSTR lpFileName);

#ifdef UNICODE
#define InetReadRequestResponseToFile InetReadRequestResponseToFileW
#else
#define InetReadRequestResponseToFile InetReadRequestResponseToFileA
#endif


SYSLIBEXP(BOOL) InetGetUrlLocationW(HANDLE hUrl,LPWSTR lpAddress,LPDWORD lpLen);
SYSLIBEXP(BOOL) InetGetUrlLocationA(HANDLE hUrl,LPSTR lpAddress,LPDWORD lpLen);

#ifdef UNICODE
#define InetGetUrlLocation InetGetUrlLocationW
#else
#define InetGetUrlLocation InetGetUrlLocationA
#endif


SYSLIBEXP(BOOL) InetCallUrlExW(HANDLE hSession,LPCWSTR lpUrl,HTTP_METHODS dwMethod,HTTP_DATA_TYPE dwDataType,LPCWSTR lpReferer,LPCWSTR lpHeaders,HANDLE hArgumentsList,PREQUEST_RESULTW lpResult,DWORD dwFlags);
SYSLIBEXP(BOOL) InetCallUrlExA(HANDLE hSession,LPCSTR lpUrl,HTTP_METHODS dwMethod,HTTP_DATA_TYPE dwDataType,LPCSTR lpReferer,LPCSTR lpHeaders,HANDLE hArgumentsList,PREQUEST_RESULTA lpResult,DWORD dwFlags);

#ifdef UNICODE
#define InetCallUrlEx InetCallUrlExW
#else
#define InetCallUrlEx InetCallUrlExA
#endif


SYSLIBEXP(BOOL) InetCallUrlW(HANDLE hSession,LPCWSTR lpUrl,HTTP_METHODS dwMethod,LPCWSTR lpReferer,PREQUEST_RESULTW lpResult,DWORD dwFlags);
SYSLIBEXP(BOOL) InetCallUrlA(HANDLE hSession,LPCSTR lpUrl,HTTP_METHODS dwMethod,LPCSTR lpReferer,PREQUEST_RESULTA lpResult,DWORD dwFlags);

#ifdef UNICODE
#define InetCallUrl InetCallUrlW
#else
#define InetCallUrl InetCallUrlA
#endif


SYSLIBEXP(HANDLE) InetArgsList_Create();

SYSLIBEXP(BOOL) InetArgsList_AddBinaryArgumentW(HANDLE hList,LPCWSTR lpName,LPVOID lpValue,DWORD dwValueSize);
SYSLIBEXP(BOOL) InetArgsList_AddBinaryArgumentA(HANDLE hList,LPCSTR lpName,LPVOID lpValue,DWORD dwValueSize);

#ifdef UNICODE
#define InetArgsList_AddBinaryArgument InetArgsList_AddBinaryArgumentW
#else
#define InetArgsList_AddBinaryArgument InetArgsList_AddBinaryArgumentA
#endif


SYSLIBEXP(BOOL) InetArgsList_AddFileArgumentW(HANDLE hList,LPCWSTR lpName,LPCWSTR lpFileName);
SYSLIBEXP(BOOL) InetArgsList_AddFileArgumentA(HANDLE hList,LPCSTR lpName,LPCSTR lpFileName);

#ifdef UNICODE
#define InetArgsList_AddFileArgument InetArgsList_AddFileArgumentW
#else
#define InetArgsList_AddFileArgument InetArgsList_AddFileArgumentA
#endif


SYSLIBEXP(BOOL) InetArgsList_AddBinaryArgumentAsFileW(HANDLE hList,LPCWSTR lpName,LPVOID lpValue,DWORD dwValueSize,LPCWSTR lpFileName);
SYSLIBEXP(BOOL) InetArgsList_AddBinaryArgumentAsFileA(HANDLE hList,LPCSTR lpName,LPVOID lpValue,DWORD dwValueSize,LPCSTR lpFileName);

#ifdef UNICODE
#define InetArgsList_AddBinaryArgumentAsFile InetArgsList_AddBinaryArgumentAsFileW
#else
#define InetArgsList_AddBinaryArgumentAsFile InetArgsList_AddBinaryArgumentAsFileA
#endif


SYSLIBEXP(BOOL) InetArgsList_AddStringArgumentW(HANDLE hList,LPCWSTR lpName,LPCWSTR lpValue);
SYSLIBEXP(BOOL) InetArgsList_AddStringArgumentA(HANDLE hList,LPCSTR lpName,LPCSTR lpValue);

#ifdef UNICODE
#define InetArgsList_AddStringArgument InetArgsList_AddStringArgumentW
#else
#define InetArgsList_AddStringArgument InetArgsList_AddStringArgumentA
#endif


SYSLIBEXP(BOOL) InetArgsList_AddIntArgumentW(HANDLE hList,LPCWSTR lpName,int dwValue);
SYSLIBEXP(BOOL) InetArgsList_AddIntArgumentA(HANDLE hList,LPCSTR lpName,int dwValue);

#ifdef UNICODE
#define InetArgsList_AddIntArgument InetArgsList_AddIntArgumentW
#else
#define InetArgsList_AddIntArgument InetArgsList_AddIntArgumentA
#endif


SYSLIBEXP(void) InetArgsList_Destroy(HANDLE hList);

SYSLIBEXP(void) InetCloseHandle(HANDLE hInet);

SYSLIBEXP(BOOL) InetDownloadToFileW(HANDLE hSession,LPCWSTR lpUrl,LPCWSTR lpReferer,LPCWSTR lpFile);
SYSLIBEXP(BOOL) InetDownloadToFileA(HANDLE hSession,LPCSTR lpUrl,LPCSTR lpReferer,LPCSTR lpFile);

#ifdef UNICODE
#define InetDownloadToFile InetDownloadToFileW
#else
#define InetDownloadToFile InetDownloadToFileA
#endif


SYSLIBEXP(DWORD) InetDownloadW(HANDLE hSession,LPCWSTR lpUrl,LPCWSTR lpReferer,LPVOID *lppData,LPDWORD lpdwErrorCode);
SYSLIBEXP(DWORD) InetDownloadA(HANDLE hSession,LPCSTR lpUrl,LPCSTR lpReferer,LPVOID *lppData,LPDWORD lpdwErrorCode);

#ifdef UNICODE
#define InetDownload InetDownloadW
#else
#define InetDownload InetDownloadA
#endif

SYSLIBEXP(DWORD) NetGetWanIP();
SYSLIBEXP(BOOL) NetIsBehindNAT();

#endif // SYSLIB_NET_H_INCLUDED
