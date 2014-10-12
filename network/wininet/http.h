#ifndef HTTP_H_INCLUDED
#define HTTP_H_INCLUDED

#include "cookie.h"

enum HTTP_HANDLE_TYPE
{
    HTTP_SESSION=1,
    HTTP_URL,
    HTTP_REQUEST,
    HTTP_ARGUMENTS_LIST
};

struct HTTP_URL_HANDLE;
struct HTTP_REQUEST_HANDLE;

struct HTTP_HANDLE
{
    HTTP_HANDLE_TYPE dwType;
    union
    {
        SAFE_CRITICAL_SECTION csSession;
        SAFE_CRITICAL_SECTION csUrl;
        SAFE_CRITICAL_SECTION csRequest;
    };
    union
    {
        HINTERNET hOpen;
        HINTERNET hUrl;
        HINTERNET hReq;
    };
    union
    {
        DWORD dwSessionFlags;
        DWORD dwUrlFlags;
        DWORD dwRequestFlags;
    };
};

struct HTTP_SESSION_HANDLE: HTTP_HANDLE
{
    WCHAR *lpAgent;
    WCHAR *lpVersion;
    INET_PROXY_TYPE dwProxyType;
    INET_PROXY_SETTINGSW ProxySettings;
    bool bGZipEnabled;

    COOKIE_DOMAIN *lpSessionCookies;
    HTTP_URL_HANDLE *lpUrls;
};

struct HTTP_URL_HANDLE: HTTP_HANDLE
{
    HTTP_SESSION_HANDLE *lpSession;

    INTERNET_SCHEME dwScheme;
    WCHAR *lpHost;
    DWORD dwPort;
    WCHAR *lpUser;
    WCHAR *lpPassword;
    WCHAR *lpPath;
    WCHAR *lpReferer;
    HTTP_REQUEST_HANDLE *lpRequests;

    HTTP_URL_HANDLE *lpNext;
};

struct HTTP_REQUEST_HANDLE: HTTP_HANDLE
{
    HTTP_URL_HANDLE *lpUrl;
    HTTP_DATA_TYPE dwDataType;
    HANDLE hArgsList;
    char szMultipartBoundary[40];
    DWORD dwMultipartBoundarySize;

    HTTP_REQUEST_HANDLE *lpNext;
};

struct WININETOPTION
{
	DWORD dwOption;
	DWORD dwValue;
};

#define INET_TIMEOUT 1*60*1000

#define DEFAULT_REQUEST_FLAGS INTERNET_FLAG_IGNORE_CERT_CN_INVALID|INTERNET_FLAG_IGNORE_CERT_DATE_INVALID|INTERNET_FLAG_HYPERLINK|\
                              INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP|INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS|INTERNET_FLAG_NO_CACHE_WRITE|\
                              INTERNET_FLAG_NO_UI|INTERNET_FLAG_PRAGMA_NOCACHE|INTERNET_FLAG_RELOAD|INTERNET_FLAG_KEEP_CONNECTION

#define MAX_RESPONSE_BUFFER_SIZE  10*1024*1024
#define INET_BUFFER_SIZE 4*1024

#define REINIT_URL_ENTRY(x,y) if (x->y) MemFree(x->y); x->y=StrDuplicateW(y,0);

#endif // HTTP_H_INCLUDED
