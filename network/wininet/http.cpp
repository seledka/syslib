#include "sys_includes.h"
#include <wininet.h>
#include <shlwapi.h>

#include "syslib\utils.h"
#include "syslib\base64.h"
#include "syslib\files.h"
#include "syslib\system.h"
#include "syslib\net.h"
#include "syslib\debug.h"
#include "syslib\str.h"
#include "syslib\mem.h"
#include "syslib\criticalsections.h"

#include "http.h"
#include "argslist.h"
#include "requests.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

// TODO (Гость#1#): придумать что-то с авто-определением режима прокси

static void InetDisableSecurity(HINTERNET hReq)
{
    DWORD dwSecFlags=0,
    dwLen=sizeof(dwSecFlags);
    if (InternetQueryOption(hReq,INTERNET_OPTION_SECURITY_FLAGS,(LPVOID)&dwSecFlags,&dwLen))
    {
        dwSecFlags|=SECURITY_SET_MASK;
        InternetSetOption(hReq,INTERNET_OPTION_SECURITY_FLAGS,&dwSecFlags,sizeof(dwSecFlags));
    }
    return;
}

static bool ParseUrl(HTTP_URL_HANDLE *lpHandle,LPCWSTR lpUrl)
{
    LPWSTR lpHost=NULL,
           lpPath=NULL,
           lpUser=NULL,
           lpPassword=NULL;

    bool bRet=false;
    do
    {
        lpHost=WCHAR_QuickAlloc(INTERNET_MAX_HOST_NAME_LENGTH);
        if (!lpHost)
            break;

        lpPath=WCHAR_QuickAlloc(INTERNET_MAX_PATH_LENGTH);
        if (!lpPath)
            break;

        lpUser=WCHAR_QuickAlloc(INTERNET_MAX_USER_NAME_LENGTH);
        if (!lpUser)
            break;

        lpPassword=WCHAR_QuickAlloc(INTERNET_MAX_PASSWORD_LENGTH);
        if (!lpPassword)
            break;

        URL_COMPONENTSW url={0};
        url.dwStructSize=sizeof(url);

        url.lpszHostName=lpHost;
        url.dwHostNameLength=INTERNET_MAX_HOST_NAME_LENGTH;

        url.lpszUrlPath=lpPath;
        url.dwUrlPathLength=INTERNET_MAX_PATH_LENGTH;

        url.lpszUserName=lpUser;
        url.dwUserNameLength=INTERNET_MAX_USER_NAME_LENGTH;

        url.lpszPassword=lpPassword;
        url.dwPasswordLength=INTERNET_MAX_PASSWORD_LENGTH;

        if (InternetCrackUrlW(lpUrl,NULL,0,&url) == FALSE)
            break;

        if ((url.nScheme != INTERNET_SCHEME_HTTP) && (url.nScheme != INTERNET_SCHEME_HTTPS))
            break;

        REINIT_URL_ENTRY(lpHandle,lpHost);
        REINIT_URL_ENTRY(lpHandle,lpPath);
        REINIT_URL_ENTRY(lpHandle,lpUser);
        REINIT_URL_ENTRY(lpHandle,lpPassword);

        lpHandle->dwPort=url.nPort;
        lpHandle->dwScheme=url.nScheme;

        bRet=true;
    }
    while (false);

    MemFree(lpHost);
    MemFree(lpPath);
    MemFree(lpUser);
    MemFree(lpPassword);
    return bRet;
}

static void WINAPI InetCallback(HINTERNET hInternet,HTTP_URL_HANDLE *lpContext,DWORD dwInternetStatus,LPVOID lpvStatusInformation,DWORD dwStatusInformationLength)
{
    switch (dwInternetStatus)
	{
        case INTERNET_STATUS_CONNECTED_TO_SERVER:
        {
            InetDisableSecurity(hInternet);
            break;
        }
        case INTERNET_STATUS_HANDLE_CREATED:
        {
            InetDisableSecurity(hInternet);
            break;
        }
        case INTERNET_STATUS_REDIRECT:
        {
            if ((lpContext) && (lpContext->dwType == HTTP_URL))
            {
                HTTP_REQUEST_HANDLE *lpRequest=lpContext->lpRequests;
                while (lpRequest)
                {
                    if (lpRequest->hReq == hInternet)
                    {
                        if (lpContext->lpSession->dwSessionFlags & INET_SESSION_FLAG_DONT_SAVE_NEW_COOKIES)
                        {
                            if (!(lpRequest->dwRequestFlags & INET_REQUEST_FLAG_NO_COOKIES))
                                SYSLIB::InetProcessCookies(lpRequest);
                        }
                        break;
                    }
                    lpRequest=lpRequest->lpNext;
                }
            }
            ParseUrl(lpContext,(WCHAR*)lpvStatusInformation);
            break;
        }
	}
    return;
}

static void FindAnyGoodProxy(HTTP_SESSION_HANDLE *lpSession)
{
    HANDLE hSession=NULL;
    do
    {
        hSession=InetCreateSessionW(NULL,HTTP_1_1,INET_PROXY_PREDEFINED,NULL,0);
        if (hSession)
        {
            REQUEST_RESULTA Result={0};
            Result.dwResultFlags=INET_RESULT_FLAG_READ_RESPONSE;
            if (InetCallUrlA(hSession,dcrA_21aef358("http://google.com"),HTTP_METHOD_POST,NULL,&Result,0))
            {
                if (Result.lpResponse)
                {
                    if (StrStrA((LPSTR)Result.lpResponse,dcrA_226d94aa("google")) != NULL)
                    {
                        lpSession->dwProxyType=INET_PROXY_PREDEFINED;
                        break;
                    }
                    MemFree(Result.lpResponse);
                }
            }
            InetCloseHandle(hSession);
            hSession=NULL;
        }

        lpSession->dwProxyType=INET_NO_PROXY;
    }
    while (false);

    if (hSession)
        InetCloseHandle(hSession);

    return;
}

static WININETOPTION InetOptions[]=
{
    {INTERNET_OPTION_CONNECT_TIMEOUT,INET_TIMEOUT},
    {INTERNET_OPTION_RECEIVE_TIMEOUT,INET_TIMEOUT},
    {INTERNET_OPTION_SEND_TIMEOUT,INET_TIMEOUT},
    {INTERNET_OPTION_HTTP_DECODING,1}
};

static HINTERNET InetOpenInt(HTTP_SESSION_HANDLE *lpSession)
{
    if (lpSession->dwProxyType == INET_PROXY_AUTO)
        FindAnyGoodProxy(lpSession);

    LPWSTR lpProxy=NULL;
    DWORD dwFlags;
    switch (lpSession->dwProxyType)
    {
        case INET_PROXY_AUTO:
        case INET_NO_PROXY:
        {
            dwFlags=INTERNET_OPEN_TYPE_DIRECT;
            break;
        }
        case INET_PROXY_PREDEFINED:
        {
            dwFlags=INTERNET_OPEN_TYPE_PRECONFIG;
            break;
        }
        case INET_PROXY_USER_DEFINED:
        {
            dwFlags=INTERNET_OPEN_TYPE_PROXY;
            if (lpSession->ProxySettings.wProxyPort)
                StrFormatExW(&lpProxy,dcrW_b73291c6("http=http://%s:%d https=http://%s:%d"),lpSession->ProxySettings.lpProxyServer,lpSession->ProxySettings.wProxyPort,lpSession->ProxySettings.lpProxyServer,lpSession->ProxySettings.wProxyPort);
            else
                StrFormatExW(&lpProxy,dcrW_88951ecc("http=http://%s https=http://%s"),lpSession->ProxySettings.lpProxyServer,lpSession->ProxySettings.lpProxyServer);
            break;
        }
    }

    HINTERNET hInet=InternetOpenW(lpSession->lpAgent,dwFlags,lpProxy,NULL,0);
    if (hInet)
    {
        for (int i=0; i < ARRAYSIZE(InetOptions); i++)
            InternetSetOptionW(hInet,InetOptions[i].dwOption,&InetOptions[i].dwValue,sizeof(DWORD));

        InternetSetStatusCallbackW(hInet,(INTERNET_STATUS_CALLBACK)InetCallback);
    }

    if (lpProxy)
        MemFree(lpProxy);

    return hInet;
}

static LPCWSTR GetVersionName(INET_HTTP_VERSION dwVersion)
{
    LPCWSTR lpVersion=NULL;
    switch (dwVersion)
    {
        case HTTP_0_9:
        {
            lpVersion=dcrW_8f1e0b6f("HTTP/0.9");
            break;
        }
        case HTTP_1_0:
        {
            lpVersion=dcrW_73fa1263("HTTP/1.0");
            break;
        }
        case HTTP_1_1:
        {
            lpVersion=dcrW_f4e1ea94("HTTP/1.1");
            break;
        }
    }
    return lpVersion;
}

SYSLIBFUNC(HANDLE) InetCreateSessionW(LPCWSTR lpAgent,INET_HTTP_VERSION dwVersion,INET_PROXY_TYPE dwProxyType,PINET_PROXY_SETTINGSW lpProxySettings,DWORD dwSessionFlags)
{
    HTTP_SESSION_HANDLE *lpSession=(HTTP_SESSION_HANDLE*)MemAlloc(sizeof(HTTP_SESSION_HANDLE));
    if (lpSession)
    {
        if (!lpAgent)
        {
#ifdef _X86_
            if (SysIsWow64())
                lpAgent=dcrW_623cd530("Mozilla/5.0 (Windows NT 6.1; WOW64; rv:20.0) Gecko/20100101 Firefox/20.0");
            else
                lpAgent=dcrW_7f3ff342("Mozilla/5.0 (Windows NT 6.1; Win32; x86; rv:20.0) Gecko/20100101 Firefox/20.0");
#else
            lpAgent=dcrW_bd7ecd27("Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:20.0) Gecko/20100101 Firefox/20.0");
#endif
        }

        lpSession->dwType=HTTP_SESSION;
        if (dwProxyType == INET_PROXY_USER_DEFINED)
        {
            if (!SYSLIB_SAFE::CheckParamRead(lpProxySettings,sizeof(*lpProxySettings)))
                dwProxyType=INET_NO_PROXY;
            else
            {
                lpSession->ProxySettings.lpProxyServer=StrDuplicateW(lpProxySettings->lpProxyServer,0);
                lpSession->ProxySettings.lpProxyUser=StrDuplicateW(lpProxySettings->lpProxyUser,0);
                lpSession->ProxySettings.lpProxyPassword=StrDuplicateW(lpProxySettings->lpProxyPassword,0);
                lpSession->ProxySettings.wProxyPort=lpProxySettings->wProxyPort;
            }
        }
        lpSession->dwProxyType=dwProxyType;

        lpSession->dwSessionFlags=dwSessionFlags;
        lpSession->lpVersion=StrDuplicateW(GetVersionName(dwVersion),0);
        lpSession->lpAgent=StrDuplicateW(lpAgent,0);
        InitializeSafeCriticalSection(&lpSession->csSession);
        lpSession->hOpen=InetOpenInt(lpSession);
        if (lpSession->hOpen)
        {
            DWORD dwValue=0,
                  dwSize=sizeof(dwValue);
            InternetQueryOptionW(lpSession->hOpen,INTERNET_OPTION_HTTP_DECODING,&dwValue,&dwSize);
            lpSession->bGZipEnabled=(dwValue != 0);
        }
        else
        {
            MemFree(lpSession->lpVersion);
            MemFree(lpSession->lpAgent);
            MemFree(lpSession);
            lpSession=NULL;
        }
    }
    return (HANDLE)lpSession;
}

SYSLIBFUNC(HANDLE) InetCreateSessionA(LPCSTR lpAgent,INET_HTTP_VERSION dwVersion,INET_PROXY_TYPE dwProxyType,PINET_PROXY_SETTINGSA lpProxySettings,DWORD dwSessionFlags)
{
    LPWSTR lpAgentW=StrAnsiToUnicodeEx(lpAgent,0,NULL);

    PINET_PROXY_SETTINGSW lpProxySettingsW=NULL;
    if (dwProxyType == INET_PROXY_USER_DEFINED)
    {
        if (!SYSLIB_SAFE::CheckParamRead(lpProxySettings,sizeof(*lpProxySettings)))
            dwProxyType=INET_NO_PROXY;
        else
        {
            lpProxySettingsW=(PINET_PROXY_SETTINGSW)MemQuickAlloc(sizeof(*lpProxySettingsW));
            if (lpProxySettingsW)
            {
                lpProxySettingsW->lpProxyServer=StrAnsiToUnicodeEx(lpProxySettings->lpProxyServer,0,NULL);
                lpProxySettingsW->lpProxyUser=StrAnsiToUnicodeEx(lpProxySettings->lpProxyUser,0,NULL);
                lpProxySettingsW->lpProxyPassword=StrAnsiToUnicodeEx(lpProxySettings->lpProxyPassword,0,NULL);
                lpProxySettingsW->wProxyPort=lpProxySettings->wProxyPort;
            }
        }
    }

    HANDLE hSession=InetCreateSessionW(lpAgentW,dwVersion,dwProxyType,lpProxySettingsW,dwSessionFlags);

    if (lpProxySettingsW)
    {
        MemFree((LPVOID)lpProxySettingsW->lpProxyServer);
        MemFree((LPVOID)lpProxySettingsW->lpProxyUser);
        MemFree((LPVOID)lpProxySettingsW->lpProxyPassword);
        MemFree(lpProxySettingsW);
    }

    MemFree(lpAgentW);
    return hSession;
}

static void AppendUrl(HTTP_SESSION_HANDLE *lpSession,HTTP_URL_HANDLE *lpUrl)
{
    if (lpSession->lpUrls)
    {
        HTTP_URL_HANDLE *lpCurUrl=lpSession->lpUrls;
        while (lpCurUrl->lpNext)
            lpCurUrl=lpCurUrl->lpNext;

        lpCurUrl->lpNext=lpUrl;
    }
    else
        lpSession->lpUrls=lpUrl;

    lpUrl->lpSession=lpSession;
    return;
}

SYSLIBFUNC(HANDLE) InetOpenUrlW(HANDLE hSession,LPCWSTR lpAddress,LPCWSTR lpReferer,DWORD dwUrlFlags)
{
    HTTP_URL_HANDLE *lpUrl=NULL;
    HTTP_SESSION_HANDLE *lpSession=(HTTP_SESSION_HANDLE*)hSession;
    if ((lpSession) && (lpSession->dwType == HTTP_SESSION))
    {
        EnterSafeCriticalSection(&lpSession->csSession);
        {
            lpUrl=(HTTP_URL_HANDLE*)MemAlloc(sizeof(HTTP_URL_HANDLE));
            if (lpUrl)
            {
                lpUrl->dwType=HTTP_URL;
                bool bDone=false;
                do
                {
                    if (!ParseUrl(lpUrl,lpAddress))
                        break;

                    lpUrl->dwUrlFlags=dwUrlFlags;

                    lpUrl->hUrl=InternetConnectW(lpSession->hOpen,lpUrl->lpHost,lpUrl->dwPort,lpUrl->lpUser,lpUrl->lpPassword,INTERNET_SERVICE_HTTP,0,(DWORD_PTR)lpUrl);
                    if (!lpUrl->hUrl)
                        break;

                    lpUrl->lpReferer=StrDuplicateW(lpReferer,0);
                    InitializeSafeCriticalSection(&lpUrl->csUrl);
                    AppendUrl(lpSession,lpUrl);
                    bDone=true;
                }
                while (false);

                if (!bDone)
                {
                    InetCloseHandle((HANDLE)lpUrl);
                    lpUrl=NULL;
                }
            }
        }
        LeaveSafeCriticalSection(&lpSession->csSession);
    }
    return lpUrl;
}

SYSLIBFUNC(HANDLE) InetOpenUrlA(HANDLE hSession,LPCSTR lpUrl,LPCSTR lpReferer,DWORD dwUrlFlags)
{
    LPWSTR lpUrlW=StrAnsiToUnicodeEx(lpUrl,0,NULL),
           lpRefererW=StrAnsiToUnicodeEx(lpReferer,0,NULL);

    HANDLE hUrl=InetOpenUrlW(hSession,lpUrlW,lpRefererW,dwUrlFlags);

    MemFree(lpUrlW);
    MemFree(lpRefererW);
    return hUrl;
}

static LPCWSTR GetMethodName(HTTP_METHODS dwMethod)
{
    LPCWSTR lpMethod=NULL;
    switch (dwMethod)
    {
        case HTTP_METHOD_GET:
        {
            lpMethod=dcrW_a300c501("GET");
            break;
        }
        case HTTP_METHOD_OPTIONS:
        {
            lpMethod=dcrW_337fbeb2("OPTIONS");
            break;
        }
        case HTTP_METHOD_HEAD:
        {
            lpMethod=dcrW_4e324dec("HEAD");
            break;
        }
        case HTTP_METHOD_POST:
        {
            lpMethod=dcrW_8c63df29("POST");
            break;
        }
        case HTTP_METHOD_PUT:
        {
            lpMethod=dcrW_da4e82e7("PUT");
            break;
        }
        case HTTP_METHOD_DELETE:
        {
            lpMethod=dcrW_ace1991c("DELETE");
            break;
        }
        case HTTP_METHOD_TRACE:
        {
            lpMethod=dcrW_52501fbf("TRACE");
            break;
        }
        case HTTP_METHOD_CONNECT:
        {
            lpMethod=dcrW_5673bc74("CONNECT");
            break;
        }
    }
    return lpMethod;
}

static void AppendRequest(HTTP_URL_HANDLE *lpUrl,HTTP_REQUEST_HANDLE *lpReq)
{
    if (lpUrl->lpRequests)
    {
        HTTP_REQUEST_HANDLE *lpRequest=lpUrl->lpRequests;
        while (lpRequest->lpNext)
            lpRequest=lpRequest->lpNext;

        lpRequest->lpNext=lpReq;
    }
    else
        lpUrl->lpRequests=lpReq;

    lpReq->lpUrl=lpUrl;


    if (lpUrl->lpSession->dwProxyType == INET_PROXY_USER_DEFINED)
    {
        HttpSendRequestW(lpReq->hReq,NULL,0,NULL,0);
        DWORD dwCode,dwSize=sizeof(dwCode);
        HttpQueryInfoW(lpReq->hReq,HTTP_QUERY_STATUS_CODE|HTTP_QUERY_FLAG_NUMBER,&dwCode,&dwSize,NULL);

        if (dwCode == HTTP_STATUS_PROXY_AUTH_REQ)
        {
            InternetSetOptionW(lpUrl->hUrl,INTERNET_OPTION_PROXY_USERNAME,(LPVOID)lpUrl->lpSession->ProxySettings.lpProxyUser,lstrlenW(lpUrl->lpSession->ProxySettings.lpProxyUser));
            InternetSetOptionW(lpUrl->hUrl,INTERNET_OPTION_PROXY_PASSWORD,(LPVOID)lpUrl->lpSession->ProxySettings.lpProxyPassword,lstrlenW(lpUrl->lpSession->ProxySettings.lpProxyPassword));

            HttpSendRequestW(lpReq->hReq,NULL,0,NULL,0);
        }
    }
    return;
}

SYSLIBFUNC(HANDLE) InetOpenRequest(HANDLE hUrl,HTTP_METHODS dwMethod,HTTP_DATA_TYPE dwDataType,DWORD dwRequestFlags)
{
    HTTP_REQUEST_HANDLE *lpReq=NULL;
    HTTP_URL_HANDLE *lpUrl=(HTTP_URL_HANDLE*)hUrl;
    if ((lpUrl) && (lpUrl->dwType == HTTP_URL))
    {
        EnterSafeCriticalSection(&lpUrl->csUrl);
        {
            DWORD dwFlags=DEFAULT_REQUEST_FLAGS;

            if (lpUrl->dwScheme == INTERNET_SCHEME_HTTPS)
                dwFlags|=INTERNET_FLAG_SECURE;

            if ((dwRequestFlags & INET_REQUEST_FLAG_NO_COOKIES) || (lpUrl->lpSession->dwSessionFlags & INET_SESSION_FLAG_DONT_SAVE_NEW_COOKIES))
                dwFlags|=INTERNET_FLAG_NO_COOKIES;

            if (dwRequestFlags & INET_REQUEST_FLAG_NO_AUTO_REDIRECT)
                dwFlags|=INTERNET_FLAG_NO_AUTO_REDIRECT;

            if (lpUrl->lpSession->dwSessionFlags & INET_SESSION_FLAG_NO_CACHE_WRITE)
                dwFlags|=INTERNET_FLAG_NO_CACHE_WRITE;

            if (lpUrl->lpSession->dwSessionFlags & INET_SESSION_FLAG_NO_CACHE_READ)
                dwFlags|=INTERNET_FLAG_RELOAD|INTERNET_FLAG_PRAGMA_NOCACHE;

            LPCWSTR lpAcceptTypes[]={dcrW_e27ac89a("text/html;q=0.7, */*;q=1"),NULL};

            LPCWSTR lpReferer=lpUrl->lpReferer;
            if (dwRequestFlags & INET_REQUEST_FLAG_NO_REFERER)
                lpReferer=NULL;

            HINTERNET hRequest=HttpOpenRequestW(lpUrl->hUrl,GetMethodName(dwMethod),lpUrl->lpPath,NULL,lpReferer,lpAcceptTypes,dwFlags,(DWORD_PTR)lpUrl);
            if (hRequest)
            {
                lpReq=(HTTP_REQUEST_HANDLE *)MemAlloc(sizeof(HTTP_REQUEST_HANDLE));
                if (lpReq)
                {
                    if (lpUrl->lpSession->bGZipEnabled)
                        HttpAddRequestHeadersA(hRequest,dcrA_5fca9227("Accept-Encoding: deflate,gzip\r\n"),-1,HTTP_ADDREQ_FLAG_ADD);

                    switch (dwDataType)
                    {
                        case HTTP_DATA_TYPE_FORM_MULTIPART:
                        {
                            LARGE_INTEGER liBoundary={GetRndDWORD(),GetRndDWORD()};
                            lpReq->dwMultipartBoundarySize=StrFormatA(lpReq->szMultipartBoundary,dcrA_d6855130("%I64X"),liBoundary.QuadPart);

                            dwRequestFlags&=~(INET_REQUEST_FLAG_BASE64_ENCODE);
                            break;
                        }
                        case HTTP_DATA_TYPE_FORM:
                        {
                            dwRequestFlags|=INET_REQUEST_FLAG_USE_UTF8|INET_REQUEST_FLAG_URL_ENCODE;
                            break;
                        }
                        case HTTP_DATA_TYPE_UNKNOWN:
                        {
                            dwRequestFlags&=~(INET_REQUEST_FLAG_USE_UTF8|INET_REQUEST_FLAG_URL_ENCODE|INET_REQUEST_FLAG_BASE64_ENCODE);
                            break;
                        }
                        case HTTP_DATA_TYPE_BINARY:
                        {
                            dwRequestFlags&=~(INET_REQUEST_FLAG_USE_UTF8|INET_REQUEST_FLAG_URL_ENCODE);
                            break;
                        }
                    }

                    lpReq->dwType=HTTP_REQUEST;
                    lpReq->dwDataType=dwDataType;
                    lpReq->hReq=hRequest;
                    lpReq->dwRequestFlags=dwRequestFlags;
                    AppendRequest(lpUrl,lpReq);
                }

                if (!lpReq)
                    InternetCloseHandle(hRequest);
            }
        }
        LeaveSafeCriticalSection(&lpUrl->csUrl);
    }
    return (HANDLE)lpReq;
}

SYSLIBFUNC(BOOL) InetGetUrlLocationW(HANDLE hUrl,LPWSTR lpAddress,LPDWORD lpLen)
{
    BOOL bRet=false;
    HTTP_URL_HANDLE *lpUrl=(HTTP_URL_HANDLE*)hUrl;
    if ((lpUrl) && (lpUrl->dwType == HTTP_URL))
    {
        EnterSafeCriticalSection(&lpUrl->csUrl);
        {
            URL_COMPONENTSW url={0};
            url.dwStructSize=sizeof(url);
            url.lpszHostName=lpUrl->lpHost;
            url.lpszUrlPath=lpUrl->lpPath;
            url.lpszUserName=lpUrl->lpUser;
            url.lpszPassword=lpUrl->lpPassword;
            url.nPort=lpUrl->dwPort;
            url.nScheme=lpUrl->dwScheme;
            bRet=(InternetCreateUrlW(&url,ICU_ESCAPE,lpAddress,lpLen) != FALSE);
        }
        LeaveSafeCriticalSection(&lpUrl->csUrl);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) InetGetUrlLocationA(HANDLE hUrl,LPSTR lpAddress,LPDWORD lpLen)
{
    LPWSTR lpAddressW=NULL;
    if ((lpAddress) && (lpLen) && (*lpLen))
        lpAddressW=WCHAR_QuickAlloc(*lpLen+1);

    BOOL bRet=InetGetUrlLocationW(hUrl,lpAddressW,lpLen);

    if (lpAddressW)
    {
        if (bRet)
            StrUnicodeToAnsi(lpAddressW,0,lpAddress,0);
        MemFree(lpAddressW);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) InetAddRequestHeaderW(HANDLE hReq,LPCWSTR lpName,LPCWSTR lpValue)
{
    BOOL bRet=false;
    HTTP_REQUEST_HANDLE *lpReq=(HTTP_REQUEST_HANDLE*)hReq;
    if ((lpReq) && (lpReq->dwType == HTTP_REQUEST) && (lpName))
    {
        EnterSafeCriticalSection(&lpReq->csRequest);
        {
            LPWSTR lpHdr;
            if (StrFormatExW(&lpHdr,dcrW_3c3f539d("%s: %s\r\n"),lpName,lpValue))
            {
                if (lpValue)
                    bRet=(HttpAddRequestHeadersW(lpReq->hReq,lpHdr,-1,HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA) != FALSE);
                else
                    bRet=(HttpAddRequestHeadersW(lpReq->hReq,lpHdr,-1,HTTP_ADDREQ_FLAG_REPLACE) != FALSE);

                MemFree(lpHdr);
            }
        }
        LeaveSafeCriticalSection(&lpReq->csRequest);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) InetAddRequestHeaderA(HANDLE hReq,LPCSTR lpName,LPCSTR lpValue)
{
    BOOL bRet=false;
    HTTP_REQUEST_HANDLE *lpReq=(HTTP_REQUEST_HANDLE*)hReq;
    if ((lpReq) && (lpReq->dwType == HTTP_REQUEST) && (lpName))
    {
        EnterSafeCriticalSection(&lpReq->csRequest);
        {
            LPSTR lpHdr;
            if (StrFormatExA(&lpHdr,dcrA_3c3f539d("%s: %s\r\n"),lpName,lpValue))
            {
                if (lpValue)
                    bRet=(HttpAddRequestHeadersA(lpReq->hReq,lpHdr,-1,HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA) != FALSE);
                else
                    bRet=(HttpAddRequestHeadersA(lpReq->hReq,lpHdr,-1,HTTP_ADDREQ_FLAG_REPLACE) != FALSE);

                MemFree(lpHdr);
            }
        }
        LeaveSafeCriticalSection(&lpReq->csRequest);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) InetSendRequest(HANDLE hReq)
{
    BOOL bRet=false;
    HTTP_REQUEST_HANDLE *lpReq=(HTTP_REQUEST_HANDLE*)hReq;
    if ((lpReq) && (lpReq->dwType == HTTP_REQUEST))
    {
        EnterSafeCriticalSection(&lpReq->csRequest);
        {
            bool bProcessCookies=false;
            if (lpReq->lpUrl->lpSession->dwSessionFlags & INET_SESSION_FLAG_DONT_SAVE_NEW_COOKIES)
            {
                if (!(lpReq->dwRequestFlags & INET_REQUEST_FLAG_NO_COOKIES))
                {
                    bProcessCookies=true;
                    SYSLIB::InetInsertCookies(lpReq);
                }
            }

            LPWSTR lpPrevLocation=NULL;
            if (!(lpReq->lpUrl->dwUrlFlags & INET_URL_FLAG_DONT_FOLLOW_REDIRECT))
            {
                DWORD dwLen=INTERNET_MAX_URL_LENGTH;
                lpPrevLocation=WCHAR_QuickAlloc(dwLen);
                if (!InetGetUrlLocationW(lpReq->lpUrl,lpPrevLocation,&dwLen))
                {
                    MemFree(lpPrevLocation);
                    lpPrevLocation=NULL;
                }
            }

            do
            {
                if (!SYSLIB::InetCompileRequestAndSend(lpReq))
                    break;

                if (bProcessCookies)
                    SYSLIB::InetProcessCookies(lpReq);

                if (!lpPrevLocation)
                    break;

                EnterSafeCriticalSection(&lpReq->lpUrl->csUrl);
                {
                    if (lpReq->lpUrl->lpReferer)
                        MemFree(lpReq->lpUrl->lpReferer);
                    lpReq->lpUrl->lpReferer=StrDuplicateW(lpPrevLocation,0);

                    DWORD dwLen=INTERNET_MAX_URL_LENGTH*sizeof(WCHAR);
                    bRet=(InternetQueryOptionW(lpReq->hReq,INTERNET_OPTION_URL,(void*)lpPrevLocation,&dwLen) != FALSE);

                    ParseUrl(lpReq->lpUrl,lpPrevLocation);
                }
                LeaveSafeCriticalSection(&lpReq->lpUrl->csUrl);
            }
            while (false);

            if (lpPrevLocation)
                MemFree(lpPrevLocation);
        }
        LeaveSafeCriticalSection(&lpReq->csRequest);
    }
    return bRet;
}

SYSLIBFUNC(void) InetFreeRequestArguments(HANDLE hReq)
{
    HTTP_REQUEST_HANDLE *lpReq=(HTTP_REQUEST_HANDLE*)hReq;
    if ((lpReq) && (lpReq->dwType == HTTP_REQUEST))
    {
        EnterSafeCriticalSection(&lpReq->csRequest);
        {
            InetArgsList_Destroy(lpReq->hArgsList);
            lpReq->hArgsList=NULL;
        }
        LeaveSafeCriticalSection(&lpReq->csRequest);
    }
    return;
}

SYSLIBFUNC(DWORD) InetReadRequestResponse(HANDLE hReq,LPVOID *lppData)
{
    DWORD dwDownloaded=0;
    HTTP_HANDLE *lpReq=(HTTP_HANDLE*)hReq;
    if ((lpReq) && (lpReq->dwType == HTTP_REQUEST) && (lppData))
    {
        EnterSafeCriticalSection(&lpReq->csRequest);
        {
            *lppData=NULL;

            bool bDownloaded=false;
            byte *lpDownloaded=NULL;
            while (true)
            {
                DWORD dwBytesRead=INET_BUFFER_SIZE;
                lpDownloaded=(byte*)MemRealloc(lpDownloaded,dwBytesRead+dwDownloaded);
                if (!lpDownloaded)
                    break;

                if (!InternetReadFile(lpReq->hReq,lpDownloaded+dwDownloaded,dwBytesRead,&dwBytesRead))
                    break;

                if (!dwBytesRead)
                {
                    if (dwDownloaded)
                        bDownloaded=true;
                    break;
                }

                dwDownloaded+=dwBytesRead;

                if (dwDownloaded > MAX_RESPONSE_BUFFER_SIZE)
                    break;
            }

            if (!bDownloaded)
                MemFree(lpDownloaded);
            else
                *lppData=(void*)lpDownloaded;
        }
        LeaveSafeCriticalSection(&lpReq->csRequest);
    }
    return dwDownloaded;
}

SYSLIBFUNC(void) InetReadRequestResponseToNull(HANDLE hReq)
{
    HTTP_HANDLE *lpReq=(HTTP_HANDLE*)hReq;
    if ((lpReq) && (lpReq->dwType == HTTP_REQUEST))
    {
        EnterSafeCriticalSection(&lpReq->csRequest);
        {
            byte *lpDownloaded=(byte*)MemQuickAlloc(INET_BUFFER_SIZE);
            if (lpDownloaded)
            {
                while (true)
                {
                    DWORD dwBytesRead=INET_BUFFER_SIZE;

                    if (!InternetReadFile(lpReq->hReq,lpDownloaded,dwBytesRead,&dwBytesRead))
                        break;

                    if (!dwBytesRead)
                        break;
                }
                MemFree(lpDownloaded);
            }
        }
        LeaveSafeCriticalSection(&lpReq->csRequest);
    }
    return;
}

SYSLIBFUNC(DWORD) InetReadRequestResponsePartial(HANDLE hReq,LPVOID lpData,DWORD dwBufSize)
{
    DWORD dwDownloaded=0;
    HTTP_HANDLE *lpReq=(HTTP_HANDLE*)hReq;
    if ((lpReq) && (lpReq->dwType == HTTP_REQUEST) && (lpData))
    {
        EnterSafeCriticalSection(&lpReq->csRequest);
        {
            bool bDownloaded=false;
            while (true)
            {
                DWORD dwBytesRead=dwBufSize-dwDownloaded;
                if (!InternetReadFile(lpReq->hReq,(byte*)lpData+dwDownloaded,dwBytesRead,&dwBytesRead))
                    break;

                if (!dwBytesRead)
                {
                    bDownloaded=true;
                    break;
                }

                dwDownloaded+=dwBytesRead;
            }

            if (!bDownloaded)
                dwDownloaded=0;
        }
        LeaveSafeCriticalSection(&lpReq->csRequest);
    }
    return dwDownloaded;
}

SYSLIBFUNC(BOOL) InetReadRequestResponseToFileW(HANDLE hReq,LPCWSTR lpFileName)
{
    BOOL bRet=false;

    HTTP_HANDLE *lpReq=(HTTP_HANDLE*)hReq;
    if ((lpReq) && (lpReq->dwType == HTTP_REQUEST))
	{
	    HANDLE hFile=NULL;
	    do
        {
            hFile=CreateFileW(lpFileName,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
            if (hFile == INVALID_HANDLE_VALUE)
                break;

            byte *lpTmp=(byte *)MemQuickAlloc(INET_BUFFER_SIZE);
            if (!lpTmp)
                break;

            bool bDownloaded=false;
            EnterSafeCriticalSection(&lpReq->csRequest);
            {
                while (true)
                {
                    DWORD dwBytesRead=INET_BUFFER_SIZE;
                    if (!InternetReadFile(lpReq->hReq,lpTmp,dwBytesRead,&dwBytesRead))
                        break;

                    if (!dwBytesRead)
                    {
                        if (bDownloaded)
                        {
                            FlushFileBuffers(hFile);
                            bRet=true;
                        }
                        break;
                    }

                    DWORD dwByteWrite=0;
                    if ((!WriteFile(hFile,lpTmp,dwBytesRead,&dwByteWrite,NULL)) || (dwBytesRead != dwByteWrite))
                        break;

                    bDownloaded=true;
                }
            }
            LeaveSafeCriticalSection(&lpReq->csRequest);

            MemFree(lpTmp);
        }
        while (false);

        SysCloseHandle(hFile);

        if (!bRet)
            RemoveFileW(lpFileName);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) InetReadRequestResponseToFileA(HANDLE hReq,LPCSTR lpFileName)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFileName,0,NULL);

    BOOL bRet=InetReadRequestResponseToFileW(hReq,lpFileNameW);

    MemFree(lpFileNameW);
    return bRet;
}

static void CloneFileArg(HANDLE hReq,LPCSTR lpName,INET_ARG *lpFile)
{
    if (lpFile->pseudo_file.lpValueRaw)
        InetAddRequestBinaryArgumentAsFileA(hReq,lpName,lpFile->pseudo_file.lpValueRaw,lpFile->pseudo_file.dwValueRawSize,lpFile->lpFullFileName);
    else
        InetAddRequestFileArgumentA(hReq,lpName,lpFile->lpFullFileName);
    return;
}

static void CloneRequestArguments(HANDLE hReq,HANDLE hArgsList)
{
    INET_ARGS_LIST *lpList=(INET_ARGS_LIST*)hArgsList;
    if ((lpList) && (lpList->dwType == HTTP_ARGUMENTS_LIST))
    {
        EnterSafeCriticalSection(&lpList->csArguments);
        {
            INET_ARG *lpArg=lpList->lpArgs;
            while (lpArg)
            {
                switch (lpArg->dwType)
                {
                    case INET_ARG_STRING:
                    {
                        InetAddRequestStringArgumentA(hReq,lpArg->lpName,lpArg->lpValueStr);
                        break;
                    }
                    case INET_ARG_INT:
                    {
                        InetAddRequestIntArgumentA(hReq,lpArg->lpName,lpArg->dwValueInt);
                        break;
                    }
                    case INET_ARG_RAW:
                    {
                        InetAddRequestBinaryArgumentA(hReq,lpArg->lpName,lpArg->lpValueRaw,lpArg->dwValueRawSize);
                        break;
                    }
                    case INET_ARG_FILE:
                    {
                        INET_ARG *lpCurArg=lpArg;
                        while (lpCurArg)
                        {
                            CloneFileArg(hReq,lpArg->lpName,lpCurArg);

                            lpCurArg=lpCurArg->lpNextFile;
                        }
                        break;
                    }
                }
                lpArg=lpArg->lpNext;
            }
        }
        LeaveSafeCriticalSection(&lpList->csArguments);
    }
    return;
}

static void GetRequestResultW(HTTP_REQUEST_HANDLE *lpReq,PREQUEST_RESULTW lpResult)
{
    if ((!lpResult) || (!lpReq))
        return;

    if (lpResult->dwResultFlags & INET_RESULT_FLAG_READ_RESPONSE)
        lpResult->dwResponseSize=InetReadRequestResponse(lpReq,&lpResult->lpResponse);

    if (lpResult->dwResultFlags & INET_RESULT_FLAG_GET_REQUEST_URL)
    {
        do
        {
            lpResult->lpRedirectedUrl=NULL;
            lpResult->dwRedirectedUrlLen=0;

            DWORD dwLen=INTERNET_MAX_URL_LENGTH;
            WCHAR *lpNewUrl=WCHAR_QuickAlloc(dwLen);
            if (!lpNewUrl)
                break;

            if (!InetGetUrlLocationW(lpReq->lpUrl,lpNewUrl,&dwLen))
            {
                MemFree(lpNewUrl);
                break;
            }

            lpResult->lpRedirectedUrl=lpNewUrl;
            lpResult->dwRedirectedUrlLen=dwLen;
        }
        while (false);
    }

    if (lpResult->dwResultFlags & INET_RESULT_FLAG_GET_STATUS_CODE)
    {
        DWORD dwSize=sizeof(lpResult->dwStatusCode);
        HttpQueryInfoW(lpReq->hReq,HTTP_QUERY_STATUS_CODE|HTTP_QUERY_FLAG_NUMBER,&lpResult->dwStatusCode,&dwSize,NULL);
    }

    if (lpResult->dwResultFlags & INET_RESULT_FLAG_GET_ALL_HEADERS)
    {
        do
        {
            lpResult->lpHeaders=NULL;
            lpResult->dwHeadersLen=0;

            WCHAR *lpRequestHeaders=NULL,
                  szTmp[1];
            DWORD dwSize=0;
            if ((HttpQueryInfoW(lpReq->hReq,HTTP_QUERY_RAW_HEADERS_CRLF,szTmp,&dwSize,NULL)) || (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
                break;

            dwSize+=2;
            lpRequestHeaders=(WCHAR*)MemQuickAlloc(dwSize);
            if (!lpRequestHeaders)
                break;

            if (!HttpQueryInfoW(lpReq->hReq,HTTP_QUERY_RAW_HEADERS_CRLF,lpRequestHeaders,&dwSize,NULL))
            {
                MemFree(lpRequestHeaders);
                break;
            }

            lpResult->lpHeaders=lpRequestHeaders;
            lpResult->dwHeadersLen=dwSize;
        }
        while (false);
    }
    return;
}

SYSLIBFUNC(HANDLE) InetSendRequestExW(HANDLE hUrl,HTTP_METHODS dwMethod,HTTP_DATA_TYPE dwDataType,LPCWSTR lpHeaders,HANDLE hArgumentsList,PREQUEST_RESULTW lpResult,DWORD dwFlags)
{
    HANDLE hReq=InetOpenRequest(hUrl,dwMethod,dwDataType,dwFlags);
    if (hReq)
    {
        HTTP_REQUEST_HANDLE *lpReq=(HTTP_REQUEST_HANDLE*)hReq;
        EnterSafeCriticalSection(&lpReq->csRequest);
        {
            if (lpHeaders)
                HttpAddRequestHeadersW(lpReq->hReq,lpHeaders,-1,HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA);
        }
        LeaveSafeCriticalSection(&lpReq->csRequest);

        CloneRequestArguments(hReq,hArgumentsList);

        if (InetSendRequest(hReq))
            GetRequestResultW(lpReq,lpResult);
        else
        {
            InetCloseHandle(hReq);
            hReq=NULL;
        }
    }
    return hReq;
}

static void GetRequestResultA(HTTP_REQUEST_HANDLE *lpReq,PREQUEST_RESULTA lpResult)
{
    if ((!lpResult) || (!lpReq))
        return;

    if (lpResult->dwResultFlags & INET_RESULT_FLAG_READ_RESPONSE)
        lpResult->dwResponseSize=InetReadRequestResponse(lpReq,&lpResult->lpResponse);

    if (lpResult->dwResultFlags & INET_RESULT_FLAG_GET_REQUEST_URL)
    {
        do
        {
            DWORD dwLen=INTERNET_MAX_URL_LENGTH;
            char *lpNewUrl=(char*)MemQuickAlloc(dwLen);
            if (!lpNewUrl)
                break;

            if (!InetGetUrlLocationA(lpReq->lpUrl,lpNewUrl,&dwLen))
            {
                MemFree(lpNewUrl);
                break;
            }

            lpResult->lpRedirectedUrl=lpNewUrl;
            lpResult->dwRedirectedUrlLen=dwLen;
        }
        while (false);
    }

    if (lpResult->dwResultFlags & INET_RESULT_FLAG_GET_STATUS_CODE)
    {
        DWORD dwSize=sizeof(lpResult->dwStatusCode);
        HttpQueryInfoA(lpReq->hReq,HTTP_QUERY_STATUS_CODE|HTTP_QUERY_FLAG_NUMBER,&lpResult->dwStatusCode,&dwSize,NULL);
    }

    if (lpResult->dwResultFlags & INET_RESULT_FLAG_GET_ALL_HEADERS)
    {
        do
        {
            char *lpRequestHeaders=NULL,
                 szTmp[1];
            DWORD dwSize=0;
            if ((HttpQueryInfoA(lpReq->hReq,HTTP_QUERY_RAW_HEADERS_CRLF,szTmp,&dwSize,NULL)) || (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
                break;

            dwSize+=2;
            lpRequestHeaders=(char*)MemQuickAlloc(dwSize);
            if (!lpRequestHeaders)
                break;

            if (!HttpQueryInfoA(lpReq->hReq,HTTP_QUERY_RAW_HEADERS_CRLF,lpRequestHeaders,&dwSize,NULL))
            {
                MemFree(lpRequestHeaders);
                break;
            }

            lpResult->lpHeaders=lpRequestHeaders;
            lpResult->dwHeadersLen=dwSize;
        }
        while (false);
    }
    return;
}

SYSLIBFUNC(HANDLE) InetSendRequestExA(HANDLE hUrl,HTTP_METHODS dwMethod,HTTP_DATA_TYPE dwDataType,LPCSTR lpHeaders,HANDLE hArgumentsList,PREQUEST_RESULTA lpResult,DWORD dwFlags)
{
    HANDLE hReq=InetOpenRequest(hUrl,dwMethod,dwDataType,dwFlags);
    if (hReq)
    {
        HTTP_REQUEST_HANDLE *lpReq=(HTTP_REQUEST_HANDLE*)hReq;
        EnterSafeCriticalSection(&lpReq->csRequest);
        {
            if (lpHeaders)
                HttpAddRequestHeadersA(lpReq->hReq,lpHeaders,-1,HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA);
        }
        LeaveSafeCriticalSection(&lpReq->csRequest);

        CloneRequestArguments(hReq,hArgumentsList);

        if (InetSendRequest(hReq))
            GetRequestResultA(lpReq,lpResult);
        else
        {
            InetCloseHandle(hReq);
            hReq=NULL;
        }
    }
    return hReq;
}

SYSLIBFUNC(BOOL) InetCallUrlExW(HANDLE hSession,LPCWSTR lpUrl,HTTP_METHODS dwMethod,HTTP_DATA_TYPE dwDataType,LPCWSTR lpReferer,LPCWSTR lpHeaders,HANDLE hArgumentsList,PREQUEST_RESULTW lpResult,DWORD dwFlags)
{
    BOOL bRet=false;
    HANDLE hUrl=InetOpenUrlW(hSession,lpUrl,lpReferer,dwFlags);
    if (hUrl)
    {
        HANDLE hReq=InetSendRequestExW(hUrl,dwMethod,dwDataType,lpHeaders,hArgumentsList,lpResult,dwFlags);
        if (hReq)
            bRet=true;

        InetCloseHandle(hUrl);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) InetCallUrlExA(HANDLE hSession,LPCSTR lpUrl,HTTP_METHODS dwMethod,HTTP_DATA_TYPE dwDataType,LPCSTR lpReferer,LPCSTR lpHeaders,HANDLE hArgumentsList,PREQUEST_RESULTA lpResult,DWORD dwFlags)
{
    BOOL bRet=false;
    HANDLE hUrl=InetOpenUrlA(hSession,lpUrl,lpReferer,dwFlags);
    if (hUrl)
    {
        HANDLE hReq=InetSendRequestExA(hUrl,dwMethod,dwDataType,lpHeaders,hArgumentsList,lpResult,dwFlags);
        if (hReq)
            bRet=true;

        InetCloseHandle(hUrl);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) InetCallUrlW(HANDLE hSession,LPCWSTR lpUrl,HTTP_METHODS dwMethod,LPCWSTR lpReferer,PREQUEST_RESULTW lpResult,DWORD dwFlags)
{
    return InetCallUrlExW(hSession,lpUrl,dwMethod,HTTP_DATA_TYPE_UNKNOWN,lpReferer,NULL,NULL,lpResult,dwFlags);
}

SYSLIBFUNC(BOOL) InetCallUrlA(HANDLE hSession,LPCSTR lpUrl,HTTP_METHODS dwMethod,LPCSTR lpReferer,PREQUEST_RESULTA lpResult,DWORD dwFlags)
{
    return InetCallUrlExA(hSession,lpUrl,dwMethod,HTTP_DATA_TYPE_UNKNOWN,lpReferer,NULL,NULL,lpResult,dwFlags);
}

static void CloseRequestHandleInt(HTTP_REQUEST_HANDLE *lpHandle)
{
    EnterSafeCriticalSection(&lpHandle->csRequest);
    {
        InternetCloseHandle(lpHandle->hReq);

        InetArgsList_Destroy(lpHandle->hArgsList);
    }
    LeaveSafeCriticalSection(&lpHandle->csRequest);

    DeleteSafeCriticalSection(&lpHandle->csRequest);

    HTTP_REQUEST_HANDLE *lpReq=lpHandle->lpUrl->lpRequests,*lpPrev=NULL;
    while (lpReq != lpHandle)
    {
        lpPrev=lpReq;
        lpReq=lpReq->lpNext;
    }

    if (lpPrev)
        lpPrev->lpNext=lpHandle->lpNext;
    else
        lpHandle->lpUrl->lpRequests=lpHandle->lpNext;

    MemFree(lpHandle);
    return;
}

static void CloseUrlHandleInt(HTTP_URL_HANDLE *lpHandle)
{
    EnterSafeCriticalSection(&lpHandle->csUrl);
    {
        while (lpHandle->lpRequests)
            CloseRequestHandleInt(lpHandle->lpRequests);

        MemFree(lpHandle->lpHost);
        MemFree(lpHandle->lpUser);
        MemFree(lpHandle->lpPassword);
        MemFree(lpHandle->lpPath);
        MemFree(lpHandle->lpReferer);

        InternetCloseHandle(lpHandle->hUrl);
    }
    LeaveSafeCriticalSection(&lpHandle->csUrl);

    HTTP_URL_HANDLE *lpUrl=lpHandle->lpSession->lpUrls,*lpPrev=NULL;
    if (lpUrl)
    {
        while (lpUrl != lpHandle)
        {
            lpPrev=lpUrl;
            lpUrl=lpUrl->lpNext;
        }
    }

    if (lpPrev)
        lpPrev->lpNext=lpHandle->lpNext;
    else
        lpHandle->lpSession->lpUrls=lpHandle->lpNext;

    DeleteSafeCriticalSection(&lpHandle->csUrl);
    MemFree(lpHandle);
    return;
}

static void CloseSessionHandle(HTTP_SESSION_HANDLE *lpHandle)
{
    EnterSafeCriticalSection(&lpHandle->csSession);
    {
        while (lpHandle->lpUrls)
            CloseUrlHandleInt(lpHandle->lpUrls);

        InternetCloseHandle(lpHandle->hOpen);

        if (lpHandle->dwProxyType == INET_PROXY_USER_DEFINED)
        {
            MemFree((LPVOID)lpHandle->ProxySettings.lpProxyPassword);
            MemFree((LPVOID)lpHandle->ProxySettings.lpProxyServer);
            MemFree((LPVOID)lpHandle->ProxySettings.lpProxyUser);
        }

        MemFree(lpHandle->lpVersion);
        MemFree(lpHandle->lpAgent);
        SYSLIB::InetCleanSessionCookies(lpHandle);
    }
    LeaveSafeCriticalSection(&lpHandle->csSession);

    DeleteSafeCriticalSection(&lpHandle->csSession);

    MemFree(lpHandle);
    return;
}

static void CloseUrlHandle(HTTP_URL_HANDLE *lpHandle)
{
    EnterSafeCriticalSection(&lpHandle->lpSession->csSession);
        CloseUrlHandleInt(lpHandle);
    LeaveSafeCriticalSection(&lpHandle->lpSession->csSession);
    return;
}

static void CloseRequestHandle(HTTP_REQUEST_HANDLE *lpHandle)
{
    EnterSafeCriticalSection(&lpHandle->lpUrl->csUrl);
        CloseRequestHandleInt(lpHandle);
    LeaveSafeCriticalSection(&lpHandle->lpUrl->csUrl);
    return;
}

SYSLIBFUNC(void) InetCloseHandle(HANDLE hInet)
{
    HTTP_HANDLE *lpHandle=(HTTP_HANDLE*)hInet;
    if (lpHandle)
    {
        switch (lpHandle->dwType)
        {
            case HTTP_SESSION:
            {
                CloseSessionHandle((HTTP_SESSION_HANDLE*)lpHandle);
                break;
            }
            case HTTP_URL:
            {
                CloseUrlHandle((HTTP_URL_HANDLE*)lpHandle);
                break;
            }
            case HTTP_REQUEST:
            {
                CloseRequestHandle((HTTP_REQUEST_HANDLE*)lpHandle);
                break;
            }
        }
    }
    return;
}

