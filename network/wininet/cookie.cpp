#include "sys_includes.h"
#include <wininet.h>
#include <shlwapi.h>

#include "syslib\str.h"
#include "syslib\debug.h"
#include "syslib\net.h"
#include "syslib\mem.h"
#include "syslib\criticalsections.h"

#include "http.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

namespace SYSLIB
{
        static COOKIE *Cookie_Add(COOKIE_DOMAIN *lpCookieDomain,WCHAR *lpCookieName,WCHAR *lpCookieValue)
    {
        COOKIE *lpCookie=(COOKIE *)MemAlloc(sizeof(COOKIE));
        if (lpCookie)
        {
            lpCookie->lpDomain=lpCookieDomain;

            lpCookie->lpCookieName=StrDuplicateW(lpCookieName,0);
            lpCookie->dwCookieNameSize=lstrlenW(lpCookieName);
            lpCookie->lpCookieValue=StrDuplicateW(lpCookieValue,0);
            lpCookie->dwCookieValueSize=lstrlenW(lpCookieValue);

            if (lpCookieDomain->lpCookies)
            {
                COOKIE *lpCurCookie=lpCookieDomain->lpCookies;
                while (lpCurCookie->lpNext)
                    lpCurCookie=lpCurCookie->lpNext;

                lpCurCookie->lpNext=lpCookie;
            }
            else
                lpCookieDomain->lpCookies=lpCookie;
        }
        return lpCookie;
    }

    void Cookie_Delete(COOKIE *lpCookie,bool bDelete);

    static void Cookie_DeleteDomain(COOKIE_DOMAIN *lpDomain)
    {
        HTTP_SESSION_HANDLE *lpSession=lpDomain->lpSession;

        COOKIE_DOMAIN *lpCurDomain=lpSession->lpSessionCookies,*lpPrev=NULL;
        while (lpCurDomain != lpDomain)
        {
            lpPrev=lpCurDomain;
            lpCurDomain=lpCurDomain->lpNext;
        }

        if (lpPrev)
            lpPrev->lpNext=lpDomain->lpNext;
        else
            lpSession->lpSessionCookies=lpDomain->lpNext;

        while (lpDomain->lpCookies)
            Cookie_Delete(lpDomain->lpCookies,false);

        MemFree(lpDomain->lpCookieDomain);
        MemFree(lpDomain->lpCookiePath);
        MemFree(lpDomain->lpCookies);

        MemFree(lpDomain);
        return;
    }

    static void Cookie_Delete(COOKIE *lpCookie,bool bDelete)
    {
        COOKIE_DOMAIN *lpDomain=lpCookie->lpDomain;
        COOKIE *lpCurCookie=lpDomain->lpCookies,*lpPrev=NULL;
        while (lpCurCookie != lpCookie)
        {
            lpPrev=lpCurCookie;
            lpCurCookie=lpCurCookie->lpNext;
        }

        if (lpPrev)
            lpPrev->lpNext=lpCookie->lpNext;
        else
            lpDomain->lpCookies=lpCookie->lpNext;

        MemFree(lpCookie->lpCookieName);
        MemFree(lpCookie->lpCookieValue);
        MemFree(lpCookie->lpPortsList);

        MemFree(lpCookie);

        if ((bDelete) && (!lpDomain->lpCookies))
            Cookie_DeleteDomain(lpDomain);
        return;
    }

    static COOKIE *Cookie_Find(COOKIE_DOMAIN *lpDomain,WCHAR *lpCookieName)
    {
        COOKIE *lpCookie=lpDomain->lpCookies;
        while (lpCookie)
        {
            COOKIE *lpCurCookie=lpCookie;
            lpCookie=lpCookie->lpNext;

            if (lpCookieName)
            {
                if (!lpCurCookie->lpCookieName)
                    continue;
                if (!lstrcmpiW(lpCookieName,lpCurCookie->lpCookieName))
                    break;
            }
        }
        return lpCookie;
    }

    static COOKIE_DOMAIN *Cookie_AddDomain(HTTP_SESSION_HANDLE *lpSession,WCHAR *lpCookieDomain,WCHAR *lpCookiePath)
    {
        COOKIE_DOMAIN *lpDomain=(COOKIE_DOMAIN*)MemAlloc(sizeof(COOKIE_DOMAIN));
        if (lpDomain)
        {
            lpDomain->lpSession=lpSession;

            lpDomain->lpCookieDomain=StrDuplicateW(lpCookieDomain,0);
            lpDomain->lpCookiePath=StrDuplicateW(lpCookiePath,0);
            lpDomain->dwPathLen=lstrlenW(lpCookiePath);

            if (lpSession->lpSessionCookies)
            {
                COOKIE_DOMAIN *lpCurDomain=lpSession->lpSessionCookies;
                while (lpCurDomain->lpNext)
                    lpCurDomain=lpCurDomain->lpNext;

                lpCurDomain->lpNext=lpDomain;
            }
            else
                lpSession->lpSessionCookies=lpDomain;
        }
        return lpDomain;
    }

    static COOKIE_DOMAIN *Cookie_FindDomain(HTTP_SESSION_HANDLE *lpSession,WCHAR *lpCookieDomain,WCHAR *lpCookiePath,bool bAllowPartial,COOKIE_DOMAIN *lpFindFrom)
    {
        COOKIE_DOMAIN *lpCurDomain=lpSession->lpSessionCookies;
        if (lpFindFrom)
            lpCurDomain=lpFindFrom->lpNext;

        while (lpCurDomain)
        {
            COOKIE_DOMAIN *lpDomain=lpCurDomain;
            lpCurDomain=lpCurDomain->lpNext;

            if (lpCookieDomain)
            {
                if (!lpDomain->lpCookieDomain)
                    continue;

                if ((bAllowPartial) && (!StrStrIW(lpCookieDomain,lpDomain->lpCookieDomain)))
                    continue;
                else if ((!bAllowPartial) && (lstrcmpiW(lpCookieDomain,lpDomain->lpCookieDomain)))
                    continue;
            }
            if (lpCookiePath)
            {
                if (!lpDomain->lpCookiePath)
                    continue;

                if (bAllowPartial)
                {
                    if (StrCmpNIW(lpDomain->lpCookiePath,lpCookiePath,lpDomain->dwPathLen))
                        continue;
                }
                else if (lstrcmpiW(lpCookiePath,lpDomain->lpCookiePath))
                    continue;
            }
            lpCurDomain=lpDomain;
            break;
        }
        return lpCurDomain;
    }

    static WCHAR *GetCookieParamValuePtr(WCHAR *lpPtr)
    {
        lpPtr=StrChrW(lpPtr,L'=');
        if (lpPtr)
        {
            lpPtr++;
            while ((*lpPtr) && (*lpPtr == L' '))
                lpPtr++;
        }
        return lpPtr;
    }

    static void Cookie_Parse(HTTP_SESSION_HANDLE *lpSession,WCHAR *lpCookieDomain,WCHAR *lpCookiePath,WCHAR *lpCookieName,WCHAR *lpData)
    {
        WCHAR *lpPtr=lpData,
              *lpPorts=NULL;

        DWORD dwCookieFlags=0,
              dwFlags=0,
              dwPortsCount=0;

        FILETIME ftExpiry={0};
        while (true)
        {
            if (!(lpPtr=StrChrW(lpPtr,L';')))
                break;

            *lpPtr++=0;

            while ((*lpPtr) && (*lpPtr == L' '))
                lpPtr++;

            if (IsKnownParam(dcrW_c7ed8bb1("domain"),6))
            {
                lpPtr=GetCookieParamValuePtr(lpPtr);
                lpCookieDomain=lpPtr;
            }
            else if (IsKnownParam(dcrW_1ab74e01("path"),4))
            {
                lpPtr=GetCookieParamValuePtr(lpPtr);
                lpCookiePath=lpPtr;
            }
            else if (IsKnownParam(dcrW_a3df71ef("expires"),7))
            {
                lpPtr=GetCookieParamValuePtr(lpPtr);
                if ((!(dwCookieFlags & COOKIE_FLAG_EXPIRES_SET)) && (!(dwFlags & COOKIE_HANDLER_MAXAGE_SET)))
                {
                    SYSTEMTIME st;
                    if (InternetTimeToSystemTimeW(lpPtr,&st,0))
                    {
                        dwCookieFlags|=COOKIE_FLAG_EXPIRES_SET;
                        SystemTimeToFileTime(&st,&ftExpiry);
                        FILETIME tm;
                        GetSystemTimeAsFileTime(&tm);

                        if (CompareFileTime(&tm,&ftExpiry) > 0)
                            dwFlags|=COOKIE_HANDLER_EXPIRED;
                    }
                }
            }
            else if (IsKnownParam(dcrW_77b02e79("secure"),6))
            {
                lpPtr=GetCookieParamValuePtr(lpPtr);
                dwCookieFlags|=COOKIE_FLAG_SECURE;
            }
            else if (IsKnownParam(dcrW_60249e06("discard"),7))
            {
                lpPtr=GetCookieParamValuePtr(lpPtr);
                dwCookieFlags|=COOKIE_FLAG_DISCARD;
            }
            else if (IsKnownParam(dcrW_53e691c9("max-age"),7))
            {
                lpPtr=GetCookieParamValuePtr(lpPtr);
                GetSystemTimeAsFileTime(&ftExpiry);

                /**
                    MSDN:
                    It is not recommended that you add and subtract values from the FILETIME structure to obtain relative times.
                    Instead, you should copy the low- and high-order parts of the file time to a LARGE_INTEGER structure, perform
                    64-bit arithmetic on the QuadPart member, and copy the LowPart and HighPart members into the FILETIME structure.

                    Do not cast a pointer to a FILETIME structure to either a LARGE_INTEGER* or __int64* value because it can cause
                    alignment faults on 64-bit Windows.
                **/

                LARGE_INTEGER liTime={ftExpiry.dwLowDateTime,ftExpiry.dwHighDateTime};
                liTime.QuadPart+=StrToIntW(lpPtr)*_100NS_IN_SEC;
                ftExpiry.dwLowDateTime=liTime.LowPart;
                ftExpiry.dwHighDateTime=liTime.HighPart;

                dwFlags|=COOKIE_HANDLER_MAXAGE_SET;
                dwCookieFlags|=COOKIE_FLAG_EXPIRES_SET;
            }
            else if (IsKnownParam(dcrW_f98fd7e9("port"),4))
            {
                lpPtr=GetCookieParamValuePtr(lpPtr);
                do
                {
                    if (dwCookieFlags & COOKIE_FLAG_PORT_SET)
                        break;

                    if (*lpPtr != L'"')
                        break;

                    WCHAR *lpPortsStart=lpPtr+1,
                          *lpPortsEnd=StrChrW(lpPortsStart,L'"');

                    if (!lpPortsEnd)
                        break;

                    dwPortsCount=1;
                    WCHAR *lpCurPort=lpPortsStart;
                    while (true)
                    {
                        lpCurPort=StrChrW(lpCurPort,L',');
                        if (!lpCurPort)
                            break;

                        if (lpCurPort > lpPortsEnd)
                            break;

                        dwPortsCount++;
                        lpCurPort++;
                    }

                    lpPorts=lpPortsStart;
                    dwCookieFlags|=COOKIE_FLAG_PORT_SET;
                }
                while (false);
            }
        }

        do
        {
            COOKIE_DOMAIN *lpDomain=Cookie_FindDomain(lpSession,lpCookieDomain,lpCookiePath,false,NULL);
            if ((!lpDomain) && (!(dwFlags & COOKIE_HANDLER_EXPIRED)))
                lpDomain=Cookie_AddDomain(lpSession,lpCookieDomain,lpCookiePath);

            if (!lpDomain)
                break;

            COOKIE *lpCookie=Cookie_Find(lpDomain,lpCookieName);
            if (lpCookie)
                Cookie_Delete(lpCookie,(!(dwFlags & COOKIE_HANDLER_EXPIRED)));

            if (!(dwFlags & COOKIE_HANDLER_EXPIRED))
            {
                COOKIE *lpCookie=Cookie_Add(lpDomain,lpCookieName,lpData);
                if (!lpCookie)
                    break;

                lpCookie->ftExpiry=ftExpiry;
                lpCookie->dwCookieFlags=dwCookieFlags;

                if (dwCookieFlags & COOKIE_FLAG_PORT_SET)
                {
                    lpCookie->lpPortsList=(WORD*)MemQuickAlloc(dwPortsCount*sizeof(WORD));
                    if (lpCookie->lpPortsList)
                    {
                        lpCookie->dwPortsCount&=~COOKIE_FLAG_PORT_SET;
                        break;
                    }

                    lpCookie->dwPortsCount=dwPortsCount;

                    WCHAR *lpCurPort=lpPorts;
                    for (DWORD i=0; i < dwPortsCount; i++)
                    {
                        lpCookie->lpPortsList[i]=StrToIntW(lpCurPort);

                        lpCurPort=StrChrW(lpCurPort,L',');
                        lpCurPort++;
                    }
                }
            }
        }
        while (false);
        return;
    }

    void InetProcessCookies(HTTP_REQUEST_HANDLE *lpReq)
    {
        if ((lpReq) && (lpReq->dwType == HTTP_REQUEST))
        {
            EnterSafeCriticalSection(&lpReq->lpUrl->lpSession->csSession);
            {
                WCHAR *lpUrl=NULL,
                      *lpPath=NULL,
                      *lpHost=NULL;
                do
                {
                    DWORD dwLen=INTERNET_MAX_URL_LENGTH*sizeof(WCHAR);
                    lpUrl=(WCHAR*)MemQuickAlloc(dwLen);
                    if (!lpUrl)
                        break;

                    if (!InternetQueryOptionW(lpReq->hReq,INTERNET_OPTION_URL,lpUrl,&dwLen))
                        break;

                    lpPath=WCHAR_QuickAlloc(INTERNET_MAX_PATH_LENGTH);
                    if (!lpPath)
                        break;

                    lpHost=WCHAR_QuickAlloc(INTERNET_MAX_HOST_NAME_LENGTH);
                    if (!lpHost)
                        break;

                    URL_COMPONENTSW url={0};
                    url.dwStructSize=sizeof(url);
                    url.lpszHostName=lpHost;
                    url.dwHostNameLength=INTERNET_MAX_HOST_NAME_LENGTH;
                    url.lpszUrlPath=lpPath;
                    url.dwUrlPathLength=INTERNET_MAX_PATH_LENGTH;
                    if (!InternetCrackUrlW(lpUrl,NULL,0,&url))
                        break;

                    DWORD i=0;
                    while (true)
                    {
                        WCHAR *lpCookie=NULL,szTmp[1];
                        DWORD dwSize=0;
                        if ((HttpQueryInfoW(lpReq->hReq,HTTP_QUERY_SET_COOKIE,szTmp,&dwSize,&i)) || (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
                            break;

                        dwSize+=2;
                        lpCookie=(WCHAR*)MemQuickAlloc(dwSize);
                        if (!lpCookie)
                            break;

                        if (HttpQueryInfoW(lpReq->hReq,HTTP_QUERY_SET_COOKIE,lpCookie,&dwSize,&i))
                        {
                            WCHAR *lpData=StrChrW(lpCookie,L'=');
                            if (lpData)
                            {
                                *lpData++=0;
                                Cookie_Parse(lpReq->lpUrl->lpSession,lpHost,lpPath,lpCookie,lpData);
                            }
                        }
                        MemFree(lpCookie);
                    }
                }
                while (false);

                MemFree(lpUrl);
                MemFree(lpPath);
                MemFree(lpHost);
            }
            LeaveSafeCriticalSection(&lpReq->lpUrl->lpSession->csSession);
        }
        return;
    }

    static bool Cookie_Get(HTTP_SESSION_HANDLE *lpSession,WCHAR *lpHost,WCHAR *lpPath,WCHAR **lppCookiesHdr,bool bSecure,WORD wPort)
    {
        DWORD dwCookiesCount=0;

        FILETIME tm;
        GetSystemTimeAsFileTime(&tm);

        DWORD dwCurSize=sizeof("Cookie: ")-1;
        WCHAR *lpCookiesHdr=StrDuplicateW(dcrW_46ceba8e("Cookie: "),0);
        *lppCookiesHdr=NULL;

        COOKIE_DOMAIN *lpDomain=NULL;
        while (lpDomain=Cookie_FindDomain(lpSession,lpHost,lpPath,true,lpDomain))
        {
            COOKIE *lpCookie=lpDomain->lpCookies;
            while (lpCookie)
            {
                COOKIE *lpCurCookie=lpCookie;
                lpCookie=lpCookie->lpNext;

                if ((lpCurCookie->dwCookieFlags & COOKIE_FLAG_EXPIRES_SET) && (CompareFileTime(&tm,&lpCurCookie->ftExpiry) > 0))
                {
                    Cookie_Delete(lpCurCookie,false);
                    continue;
                }

                if ((lpCurCookie->dwCookieFlags & COOKIE_FLAG_SECURE) && (!bSecure))
                    continue;

                if (lpCurCookie->dwCookieFlags & COOKIE_FLAG_PORT_SET)
                {
                    bool bGoodCookie=false;
                    for (DWORD i=0; i < lpCurCookie->dwPortsCount; i++)
                    {
                        if (lpCurCookie->lpPortsList[i] == wPort)
                        {
                            bGoodCookie=true;
                            break;
                        }
                    }

                    if (!bGoodCookie)
                        continue;
                }

                if (dwCookiesCount)
                    dwCurSize=StrCatFormatExW(&lpCookiesHdr,dwCurSize,dcrW_cefd71e7("; %s"),lpCurCookie->lpCookieName);
                else
                    dwCurSize=StrCatExW(&lpCookiesHdr,lpCurCookie->lpCookieName,0);

                if (lpCurCookie->lpCookieValue)
                    dwCurSize=StrCatFormatExW(&lpCookiesHdr,dwCurSize,dcrW_21840aef("=%s"),lpCurCookie->lpCookieValue);

                dwCookiesCount++;

                if (!lpCookiesHdr)
                    break;
            }
        }

        if (!lpCookiesHdr)
            dwCookiesCount=0;
        else
        {
            StrCatExW(&lpCookiesHdr,dcrW_0f7b6850("\r\n"),2);
            *lppCookiesHdr=lpCookiesHdr;
        }
        return (dwCookiesCount != 0);
    }

    void InetInsertCookies(HTTP_REQUEST_HANDLE *lpReq)
    {
        if ((lpReq) && (lpReq->dwType == HTTP_REQUEST))
        {
            EnterSafeCriticalSection(&lpReq->lpUrl->lpSession->csSession);
            {
                WCHAR *lpUrl=NULL,
                      *lpPath=NULL,
                      *lpHost=NULL;
                do
                {
                    DWORD dwLen=INTERNET_MAX_URL_LENGTH*sizeof(WCHAR);
                    lpUrl=(WCHAR*)MemQuickAlloc(dwLen);
                    if (!lpUrl)
                        break;

                    if (!InternetQueryOptionW(lpReq->hReq,INTERNET_OPTION_URL,lpUrl,&dwLen))
                        break;

                    lpPath=WCHAR_QuickAlloc(INTERNET_MAX_PATH_LENGTH);
                    if (!lpPath)
                        break;

                    lpHost=WCHAR_QuickAlloc(INTERNET_MAX_HOST_NAME_LENGTH);
                    if (!lpHost)
                        break;

                    URL_COMPONENTSW url={0};
                    url.dwStructSize=sizeof(url);
                    url.lpszHostName=lpHost;
                    url.dwHostNameLength=INTERNET_MAX_HOST_NAME_LENGTH;
                    url.lpszUrlPath=lpPath;
                    url.dwUrlPathLength=INTERNET_MAX_PATH_LENGTH;
                    if (!InternetCrackUrlW(lpUrl,NULL,0,&url))
                        break;

                    WCHAR *lpCookies=NULL;
                    if (Cookie_Get(lpReq->lpUrl->lpSession,lpHost,lpPath,&lpCookies,(url.nScheme == INTERNET_SCHEME_HTTPS),url.nPort))
                    {
                        HttpAddRequestHeadersW(lpReq->hReq,lpCookies,-1,HTTP_ADDREQ_FLAG_ADD);
                        MemFree(lpCookies);
                    }
                }
                while (false);

                MemFree(lpUrl);
                MemFree(lpPath);
                MemFree(lpHost);
            }
            LeaveSafeCriticalSection(&lpReq->lpUrl->lpSession->csSession);
        }
        return;
    }

    void InetCleanSessionCookies(HTTP_SESSION_HANDLE *lpSession)
    {
        while (lpSession->lpSessionCookies)
            Cookie_DeleteDomain(lpSession->lpSessionCookies);
        return;
    }
}
