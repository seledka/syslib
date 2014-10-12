#ifndef COOKIE_H_INCLUDED
#define COOKIE_H_INCLUDED

struct COOKIE;

struct HTTP_SESSION_HANDLE;
struct COOKIE_DOMAIN
{
    HTTP_SESSION_HANDLE *lpSession;

    WCHAR *lpCookieDomain;
    WCHAR *lpCookiePath;
    DWORD dwPathLen;
    COOKIE *lpCookies;

    COOKIE_DOMAIN *lpNext;
};

#define COOKIE_FLAG_SECURE       1
#define COOKIE_FLAG_DISCARD      2
#define COOKIE_FLAG_EXPIRES_SET  4
#define COOKIE_FLAG_PORT_SET     8

struct COOKIE
{
    COOKIE_DOMAIN *lpDomain;

    DWORD dwCookieFlags;
    WCHAR *lpCookieName;
    DWORD dwCookieNameSize;
    WCHAR *lpCookieValue;
    DWORD dwCookieValueSize;
    WORD *lpPortsList;
    DWORD dwPortsCount;
    FILETIME ftExpiry;

    COOKIE *lpNext;
};

struct HTTP_REQUEST_HANDLE;

#define COOKIE_HANDLER_MAXAGE_SET  1
#define COOKIE_HANDLER_VERSION_SET 2
#define COOKIE_HANDLER_EXPIRED     4

namespace SYSLIB
{
    void InetProcessCookies(HTTP_REQUEST_HANDLE *lpReq);
    void InetInsertCookies(HTTP_REQUEST_HANDLE *lpReq);
    void InetCleanSessionCookies(HTTP_SESSION_HANDLE *lpSession);
};

#define NS_IN_MCSEC    1000
#define NS_IN_MSEC     NS_IN_MCSEC*1000
#define NS_IN_SEC      NS_IN_MSEC*1000

#define _100NS_IN_SEC  NS_IN_SEC/100
#define _100NS_IN_MIN  (_100NS_IN_SEC)*60
#define _100NS_IN_HOUR _100NS_IN_MIN*60
#define _100NS_IN_DAY  _100NS_IN_HOUR*24
#define _100NS_IN_WEEK _100NS_IN_DAY*7

#define IsKnownParam(name,size) (!(StrCmpNIW(lpPtr,name,size)))

#endif // COOKIE_H_INCLUDED
