#include "sys_includes.h"
#include <wininet.h>

#include "syslib\str.h"
#include "syslib\net.h"
#include "syslib\mem.h"
#include "syslib\criticalsections.h"

#include "http.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

static DWORD IsStatusOk(HANDLE hReq,LPDWORD lpdwErrorCode=NULL)
{
    DWORD dwStatus,
          dwSize=sizeof(dwStatus);
    HttpQueryInfoW(hReq,HTTP_QUERY_STATUS_CODE|HTTP_QUERY_FLAG_NUMBER,&dwStatus,&dwSize,NULL);
    if (lpdwErrorCode)
        *lpdwErrorCode=dwStatus;
    return (dwStatus == HTTP_STATUS_OK);
}

SYSLIBFUNC(BOOL) InetDownloadToFileW(HANDLE hSession,LPCWSTR lpUrl,LPCWSTR lpReferer,LPCWSTR lpFile)
{
    BOOL bRet=false;
    HANDLE hUrl=InetOpenUrlW(hSession,lpUrl,lpReferer,0);
    if (hUrl)
    {
        HANDLE hReq=InetOpenRequest(hUrl,HTTP_METHOD_GET,HTTP_DATA_TYPE_UNKNOWN,0);
        if (hReq)
        {
            if (InetSendRequest(hReq))
            {
                if (IsStatusOk(((HTTP_REQUEST_HANDLE*)hReq)->hReq))
                    bRet=InetReadRequestResponseToFileW(hReq,lpFile);
            }
            else
            {
                InetCloseHandle(hReq);
                hReq=NULL;
            }
        }
        InetCloseHandle(hUrl);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) InetDownloadToFileA(HANDLE hSession,LPCSTR lpUrl,LPCSTR lpReferer,LPCSTR lpFile)
{
    BOOL bRet=false;
    HANDLE hUrl=InetOpenUrlA(hSession,lpUrl,lpReferer,0);
    if (hUrl)
    {
        HANDLE hReq=InetOpenRequest(hUrl,HTTP_METHOD_GET,HTTP_DATA_TYPE_UNKNOWN,0);
        if (hReq)
        {
            if (InetSendRequest(hReq))
            {
                if (IsStatusOk(((HTTP_REQUEST_HANDLE*)hReq)->hReq))
                    bRet=InetReadRequestResponseToFileA(hReq,lpFile);
            }
            else
            {
                InetCloseHandle(hReq);
                hReq=NULL;
            }
        }
        InetCloseHandle(hUrl);
    }
    return bRet;
}

SYSLIBFUNC(DWORD) InetDownloadW(HANDLE hSession,LPCWSTR lpUrl,LPCWSTR lpReferer,LPVOID *lppData,LPDWORD lpdwErrorCode)
{
    DWORD dwDownloaded=0,
          dwErrorCode=0;
    HANDLE hUrl=InetOpenUrlW(hSession,lpUrl,lpReferer,0);
    if (hUrl)
    {
        HANDLE hReq=InetOpenRequest(hUrl,HTTP_METHOD_GET,HTTP_DATA_TYPE_UNKNOWN,0);
        if (hReq)
        {
            if (InetSendRequest(hReq))
            {
                if (IsStatusOk(((HTTP_REQUEST_HANDLE*)hReq)->hReq,&dwErrorCode))
                    dwDownloaded=InetReadRequestResponse(hReq,lppData);
            }
            else
            {
                InetCloseHandle(hReq);
                hReq=NULL;
            }
        }
        InetCloseHandle(hUrl);
    }

    if (SYSLIB_SAFE::CheckParamWrite(lpdwErrorCode,sizeof(*lpdwErrorCode)))
        *lpdwErrorCode=dwErrorCode;
    return dwDownloaded;
}

SYSLIBFUNC(DWORD) InetDownloadA(HANDLE hSession,LPCSTR lpUrl,LPCSTR lpReferer,LPVOID *lppData,LPDWORD lpdwErrorCode)
{
    DWORD dwDownloaded=0,
          dwErrorCode=0;
    HANDLE hUrl=InetOpenUrlA(hSession,lpUrl,lpReferer,0);
    if (hUrl)
    {
        HANDLE hReq=InetOpenRequest(hUrl,HTTP_METHOD_GET,HTTP_DATA_TYPE_UNKNOWN,0);
        if (hReq)
        {
            if (InetSendRequest(hReq))
            {
                if (IsStatusOk(((HTTP_REQUEST_HANDLE*)hReq)->hReq,&dwErrorCode))
                    dwDownloaded=InetReadRequestResponse(hReq,lppData);
            }
            else
            {
                InetCloseHandle(hReq);
                hReq=NULL;
            }
        }
        InetCloseHandle(hUrl);
    }

    if (SYSLIB_SAFE::CheckParamWrite(lpdwErrorCode,sizeof(*lpdwErrorCode)))
        *lpdwErrorCode=dwErrorCode;
    return dwDownloaded;
}

