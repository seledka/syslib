#include "sys_includes.h"
#include <wininet.h>

#include "syslib\net.h"
#include "syslib\str.h"
#include "syslib\system.h"
#include "syslib\mem.h"
#include "syslib\criticalsections.h"

#include "http.h"
#include "argslist.h"
#include "requests.h"

SYSLIBFUNC(HANDLE) InetArgsList_Create()
{
    INET_ARGS_LIST *lpList=(INET_ARGS_LIST*)MemAlloc(sizeof(INET_ARGS_LIST));
    if (lpList)
    {
        lpList->dwType=HTTP_ARGUMENTS_LIST;
        InitializeSafeCriticalSection(&lpList->csArguments);
    }
    return (HANDLE)lpList;
}

static void FreeListItem(INET_ARG *lpArg)
{
    MemFree(lpArg->lpName);

    switch (lpArg->dwType)
    {
        case INET_ARG_STRING:
        {
            MemFree(lpArg->lpValueStr);
            break;
        }
        case INET_ARG_RAW:
        {
            MemFree(lpArg->lpValueRaw);
            break;
        }
        case INET_ARG_FILE:
        {
            if (lpArg->lpNextFile)
                FreeListItem(lpArg->lpNextFile);

            MemFree(lpArg->pseudo_file.lpValueRaw);
            MemFree(lpArg->lpFullFileName);
            break;
        }
    }

    MemFree(lpArg);
    return;
}

SYSLIBFUNC(void) InetArgsList_Destroy(HANDLE hList)
{
    INET_ARGS_LIST *lpList=(INET_ARGS_LIST*)hList;
    if ((lpList) && (lpList->dwType == HTTP_ARGUMENTS_LIST))
    {
        EnterSafeCriticalSection(&lpList->csArguments);
        {
            while (lpList->lpArgs)
            {
                INET_ARG *lpArg=lpList->lpArgs;
                lpList->lpArgs=lpArg->lpNext;

                FreeListItem(lpArg);
            }
        }
        LeaveSafeCriticalSection(&lpList->csArguments);
        DeleteSafeCriticalSection(&lpList->csArguments);

        MemFree(lpList);
    }
    return;
}

static void InetAppendArgument(INET_ARGS_LIST *lpList,INET_ARG *lpArg)
{
    if (lpList->lpArgs)
    {
        INET_ARG *lpCurArg=lpList->lpArgs;
        while (lpCurArg->lpNext)
            lpCurArg=lpCurArg->lpNext;

        lpCurArg->lpNext=lpArg;
    }
    else
        lpList->lpArgs=lpArg;
    return;
}

static INET_ARG *FindArgByName(INET_ARGS_LIST *lpList,LPCSTR lpName)
{
    if (!lpName)
        return NULL;

    INET_ARG *lpArg=lpList->lpArgs;
    while (lpArg)
    {
        if (!lstrcmpiA(lpArg->lpName,lpName))
            break;

        lpArg=lpArg->lpNext;
    }
    return lpArg;
}

SYSLIBFUNC(BOOL) InetArgsList_AddBinaryArgumentA(HANDLE hList,LPCSTR lpName,LPVOID lpValue,DWORD dwValueSize)
{
    if ((!lpValue) || (!dwValueSize))
        return false;

    BOOL bRet=false;
    INET_ARGS_LIST *lpList=(INET_ARGS_LIST*)hList;
    if ((lpList) && (lpList->dwType == HTTP_ARGUMENTS_LIST))
    {
        EnterSafeCriticalSection(&lpList->csArguments);
        {
            INET_ARG *lpArg=FindArgByName(lpList,lpName);
            if (lpArg)
            {
                do
                {
                    if (lpArg->dwType != INET_ARG_RAW)
                        break;

                    if (lpArg->dwValueRawSize <= dwValueSize)
                    {
                        memcpy(lpArg->lpValueRaw,lpValue,dwValueSize);
                        lpArg->dwValueRawSize=dwValueSize;
                    }
                    else
                    {
                        void *lpNewVal=MemQuickAlloc(dwValueSize);
                        if (!lpNewVal)
                            break;

                        MemFree(lpArg->lpValueRaw);
                        lpArg->lpValueRaw=lpNewVal;
                        lpArg->dwValueRawSize=dwValueSize;
                        memcpy(lpArg->lpValueRaw,lpValue,dwValueSize);
                    }
                    bRet=true;
                }
                while (false);
            }
            else
            {
                lpArg=(INET_ARG*)MemAlloc(sizeof(INET_ARG));
                do
                {
                    if (!lpArg)
                        break;

                    lpArg->dwType=INET_ARG_RAW;
                    lpArg->lpName=StrDuplicateA(lpName,0);
                    lpArg->lpValueRaw=MemQuickAlloc(dwValueSize);
                    if (!lpArg->lpValueRaw)
                        break;

                    memcpy(lpArg->lpValueRaw,lpValue,dwValueSize);
                    lpArg->dwValueRawSize=dwValueSize;

                    InetAppendArgument(lpList,lpArg);
                    bRet=true;
                }
                while (false);

                if (!bRet)
                    FreeListItem(lpArg);
            }
        }
        LeaveSafeCriticalSection(&lpList->csArguments);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) InetArgsList_AddBinaryArgumentW(HANDLE hList,LPCWSTR lpName,LPVOID lpValue,DWORD dwValueSize)
{
    LPSTR lpNameA=StrUnicodeToAnsiEx(lpName,0,NULL);

    BOOL bRet=InetArgsList_AddBinaryArgumentA(hList,lpNameA,lpValue,dwValueSize);

    MemFree(lpNameA);
    return bRet;
}

static bool AddFileInt(HANDLE hList,LPCSTR lpName,LPCSTR lpFileName,LPVOID lpPseudoFileData,DWORD dwPseudoFileDataSize)
{
    bool bRet=false;
    INET_ARGS_LIST *lpList=(INET_ARGS_LIST*)hList;
    if ((lpList) && (lpList->dwType == HTTP_ARGUMENTS_LIST))
    {
        EnterSafeCriticalSection(&lpList->csArguments);
        {
            INET_ARG *lpArg=FindArgByName(lpList,lpName);
            if (lpArg)
            {
                INET_ARG *lpNextFile=NULL;
                do
                {
                    if (lpArg->dwType != INET_ARG_FILE)
                        break;

                    lpNextFile=(INET_ARG*)MemAlloc(sizeof(INET_ARG));
                    if (!lpNextFile)
                        break;

                    lpNextFile->dwType=INET_ARG_FILE;

                    lpNextFile->lpFullFileName=StrDuplicateA(lpFileName,0);
                    if (!lpNextFile->lpFullFileName)
                        break;

                    lpNextFile->dwFileNameSize=lstrlenA(lpFileName);

                    if (lpPseudoFileData)
                    {
                        lpNextFile->pseudo_file.lpValueRaw=MemQuickAlloc(dwPseudoFileDataSize);
                        if (!lpNextFile->pseudo_file.lpValueRaw)
                            break;

                        memcpy(lpNextFile->pseudo_file.lpValueRaw,lpPseudoFileData,dwPseudoFileDataSize);
                        lpNextFile->pseudo_file.dwValueRawSize=dwPseudoFileDataSize;
                    }

                    if (lpArg->lpNextFile)
                    {
                        INET_ARG *lpCurFile=lpArg->lpNextFile;
                        while (lpCurFile->lpNextFile)
                            lpCurFile=lpCurFile->lpNextFile;

                        lpCurFile->lpNextFile=lpNextFile;
                    }
                    else
                        lpArg->lpNextFile=lpNextFile;

                    bRet=true;
                }
                while (false);

                if (!bRet)
                    FreeListItem(lpNextFile);
            }
            else
            {
                lpArg=(INET_ARG*)MemAlloc(sizeof(INET_ARG));
                do
                {
                    if (!lpArg)
                        break;

                    lpArg->dwType=INET_ARG_FILE;
                    lpArg->lpName=StrDuplicateA(lpName,0);

                    lpArg->lpFullFileName=StrDuplicateA(lpFileName,0);
                    if (!lpArg->lpFullFileName)
                        break;

                    lpArg->dwFileNameSize=lstrlenA(lpFileName);

                    if (lpPseudoFileData)
                    {
                        lpArg->pseudo_file.lpValueRaw=MemQuickAlloc(dwPseudoFileDataSize);
                        if (!lpArg->pseudo_file.lpValueRaw)
                            break;

                        memcpy(lpArg->pseudo_file.lpValueRaw,lpPseudoFileData,dwPseudoFileDataSize);
                        lpArg->pseudo_file.dwValueRawSize=dwPseudoFileDataSize;
                    }

                    InetAppendArgument(lpList,lpArg);
                    bRet=true;
                }
                while (false);

                if (!bRet)
                    FreeListItem(lpArg);
            }
        }
        LeaveSafeCriticalSection(&lpList->csArguments);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) InetArgsList_AddFileArgumentA(HANDLE hList,LPCSTR lpName,LPCSTR lpFileName)
{
    if (!lpFileName)
        return false;

    return AddFileInt(hList,lpName,lpFileName,NULL,0);
}

SYSLIBFUNC(BOOL) InetArgsList_AddFileArgumentW(HANDLE hList,LPCWSTR lpName,LPCWSTR lpFileName)
{
    LPSTR lpNameA=StrUnicodeToAnsiEx(lpName,0,NULL),
          lpFileNameA=StrUnicodeToAnsiEx(lpFileName,0,NULL);

    BOOL bRet=InetArgsList_AddFileArgumentA(hList,lpNameA,lpFileNameA);

    MemFree(lpNameA);
    MemFree(lpFileNameA);
    return bRet;
}

SYSLIBFUNC(BOOL) InetArgsList_AddBinaryArgumentAsFileA(HANDLE hList,LPCSTR lpName,LPVOID lpValue,DWORD dwValueSize,LPCSTR lpFileName)
{
    if ((!lpValue) || (!dwValueSize) || (!lpFileName))
        return false;

    return AddFileInt(hList,lpName,lpFileName,lpValue,dwValueSize);
}

SYSLIBFUNC(BOOL) InetArgsList_AddBinaryArgumentAsFileW(HANDLE hList,LPCWSTR lpName,LPVOID lpValue,DWORD dwValueSize,LPCWSTR lpFileName)
{
    LPSTR lpNameA=StrUnicodeToAnsiEx(lpName,0,NULL),
          lpFileNameA=StrUnicodeToAnsiEx(lpFileName,0,NULL);

    BOOL bRet=InetArgsList_AddBinaryArgumentAsFileA(hList,lpNameA,lpValue,dwValueSize,lpFileNameA);

    MemFree(lpNameA);
    MemFree(lpFileNameA);
    return bRet;
}

SYSLIBFUNC(BOOL) InetArgsList_AddStringArgumentW(HANDLE hList,LPCWSTR lpName,LPCWSTR lpValue)
{
    LPSTR lpNameA=StrUnicodeToAnsiEx(lpName,0,NULL),
          lpValueA=StrUnicodeToAnsiEx(lpValue,0,NULL);

    BOOL bRet=InetArgsList_AddStringArgumentA(hList,lpNameA,lpValueA);

    MemFree(lpNameA);
    MemFree(lpValueA);
    return bRet;
}

SYSLIBFUNC(BOOL) InetArgsList_AddStringArgumentA(HANDLE hList,LPCSTR lpName,LPCSTR lpValue)
{
    if (!lpValue)
        return false;

    BOOL bRet=false;
    INET_ARGS_LIST *lpList=(INET_ARGS_LIST*)hList;
    if ((lpList) && (lpList->dwType == HTTP_ARGUMENTS_LIST))
    {
        EnterSafeCriticalSection(&lpList->csArguments);
        {
            DWORD dwStrSize=lstrlenA(lpValue);

            INET_ARG *lpArg=FindArgByName(lpList,lpName);
            if (lpArg)
            {
                do
                {
                    if (lpArg->dwType != INET_ARG_STRING)
                        break;

                    if (lpArg->dwValueStrSize <= dwStrSize+1)
                    {
                        lstrcpyA(lpArg->lpValueStr,lpValue);
                        lpArg->dwValueStrSize=dwStrSize;
                    }
                    else
                    {
                        LPSTR lpNewVal=StrDuplicateA(lpValue,0);
                        if (!lpNewVal)
                            break;

                        MemFree(lpArg->lpValueStr);
                        lpArg->lpValueStr=lpNewVal;
                        lpArg->dwValueStrSize=dwStrSize;
                    }
                    bRet=true;
                }
                while (false);
            }
            else
            {
                lpArg=(INET_ARG*)MemAlloc(sizeof(INET_ARG));
                do
                {
                    if (!lpArg)
                        break;

                    lpArg->dwType=INET_ARG_STRING;
                    lpArg->lpName=StrDuplicateA(lpName,0);
                    lpArg->lpValueStr=StrDuplicateA(lpValue,0);
                    if (!lpArg->lpValueStr)
                        break;

                    lpArg->dwValueStrSize=dwStrSize;

                    InetAppendArgument(lpList,lpArg);
                    bRet=true;
                }
                while (false);

                if (!bRet)
                    FreeListItem(lpArg);
            }
        }
        LeaveSafeCriticalSection(&lpList->csArguments);
    }
    return bRet;
}

SYSLIBFUNC(BOOL) InetArgsList_AddIntArgumentW(HANDLE hList,LPCWSTR lpName,int dwValue)
{
    LPSTR lpNameA=StrUnicodeToAnsiEx(lpName,0,NULL);

    BOOL bRet=InetArgsList_AddIntArgumentA(hList,lpNameA,dwValue);

    MemFree(lpNameA);
    return bRet;
}

SYSLIBFUNC(BOOL) InetArgsList_AddIntArgumentA(HANDLE hList,LPCSTR lpName,int dwValue)
{
    BOOL bRet=false;
    INET_ARGS_LIST *lpList=(INET_ARGS_LIST*)hList;
    if ((lpList) && (lpList->dwType == HTTP_ARGUMENTS_LIST))
    {
        EnterSafeCriticalSection(&lpList->csArguments);
        {
            INET_ARG *lpArg=FindArgByName(lpList,lpName);
            if (lpArg)
            {
                do
                {
                    if (lpArg->dwType != INET_ARG_INT)
                        break;

                    lpArg->dwValueInt=dwValue;
                    bRet=true;
                }
                while (false);
            }
            else
            {
                lpArg=(INET_ARG*)MemAlloc(sizeof(INET_ARG));
                do
                {
                    if (!lpArg)
                        break;

                    lpArg->dwType=INET_ARG_INT;
                    lpArg->lpName=StrDuplicateA(lpName,0);
                    lpArg->dwValueInt=dwValue;

                    InetAppendArgument(lpList,lpArg);
                    bRet=true;
                }
                while (false);

                if (!bRet)
                    FreeListItem(lpArg);
            }
        }
        LeaveSafeCriticalSection(&lpList->csArguments);
    }
    return bRet;
}

static HANDLE CreateRequestArgsList(HANDLE hReq)
{
    HANDLE hList=NULL;
    HTTP_REQUEST_HANDLE *lpReq=(HTTP_REQUEST_HANDLE*)hReq;
    if ((lpReq) && (lpReq->dwType == HTTP_REQUEST))
    {
        EnterSafeCriticalSection(&lpReq->csRequest);
        {
            if (!lpReq->hArgsList)
                lpReq->hArgsList=InetArgsList_Create();

            hList=lpReq->hArgsList;
        }
        LeaveSafeCriticalSection(&lpReq->csRequest);
    }
    return hList;
}

SYSLIBFUNC(BOOL) InetAddRequestStringArgumentW(HANDLE hReq,LPCWSTR lpName,LPCWSTR lpValue)
{
    BOOL bRet=false;
    HANDLE hList=CreateRequestArgsList(hReq);
    if (hList)
        bRet=InetArgsList_AddStringArgumentW(hList,lpName,lpValue);
    return bRet;
}

SYSLIBFUNC(BOOL) InetAddRequestStringArgumentA(HANDLE hReq,LPCSTR lpName,LPCSTR lpValue)
{
    BOOL bRet=false;
    HANDLE hList=CreateRequestArgsList(hReq);
    if (hList)
        bRet=InetArgsList_AddStringArgumentA(hList,lpName,lpValue);
    return bRet;
}

SYSLIBFUNC(BOOL) InetAddRequestBinaryArgumentW(HANDLE hReq,LPCWSTR lpName,LPVOID lpValue,DWORD dwValueSize)
{
    BOOL bRet=false;
    HANDLE hList=CreateRequestArgsList(hReq);
    if (hList)
        bRet=InetArgsList_AddBinaryArgumentW(hList,lpName,lpValue,dwValueSize);
    return bRet;
}

SYSLIBFUNC(BOOL) InetAddRequestBinaryArgumentA(HANDLE hReq,LPCSTR lpName,LPVOID lpValue,DWORD dwValueSize)
{
    BOOL bRet=false;
    HANDLE hList=CreateRequestArgsList(hReq);
    if (hList)
        bRet=InetArgsList_AddBinaryArgumentA(hList,lpName,lpValue,dwValueSize);
    return bRet;
}

SYSLIBFUNC(BOOL) InetAddRequestFileArgumentW(HANDLE hReq,LPCWSTR lpName,LPCWSTR lpFileName)
{
    BOOL bRet=false;
    HANDLE hList=CreateRequestArgsList(hReq);
    if (hList)
        bRet=InetArgsList_AddFileArgumentW(hList,lpName,lpFileName);
    return bRet;
}

SYSLIBFUNC(BOOL) InetAddRequestFileArgumentA(HANDLE hReq,LPCSTR lpName,LPCSTR lpFileName)
{
    BOOL bRet=false;
    HANDLE hList=CreateRequestArgsList(hReq);
    if (hList)
        bRet=InetArgsList_AddFileArgumentA(hList,lpName,lpFileName);
    return bRet;
}

SYSLIBFUNC(BOOL) InetAddRequestBinaryArgumentAsFileW(HANDLE hReq,LPCWSTR lpName,LPVOID lpValue,DWORD dwValueSize,LPCWSTR lpFileName)
{
    BOOL bRet=false;
    HANDLE hList=CreateRequestArgsList(hReq);
    if (hList)
        bRet=InetArgsList_AddBinaryArgumentAsFileW(hList,lpName,lpValue,dwValueSize,lpFileName);
    return bRet;
}

SYSLIBFUNC(BOOL) InetAddRequestBinaryArgumentAsFileA(HANDLE hReq,LPCSTR lpName,LPVOID lpValue,DWORD dwValueSize,LPCSTR lpFileName)
{
    BOOL bRet=false;
    HANDLE hList=CreateRequestArgsList(hReq);
    if (hList)
        bRet=InetArgsList_AddBinaryArgumentAsFileA(hList,lpName,lpValue,dwValueSize,lpFileName);
    return bRet;
}

SYSLIBFUNC(BOOL) InetAddRequestIntArgumentW(HANDLE hReq,LPCWSTR lpName,int dwValue)
{
    BOOL bRet=false;
    HANDLE hList=CreateRequestArgsList(hReq);
    if (hList)
        bRet=InetArgsList_AddIntArgumentW(hList,lpName,dwValue);
    return bRet;
}

SYSLIBFUNC(BOOL) InetAddRequestIntArgumentA(HANDLE hReq,LPCSTR lpName,int dwValue)
{
    BOOL bRet=false;
    HANDLE hList=CreateRequestArgsList(hReq);
    if (hList)
        bRet=InetArgsList_AddIntArgumentA(hList,lpName,dwValue);
    return bRet;
}

