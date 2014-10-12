#include "sys_includes.h"

#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>

#include "ssl.h"

#include "syslib\str.h"
#include "syslib\mem.h"
#include "syslib\ssl.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

static DWORD dwInit;

static CredHandle hCreds;
static PSecurityFunctionTableA lpSSPI;

static bool IsInit()
{
    return (dwInit == GetCurrentProcessId());
}

static bool CheckHandle(SSL_HANDLE *lpSSL)
{
    bool bRet=false;
    do
    {
        if (!IsInit())
            break;

        if (!SYSLIB_SAFE::CheckParamWrite(lpSSL,sizeof(*lpSSL)))
            break;

        if (!SecIsValidHandle(&lpSSL->hContext))
            break;

        bRet=true;
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) SSL_IsPending(HSSL hSSL)
{
    BOOL bRet=false;
    do
    {
        SSL_HANDLE *lpSSL=(SSL_HANDLE*)hSSL;
        if (!CheckHandle(lpSSL))
            break;

        bRet=((lpSSL->cbRecDataBuf) || (lpSSL->cbIoBuffer));
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(void) SSL_Cleanup()
{
    do
    {
        if (!IsInit())
            break;

        if (!SecIsValidHandle(&hCreds))
            break;

        if (!lpSSPI)
            break;

        lpSSPI->FreeCredentialsHandle(&hCreds);
    }
    while (false);

    return;
}

static bool InitSSL()
{
    if (!IsInit())
    {
        SecInvalidateHandle(&hCreds);
        lpSSPI=InitSecurityInterfaceA();

        SCHANNEL_CRED scCred={0};
        scCred.dwVersion=SCHANNEL_CRED_VERSION;
        scCred.grbitEnabledProtocols=SP_PROT_SSL3TLS1_CLIENTS;
        scCred.dwFlags|=SCH_CRED_NO_DEFAULT_CREDS|SCH_CRED_MANUAL_CRED_VALIDATION;

        TimeStamp tsExpiry;
        if (lpSSPI->AcquireCredentialsHandleA(NULL,UNISP_NAME_A,SECPKG_CRED_OUTBOUND,NULL,&scCred,NULL,NULL,&hCreds,&tsExpiry) == SEC_E_OK)
            dwInit=GetCurrentProcessId();
        else
            SSL_Cleanup();
    }
    return IsInit();
}

static bool VerifyCertificate(SSL_HANDLE *lpSSL,PCSTR lpHost)
{
	LPSTR rgszUsages[]=
	{
		szOID_PKIX_KP_SERVER_AUTH,
		szOID_SERVER_GATED_CRYPTO,
		szOID_SGC_NETSCAPE
	};

    SECURITY_STATUS scRet;

	LPWSTR lpHostW=StrAnsiToUnicodeEx(lpHost,0,NULL);
    PCCERT_CHAIN_CONTEXT lpChainContext=NULL;
	PCCERT_CONTEXT lpServerCert=NULL;
	do
    {
        scRet=lpSSPI->QueryContextAttributesA(&lpSSL->hContext,SECPKG_ATTR_REMOTE_CERT_CONTEXT,&lpServerCert);
        if (scRet != SEC_E_OK)
            break;

        if (!lpServerCert)
        {
            scRet=SEC_E_WRONG_PRINCIPAL;
            break;
        }

        CERT_CHAIN_PARA ChainPara={0};
        ChainPara.cbSize=sizeof(ChainPara);
        ChainPara.RequestedUsage.dwType=USAGE_MATCH_TYPE_OR;
        ChainPara.RequestedUsage.Usage.cUsageIdentifier=sizeof(rgszUsages);
        ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier=rgszUsages;

        if (!CertGetCertificateChain(NULL,lpServerCert,NULL,lpServerCert->hCertStore,&ChainPara,0,NULL,&lpChainContext))
        {
            scRet=GetLastError();
            break;
        }

        HTTPSPolicyCallbackData polHttps={0};
        polHttps.cbStruct=sizeof(HTTPSPolicyCallbackData);
        polHttps.dwAuthType=AUTHTYPE_SERVER;
        polHttps.fdwChecks=CERT_CHAIN_POLICY_IGNORE_PEER_TRUST_FLAG;
        polHttps.pwszServerName=lpHostW;

        CERT_CHAIN_POLICY_PARA PolicyPara={0};
        PolicyPara.cbSize=sizeof(PolicyPara);
        PolicyPara.pvExtraPolicyPara=&polHttps;

        CERT_CHAIN_POLICY_STATUS PolicyStatus={0};
        PolicyStatus.cbSize=sizeof(PolicyStatus);

        if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,lpChainContext,&PolicyPara,&PolicyStatus))
        {
            scRet=GetLastError();
            break;
        }

        if (PolicyStatus.dwError)
        {
            scRet=PolicyStatus.dwError;
            break;
        }

        scRet=SEC_E_OK;
    }
    while (false);

    if (lpChainContext)
        CertFreeCertificateChain(lpChainContext);
    if (lpServerCert)
        CertFreeCertificateContext(lpServerCert);

    MemFree(lpHostW);
    return (scRet == SEC_E_OK);
}

static bool ClientHandshakeLoop(SSL_HANDLE *lpSSL,bool bInitialRead)
{
	DWORD dwSSPIFlags=ISC_REQ_SEQUENCE_DETECT|ISC_REQ_REPLAY_DETECT|ISC_REQ_CONFIDENTIALITY|ISC_REQ_EXTENDED_ERROR|ISC_REQ_ALLOCATE_MEMORY|ISC_REQ_STREAM;
	bool bRead=bInitialRead;
	lpSSL->cbIoBuffer=0;

    SECURITY_STATUS scRet=SEC_I_CONTINUE_NEEDED;
	while ((scRet == SEC_I_CONTINUE_NEEDED) || (scRet == SEC_E_INCOMPLETE_MESSAGE) || (scRet == SEC_I_INCOMPLETE_CREDENTIALS))
	{
		if ((lpSSL->cbIoBuffer) || (scRet == SEC_E_INCOMPLETE_MESSAGE))
		{
		    if (bRead)
            {
				if (lpSSL->sbIoBuffer <= lpSSL->cbIoBuffer)
				{
					lpSSL->sbIoBuffer+=4096;
					lpSSL->lpIoBuffer=(PUCHAR)MemRealloc(lpSSL->lpIoBuffer,lpSSL->sbIoBuffer);
				}

                const TIMEVAL tv={6,0};
                fd_set fd;

				FD_ZERO(&fd);
				FD_SET(lpSSL->hSock,&fd);
				if (select(1,&fd,NULL,NULL,&tv) != 1)
				{
					scRet=ERROR_NOT_READY;
					break;
				}

				DWORD cbData=recv(lpSSL->hSock,(char*)lpSSL->lpIoBuffer+lpSSL->cbIoBuffer,lpSSL->sbIoBuffer-lpSSL->cbIoBuffer,0);
				if ((cbData == SOCKET_ERROR) || (!cbData))
				{
					scRet=ERROR_NOT_READY;
					break;
				}

				lpSSL->cbIoBuffer+=cbData;
            }
            else
                bRead=true;
		}

        SecBuffer InBuffers[2];
		InBuffers[0].pvBuffer=lpSSL->lpIoBuffer;
		InBuffers[0].cbBuffer=lpSSL->cbIoBuffer;
		InBuffers[0].BufferType=SECBUFFER_TOKEN;

		InBuffers[1].pvBuffer=NULL;
		InBuffers[1].cbBuffer=0;
		InBuffers[1].BufferType=SECBUFFER_EMPTY;

        SecBufferDesc InBuffer;
		InBuffer.cBuffers=ARRAYSIZE(InBuffers);
		InBuffer.pBuffers=InBuffers;
		InBuffer.ulVersion=SECBUFFER_VERSION;

        SecBuffer OutBuffers[1];
		OutBuffers[0].pvBuffer=NULL;
		OutBuffers[0].BufferType=SECBUFFER_TOKEN;
		OutBuffers[0].cbBuffer=0;

        SecBufferDesc OutBuffer;
		OutBuffer.cBuffers=ARRAYSIZE(OutBuffers);
		OutBuffer.pBuffers=OutBuffers;
		OutBuffer.ulVersion=SECBUFFER_VERSION;

        DWORD dwSSPIOutFlags;
        TimeStamp tsExpiry;
		scRet=lpSSPI->InitializeSecurityContextA(&hCreds,&lpSSL->hContext,NULL,dwSSPIFlags,0,SECURITY_NATIVE_DREP,&InBuffer,0,NULL,&OutBuffer,&dwSSPIOutFlags,&tsExpiry);

		if ((scRet == SEC_E_OK) || (scRet == SEC_I_CONTINUE_NEEDED) || ((FAILED(scRet)) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR)))
		{
			if ((OutBuffers[0].cbBuffer) && (OutBuffers[0].pvBuffer))
			{
				DWORD cbData=send(lpSSL->hSock,(char*)OutBuffers[0].pvBuffer,OutBuffers[0].cbBuffer,0);
				if ((cbData == SOCKET_ERROR) || (!cbData))
				{
					lpSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
					scRet=SEC_E_INTERNAL_ERROR;
					break;
				}

				lpSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
				OutBuffers[0].pvBuffer=NULL;
			}
		}

		if (scRet == SEC_E_INCOMPLETE_MESSAGE)
            continue;

		if (scRet == SEC_E_OK)
		{
		    if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
			{
				memmove(lpSSL->lpIoBuffer,lpSSL->lpIoBuffer+(lpSSL->cbIoBuffer-InBuffers[1].cbBuffer),InBuffers[1].cbBuffer);
				lpSSL->cbIoBuffer=InBuffers[1].cbBuffer;
			}
			else
				lpSSL->cbIoBuffer=0;
			break;
		}

		if (FAILED(scRet))
            break;

		if (scRet == SEC_I_INCOMPLETE_CREDENTIALS)
		{
			bRead=false;
			scRet=SEC_I_CONTINUE_NEEDED;
			continue;
		}

		if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
		{
			memmove(lpSSL->lpIoBuffer,lpSSL->lpIoBuffer+(lpSSL->cbIoBuffer-InBuffers[1].cbBuffer),InBuffers[1].cbBuffer);
			lpSSL->cbIoBuffer=InBuffers[1].cbBuffer;
		}
		else
            lpSSL->cbIoBuffer=0;
	}

	if (!lpSSL->cbIoBuffer)
	{
	    MemFree(lpSSL->lpIoBuffer);
		lpSSL->lpIoBuffer=NULL;
		lpSSL->sbIoBuffer=0;
	}
	return (scRet == SEC_E_OK);
}

static bool ClientConnect(SSL_HANDLE *lpSSL,LPCSTR lpHost)
{
    bool bRet=false;
    do
    {
        if (!IsInit())
            break;

        if (!lpSSL)
            break;

        ///SslEmptyCache(NULL,0);
        DWORD dwSSPIFlags=ISC_REQ_SEQUENCE_DETECT|ISC_REQ_REPLAY_DETECT|ISC_REQ_CONFIDENTIALITY|ISC_REQ_EXTENDED_ERROR|ISC_REQ_ALLOCATE_MEMORY |ISC_REQ_STREAM;

        SecBuffer OutBuffers[1];
        OutBuffers[0].pvBuffer=NULL;
        OutBuffers[0].BufferType=SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer=0;

        SecBufferDesc OutBuffer;
        OutBuffer.cBuffers=ARRAYSIZE(OutBuffers);
        OutBuffer.pBuffers=OutBuffers;
        OutBuffer.ulVersion=SECBUFFER_VERSION;

        DWORD dwSSPIOutFlags;
        TimeStamp tsExpiry;

        if (lpSSPI->InitializeSecurityContextA(&hCreds,NULL,(SEC_CHAR*)lpHost,dwSSPIFlags,0,SECURITY_NATIVE_DREP,NULL,0,&lpSSL->hContext,&OutBuffer,&dwSSPIOutFlags,&tsExpiry) != SEC_I_CONTINUE_NEEDED)
            break;

        if ((OutBuffers[0].cbBuffer) && (OutBuffers[0].pvBuffer))
        {
            DWORD cbData=send(lpSSL->hSock,(char*)OutBuffers[0].pvBuffer,OutBuffers[0].cbBuffer,0);
            if ((cbData == SOCKET_ERROR) || (!cbData))
            {
                lpSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
                break;
            }

            lpSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
            OutBuffers[0].pvBuffer=NULL;
        }

        if (!ClientHandshakeLoop(lpSSL,true))
            break;

        bRet=true;
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(HSSL) SSL_Connect(SOCKET hSock,LPCSTR lpHost,BOOL bVerifyCert)
{
    SSL_HANDLE *lpSSL=NULL;
    do
    {
        if (!InitSSL())
            break;

        lpSSL=(SSL_HANDLE*)MemAlloc(sizeof(SSL_HANDLE));
        if (!lpSSL)
            break;

        lpSSL->hSock=hSock;
        SecInvalidateHandle(&lpSSL->hContext);

        if (!ClientConnect(lpSSL,lpHost))
        {
            SSL_Free((HSSL)lpSSL);
            lpSSL=NULL;
            break;
        }

        if (bVerifyCert)
        {
            if (!VerifyCertificate(lpSSL,lpHost))
            {
                SSL_Free((HSSL)lpSSL);
                lpSSL=NULL;
                break;
            }
        }
    }
    while (false);
    return (HSSL)lpSSL;
}

static int SetResult(SSL_HANDLE *lpSSL,char *buf,int len)
{
	if (!lpSSL->cbRecDataBuf)
		return ((lpSSL->State == SOCK_CLOSED) ? 0:SOCKET_ERROR);

	int dwBytes=min(len,lpSSL->cbRecDataBuf),
        dwRBytes=lpSSL->cbRecDataBuf-dwBytes;

	memcpy(buf,lpSSL->lpRecDataBuf,dwBytes);
    memmove(lpSSL->lpRecDataBuf,lpSSL->lpRecDataBuf+dwBytes,dwRBytes);
    lpSSL->cbRecDataBuf=dwRBytes;
	return dwBytes;
}

SYSLIBFUNC(int) SSL_Recv(HSSL hSSL,char *buf,int len)
{
    int dwRet=SOCKET_ERROR;

    do
    {
        SSL_HANDLE *lpSSL=(SSL_HANDLE*)hSSL;
        if (!CheckHandle(lpSSL))
            break;

        if (len <= 0)
        {
            dwRet=len;
            break;
        }

        if ((lpSSL->State != SOCK_OPENED) || (lpSSL->cbRecDataBuf >= len))
        {
            dwRet=SetResult(lpSSL,buf,len);
            break;
        }

        SECURITY_STATUS scRet=SEC_E_OK;
        while (true)
        {
            if ((!lpSSL->cbIoBuffer) || (scRet == SEC_E_INCOMPLETE_MESSAGE))
            {
                if (lpSSL->sbIoBuffer <= lpSSL->cbIoBuffer)
                {
                    lpSSL->sbIoBuffer+=2048;
                    lpSSL->lpIoBuffer=(PUCHAR)MemRealloc(lpSSL->lpIoBuffer,lpSSL->sbIoBuffer);
                }

                const TIMEVAL tv={0};
                fd_set fd;
                FD_ZERO(&fd);
                FD_SET(lpSSL->hSock,&fd);

                DWORD cbData=select(1,&fd,NULL,NULL,&tv);
                if (cbData == SOCKET_ERROR)
                {
                    lpSSL->State=SOCK_ERROR;
                    dwRet=SetResult(lpSSL,buf,len);
                    break;
                }

                if ((!cbData) && (lpSSL->cbRecDataBuf))
                {
                    dwRet=SetResult(lpSSL,buf,len);
                    break;
                }

                cbData=recv(lpSSL->hSock,(char*)lpSSL->lpIoBuffer+lpSSL->cbIoBuffer,lpSSL->sbIoBuffer-lpSSL->cbIoBuffer,0);
                if (cbData == SOCKET_ERROR)
                {
                    lpSSL->State=SOCK_ERROR;
                    dwRet=SetResult(lpSSL,buf,len);
                    break;
                }

                if (!cbData)
                {
                    if (lpSSL->cbRecDataBuf)
                    {
                        lpSSL->State=SOCK_CLOSED;
                        dwRet=SetResult(lpSSL,buf,len);
                        break;
                    }

                    if (lpSSL->cbIoBuffer)
                    {
                        lpSSL->State=SOCK_ERROR;
                        dwRet=SetResult(lpSSL,buf,len);
                        break;
                    }

                    dwRet=0;
                    break;
                }

                lpSSL->cbIoBuffer+=cbData;
            }

            SecBuffer Buffers[4];
            Buffers[0].pvBuffer=lpSSL->lpIoBuffer;
            Buffers[0].cbBuffer=lpSSL->cbIoBuffer;
            Buffers[0].BufferType=SECBUFFER_DATA;

            Buffers[1].BufferType=SECBUFFER_EMPTY;
            Buffers[2].BufferType=SECBUFFER_EMPTY;
            Buffers[3].BufferType=SECBUFFER_EMPTY;

            SecBufferDesc Message;
            Message.ulVersion=SECBUFFER_VERSION;
            Message.cBuffers=ARRAYSIZE(Buffers);
            Message.pBuffers=Buffers;

            if ((lpSSPI->DecryptMessage) && (lpSSPI->DecryptMessage != PVOID(0x80000000)))
                scRet=lpSSPI->DecryptMessage(&lpSSL->hContext,&Message,0,NULL);
            else
                scRet=((DECRYPT_MESSAGE_FN)lpSSPI->Reserved4)(&lpSSL->hContext,&Message,0,NULL);

            if (scRet == SEC_E_INCOMPLETE_MESSAGE)
                continue;

            if ((scRet != SEC_E_OK) && (scRet != SEC_I_RENEGOTIATE) && (scRet != SEC_I_CONTEXT_EXPIRED))
            {
                lpSSL->State=SOCK_ERROR;
                dwRet=SetResult(lpSSL,buf,len);
                break;
            }

            SecBuffer *lpDataBuffer=NULL,
                      *lpExtraBuffer=NULL;
            for (int i=1; i < ARRAYSIZE(Buffers); i++)
            {
                if ((lpDataBuffer == NULL) && (Buffers[i].BufferType == SECBUFFER_DATA))
                    lpDataBuffer=&Buffers[i];

                if ((lpExtraBuffer == NULL) && (Buffers[i].BufferType == SECBUFFER_EXTRA))
                    lpExtraBuffer=&Buffers[i];
            }

            int dwResNum=0;
            if (lpDataBuffer)
            {
                DWORD dwBytes=min((DWORD)len,lpDataBuffer->cbBuffer),
                      dwRBytes=lpDataBuffer->cbBuffer-dwBytes;

                if (dwRBytes > 0)
                {
                    int nbytes=lpSSL->cbRecDataBuf+dwRBytes;
                    if (lpSSL->sbRecDataBuf < nbytes)
                    {
                        lpSSL->sbRecDataBuf=nbytes;
                        lpSSL->lpRecDataBuf=(PUCHAR)MemRealloc(lpSSL->lpRecDataBuf,nbytes);
                    }

                    memcpy(lpSSL->lpRecDataBuf+lpSSL->cbRecDataBuf, (char*)lpDataBuffer->pvBuffer+dwBytes,dwRBytes);
                    lpSSL->cbRecDataBuf=nbytes;
                }

                dwResNum=dwBytes;
                memcpy(buf,lpDataBuffer->pvBuffer,dwBytes);
            }

            if (lpExtraBuffer)
            {
                memmove(lpSSL->lpIoBuffer,lpExtraBuffer->pvBuffer,lpExtraBuffer->cbBuffer);
                lpSSL->cbIoBuffer=lpExtraBuffer->cbBuffer;
            }
            else
                lpSSL->cbIoBuffer=0;

            if ((lpDataBuffer) && (dwResNum))
            {
                dwRet=dwResNum;
                break;
            }

            if (scRet == SEC_I_CONTEXT_EXPIRED)
            {
                lpSSL->State=SOCK_CLOSED;
                dwRet=SetResult(lpSSL,buf,len);
                break;
            }

            if (scRet == SEC_I_RENEGOTIATE)
            {
                if (!ClientHandshakeLoop(lpSSL,false))
                {
                    lpSSL->State=SOCK_ERROR;
                    dwRet=SetResult(lpSSL,buf,len);
                    break;
                }
            }
        }
    }
    while (false);

    return dwRet;
}

SYSLIBFUNC(int) SSL_Send(HSSL hSSL,const char *buf,int len)
{
    int dwRet=SOCKET_ERROR;

    do
    {
        SSL_HANDLE *lpSSL=(SSL_HANDLE*)hSSL;
        if (!CheckHandle(lpSSL))
            break;

        if (len <= 0)
        {
            dwRet=len;
            break;
        }

        SecPkgContext_StreamSizes Sizes;
        if (lpSSPI->QueryContextAttributesA(&lpSSL->hContext,SECPKG_ATTR_STREAM_SIZES,&Sizes) != SEC_E_OK)
            break;

        PUCHAR lpDataBuffer=(PUCHAR)MemQuickAlloc(Sizes.cbMaximumMessage+Sizes.cbHeader+Sizes.cbTrailer);
        if (!lpDataBuffer)
            break;

        PUCHAR lpMessage=lpDataBuffer+Sizes.cbHeader;
        DWORD dwSendOff=0;

        SECURITY_STATUS scRet=SEC_E_INTERNAL_ERROR;
        while (dwSendOff < (DWORD)len)
        {
            DWORD cbMessage=min(Sizes.cbMaximumMessage,(DWORD)len-dwSendOff);
            memcpy(lpMessage,buf+dwSendOff,cbMessage);

            SecBuffer Buffers[4];
            Buffers[0].pvBuffer=lpDataBuffer;
            Buffers[0].cbBuffer=Sizes.cbHeader;
            Buffers[0].BufferType=SECBUFFER_STREAM_HEADER;

            Buffers[1].pvBuffer=lpMessage;
            Buffers[1].cbBuffer=cbMessage;
            Buffers[1].BufferType=SECBUFFER_DATA;

            Buffers[2].pvBuffer=lpMessage+cbMessage;
            Buffers[2].cbBuffer=Sizes.cbTrailer;
            Buffers[2].BufferType=SECBUFFER_STREAM_TRAILER;

            Buffers[3].BufferType=SECBUFFER_EMPTY;

            SecBufferDesc Message;
            Message.ulVersion=SECBUFFER_VERSION;
            Message.cBuffers=ARRAYSIZE(Buffers);
            Message.pBuffers=Buffers;

            if (lpSSPI->EncryptMessage)
                scRet=lpSSPI->EncryptMessage(&lpSSL->hContext,0,&Message,0);
            else
                scRet=((ENCRYPT_MESSAGE_FN)lpSSPI->Reserved3)(&lpSSL->hContext,0,&Message,0);

            if (FAILED(scRet))
                break;

            DWORD cbData=Buffers[0].cbBuffer+Buffers[1].cbBuffer+Buffers[2].cbBuffer;
            cbData=send(lpSSL->hSock,(char*)lpDataBuffer,cbData,0);
            if ((cbData == SOCKET_ERROR) || (!cbData))
            {
                scRet=SEC_E_INTERNAL_ERROR;
                break;
            }

            dwSendOff+=cbMessage;
        }

        MemFree(lpDataBuffer);
        dwRet=(scRet == SEC_E_OK) ? len:SOCKET_ERROR;
    }
    while (false);

    return dwRet;
}

SYSLIBFUNC(void) SSL_Shutdown(HSSL hSSL)
{
    do
    {
        SSL_HANDLE *lpSSL=(SSL_HANDLE*)hSSL;
        if (!CheckHandle(lpSSL))
            break;

        DWORD dwType=SCHANNEL_SHUTDOWN;
        SecBuffer OutBuffers[1];
        OutBuffers[0].pvBuffer=&dwType;
        OutBuffers[0].BufferType=SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer=sizeof(dwType);

        SecBufferDesc OutBuffer;
        OutBuffer.cBuffers=ARRAYSIZE(OutBuffers);
        OutBuffer.pBuffers=OutBuffers;
        OutBuffer.ulVersion=SECBUFFER_VERSION;

        if (FAILED(lpSSPI->ApplyControlToken(&lpSSL->hContext,&OutBuffer)))
            break;

        DWORD dwSSPIFlags=ISC_REQ_SEQUENCE_DETECT|ISC_REQ_REPLAY_DETECT|ISC_REQ_CONFIDENTIALITY|ISC_RET_EXTENDED_ERROR|ISC_REQ_ALLOCATE_MEMORY|ISC_REQ_STREAM;
        OutBuffers[0].pvBuffer=NULL;
        OutBuffers[0].BufferType=SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer=0;

        OutBuffer.cBuffers=ARRAYSIZE(OutBuffers);
        OutBuffer.pBuffers=OutBuffers;
        OutBuffer.ulVersion=SECBUFFER_VERSION;

        DWORD dwSSPIOutFlags;
        TimeStamp tsExpiry;

        if (FAILED(lpSSPI->InitializeSecurityContextA(&hCreds,&lpSSL->hContext,NULL,dwSSPIFlags,0,SECURITY_NATIVE_DREP,NULL,0,&lpSSL->hContext,&OutBuffer,&dwSSPIOutFlags,&tsExpiry)))
            break;

        if ((!OutBuffers[0].pvBuffer) || (!OutBuffers[0].cbBuffer))
            break;

        send(lpSSL->hSock,(char*)OutBuffers[0].pvBuffer,OutBuffers[0].cbBuffer,0);
        lpSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
    }
    while (false);

    return;
}

SYSLIBFUNC(void) SSL_Free(HSSL hSSL)
{
    do
    {
        if (!IsInit())
            break;

        if (!hSSL)
            break;

        SSL_HANDLE *lpSSL=(SSL_HANDLE*)hSSL;
        if (SecIsValidHandle(&lpSSL->hContext))
            lpSSPI->DeleteSecurityContext(&lpSSL->hContext);

        MemFree(lpSSL->lpRecDataBuf);
        MemFree(lpSSL->lpIoBuffer);
        MemFree(lpSSL);
    }
    while (false);

    return;
}

