#ifndef SYSLIB_SSL_H_INCLUDED
#define SYSLIB_SSL_H_INCLUDED

#include "syslib_exp.h"
typedef HANDLE HSSL;

SYSLIBEXP(HSSL) SSL_Connect(SOCKET hSock,LPCSTR lpHost,BOOL bVerifyCert);

SYSLIBEXP(int) SSL_Recv(HSSL hSSL,char *buf,int len);
SYSLIBEXP(int) SSL_Send(HSSL hSSL,const char *buf,int len);
SYSLIBEXP(BOOL) SSL_IsPending(HSSL hSSL);

SYSLIBEXP(void) SSL_Shutdown(HSSL hSSL);
SYSLIBEXP(void) SSL_Free(HSSL hSSL);

#endif // SYSLIB_SSL_H_INCLUDED
