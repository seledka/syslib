#ifndef SSL_H_INCLUDED
#define SSL_H_INCLUDED

enum SSL_SOCKET_STATE
{
	SOCK_OPENED,
	SOCK_CLOSED,
	SOCK_ERROR
};


struct SSL_HANDLE
{
	SOCKET hSock;

	CtxtHandle hContext;

	LPBYTE lpRecDataBuf;
	int cbRecDataBuf;
	int sbRecDataBuf;

	LPBYTE lpIoBuffer;
	int cbIoBuffer;
	int sbIoBuffer;

	SSL_SOCKET_STATE State;
};


#endif // SSL_H_INCLUDED
