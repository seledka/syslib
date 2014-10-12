#ifndef SYSLIB_THREADMESSAGE_H_INCLUDED
#define SYSLIB_THREADMESSAGE_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(LRESULT) SendThreadMessage(DWORD dwThreadId,UINT uMsg,WPARAM wParam,LPARAM lParam);
SYSLIBEXP(BOOL) PeekThreadMessage(PMSG lpMsg);

typedef LRESULT (CALLBACK* THREADPROC)(UINT, WPARAM, LPARAM);

#ifdef __cplusplus
SYSLIBEXP(LRESULT) DispatchThreadMessage(const PMSG lpMsg,THREADPROC lpfnThreadProc=NULL);
#else
SYSLIBEXP(LRESULT) DispatchThreadMessage(const PMSG lpMsg,THREADPROC lpfnThreadProc);
#endif

#define InitThreadMessageQueue() {MSG msg; PeekMessage(&msg,(HWND)INVALID_HANDLE_VALUE,0,0,PM_NOREMOVE);}

#endif // SYSLIB_THREADMESSAGE_H_INCLUDED
