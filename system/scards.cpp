#include "sys_includes.h"
#include <winscard.h>

SYSLIBFUNC(BOOL) SysIsTokenIn()
{
    BOOL bRet=false;

    SCARDCONTEXT hContext=NULL;
    do
    {
        if (SCardEstablishContext(SCARD_SCOPE_USER,NULL,NULL,&hContext) != SCARD_S_SUCCESS)
			break;

        LPTSTR lpReaders=NULL;
        DWORD dwReaders=SCARD_AUTOALLOCATE;
        if (SCardListReaders(hContext,NULL,(LPTSTR)&lpReaders,&dwReaders) != SCARD_S_SUCCESS)
			break;

        if (!dwReaders)
            break;

        LPTSTR lpList=lpReaders;
		while ((lpList) && (*lpList))
		{
		    SCARDHANDLE hCard;
		    DWORD dwProtocol;
			if (SCardConnect(hContext,lpList,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1,&hCard,&dwProtocol) == SCARD_S_SUCCESS)
			{
				SCardDisconnect(hCard,SCARD_LEAVE_CARD);
				bRet=true;
				break;
			}
			lpList+=lstrlen(lpList)+1;
		}

		SCardFreeMemory(hContext,lpReaders);
    }
    while (false);

	if (hContext)
		SCardReleaseContext(hContext);
    return bRet;
}

