#include "sys_includes.h"

#include "md6int\md6.h"

SYSLIBFUNC(BOOL) hash_CalcMD6(const LPBYTE lpData,DWORD dwSize,LPBYTE lpOut)
{
    BOOL bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckParamRead(lpData,dwSize))
            break;

        if (!SYSLIB_SAFE::CheckParamWrite(lpOut,64))
            break;

        bRet=(md6_hash(512,lpData,dwSize*8,lpOut) == MD6_SUCCESS);
    }
    while (false);
    return bRet;
}

