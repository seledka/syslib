#include "sys_includes.h"

#include "strcrypt.h"

#include "syslib\criticalsections.h"
#include "syslib\mem.h"
#include "syslib\rc4.h"
#include "syslib\str.h"
#include "syslib\chksum.h"

static STR_DECRYPT *lpStrings=NULL;
static SAFE_CRITICAL_SECTION csCryptStrings;

static DWORD dwInit;

static void Init()
{
    if (dwInit != GetCurrentProcessId())
    {
        lpStrings=NULL;
        InitializeSafeCriticalSection(&csCryptStrings);
        dwInit=GetCurrentProcessId();
    }
    return;
}

static void *DecryptStrInt(char *lpCrypedString,DWORD dwLen,DWORD dwKey,bool bUnicode)
{
    if (!SYSLIB_SAFE::CheckStrParamA(lpCrypedString,dwLen))
        return NULL;

    void *lpDecryptedStr=NULL;
    Init();

    DWORD dwHash=MurmurHash3((byte*)lpCrypedString,dwLen);
    EnterSafeCriticalSection(&csCryptStrings);
    {
        STR_DECRYPT *lpCurStr=lpStrings;
        while (lpCurStr)
        {
            if (lpCurStr->dwCryptedStrHash == dwHash)
                break;
            lpCurStr=lpCurStr->lpNextStr;
        }

        if (!lpCurStr)
        {
            lpCurStr=(STR_DECRYPT*)MemAlloc(sizeof(STR_DECRYPT));
            if (lpCurStr)
            {
                lpCurStr->dwCryptedStrHash=dwHash;
                if (lpStrings)
                {
                    STR_DECRYPT *lpStr=lpStrings;
                    while (lpStr->lpNextStr)
                        lpStr=lpStr->lpNextStr;
                    lpStr->lpNextStr=lpCurStr;
                }
                else
                    lpStrings=lpCurStr;

                lpCurStr->lpDecryptedStrA=(char*)MemQuickAlloc(dwLen+1);
                if (lpCurStr->lpDecryptedStrA)
                {
                    rc4Full(&dwKey,sizeof(dwKey),lpCrypedString,dwLen,lpCurStr->lpDecryptedStrA);
                    lpCurStr->lpDecryptedStrA[dwLen]=0;
                }
            }
        }

        if (lpCurStr)
        {
            if (bUnicode)
            {
                if (!lpCurStr->lpDecryptedStrW)
                    lpCurStr->lpDecryptedStrW=StrAnsiToUnicodeEx(lpCurStr->lpDecryptedStrA,0,NULL);

                lpDecryptedStr=(void*)lpCurStr->lpDecryptedStrW;
            }
            else
                lpDecryptedStr=(void*)lpCurStr->lpDecryptedStrA;
        }
    }
    LeaveSafeCriticalSection(&csCryptStrings);
    return lpDecryptedStr;
}

SYSLIBFUNC(LPCSTR) DecryptStringA(LPSTR lpCrypedString,DWORD dwLen,DWORD dwKey)
{
    return (LPCSTR)DecryptStrInt(lpCrypedString,dwLen,dwKey,false);
}

SYSLIBFUNC(LPCWSTR) DecryptStringW(LPSTR lpCrypedString,DWORD dwLen,DWORD dwKey)
{
    return (LPCWSTR)DecryptStrInt(lpCrypedString,dwLen,dwKey,true);
}

