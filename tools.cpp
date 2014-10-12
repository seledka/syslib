#include "sys_includes.h"
#include <shlwapi.h>
#include <intrin.h>

#include "syslib\utils.h"
#include "syslib\files.h"
#include "syslib\system.h"
#include "syslib\mem.h"
#include "syslib\str.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

SYSLIBFUNC(int) CompareObjects(HANDLE hObj1,HANDLE hObj2)
{
    int dwRet=1;
    do
    {
        if ((!hObj1) || (!hObj2))
            break;

        TCHAR szName1[256];
        if (!GetUserObjectInformation(hObj1,UOI_NAME,szName1,sizeof(szName1),NULL))
            break;

        TCHAR szName2[256];
        if (!GetUserObjectInformation(hObj2,UOI_NAME,szName2,sizeof(szName2),NULL))
            break;

        dwRet=lstrcmpi(szName1,szName2);
    }
    while (false);

	return dwRet;
}

SYSLIBFUNC(BOOL) GetThreadDesktopNameW(DWORD dwThreadId,LPWSTR lpDeskName,DWORD dwSize)
{
    BOOL bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckParamWrite(lpDeskName,dwSize*sizeof(WCHAR)))
            break;

        HDESK hDesk=GetThreadDesktop(dwThreadId);
        if (!hDesk)
            break;

        if (!GetUserObjectInformationW(hDesk,UOI_NAME,lpDeskName,dwSize,NULL))
            break;

        bRet=true;
    }
    while (false);

    return bRet;
}

SYSLIBFUNC(BOOL) GetThreadDesktopNameA(DWORD dwThreadId,LPSTR lpDeskName,DWORD dwSize)
{
    BOOL bRet=false;
    do
    {
        if (!lpDeskName)
            break;

        if (!SYSLIB_SAFE::CheckParamWrite(lpDeskName,dwSize))
            break;

        HDESK hDesk=GetThreadDesktop(dwThreadId);
        if (!hDesk)
            break;

        if (!GetUserObjectInformationA(hDesk,UOI_NAME,lpDeskName,dwSize,NULL))
            break;

        bRet=true;
    }
    while (false);

    return bRet;
}

#pragma intrinsic(__rdtsc)

static DWORD x=0x12345678;
SYSLIBFUNC(DWORD) xor128(int val)
{
    static DWORD y=362436069,
                 z=521288629,
                 w=88675123;
    if (x == 0x12345678)
        x=(ULONG)__rdtsc();
    DWORD t;
    t=(x^(x<<11));
    x=y;
    y=z;
    z=w;
    w=(w^(w>>19))^(t^(t>>8));
    return (w%(val*100))/100;
}

SYSLIBFUNC(DWORD) xor128_Between(int iMin,int iMax)
{
    if (iMin == iMax)
        return iMin;

    DWORD dwRet=0;
    while (true)
    {
        dwRet=xor128((iMax-iMin)+1)+iMin;

        if (dwRet <= iMax)
            break;
    }
    return dwRet;
}

SYSLIBFUNC(DWORD) GetRndDWORD()
{
    union
    {
        struct
        {
            byte b1;
            byte b2;
            byte b3;
            byte b4;
        };
        DWORD dw1;
    } RndDword;

    RndDword.b1=(byte)xor128(0xFF);
    RndDword.b2=(byte)xor128(0xFF);
    RndDword.b3=(byte)xor128(0xFF);
    RndDword.b4=(byte)xor128(0xFF);
    return RndDword.dw1;
}

SYSLIBFUNC(BOOL) EnumProcessWindows(DWORD dwProcessId,WNDENUMPROC lpfn,LPARAM lParam)
{
    BOOL bRet=false;
    if ((SysIsProcess(dwProcessId)) && (SYSLIB_SAFE::CheckCodePtr(lpfn)))
    {
        HWND hCurWnd=GetWindow(GetWindow(GetDesktopWindow(),GW_CHILD),GW_HWNDLAST);
        do
        {
            if (IsWindow(hCurWnd))
            {
                DWORD dwCurProcessId;
                GetWindowThreadProcessId(hCurWnd,&dwCurProcessId);
                if (dwCurProcessId == dwProcessId)
                {
                    bRet=(lpfn(hCurWnd,lParam) != FALSE);
                    if (!bRet)
                        break;
                }
            }
        }
        while (hCurWnd=GetWindow(hCurWnd,GW_HWNDPREV));
    }
    return bRet;
}

SYSLIBFUNC(int) CountBits(DWORD64 dwValue)
{
    int dwRes=0;
    if (dwValue)
    {
        int dwSize = sizeof(dwValue) * 4;
        while (dwValue != 1)
        {
            DWORD64 l=dwValue >> dwSize;
            if (l)
            {
                dwValue=l;
                dwRes+=dwSize;
            }
            else
                dwValue^=l << dwSize;
            dwSize>>=1;
        }
        dwRes++;
    }
    return dwRes;
}

SYSLIBFUNC(DWORD64) ReverseBytes(DWORD64 dwValue)
{
    union
    {
        byte bRes[sizeof(DWORD64)];
        DWORD64 dwRes;
    };

    bRes[0]=(dwValue >> 56) & 0xFF;
    bRes[1]=(dwValue >> 48) & 0xFF;
    bRes[2]=(dwValue >> 40) & 0xFF;
    bRes[3]=(dwValue >> 32) & 0xFF;
    bRes[4]=(dwValue >> 24) & 0xFF;
    bRes[5]=(dwValue >> 16) & 0xFF;
    bRes[6]=(dwValue >>  8) & 0xFF;
    bRes[7]= dwValue        & 0xFF;
    return dwRes;
}

