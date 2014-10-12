#include "sys_includes.h"
#include <comdef.h>
#include <wbemidl.h>

#include "syslib\mem.h"
#include "syslib\str.h"
#include "av_grabber.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

static void WMI_Cleanup(WMI *lpWMI)
{
    if (lpWMI->lpLocator)
    {
        if (lpWMI->lpService)
            lpWMI->lpService->Release();

        lpWMI->lpLocator->Release();
    }

    if ((lpWMI->hResInit == S_OK) || (lpWMI->hResInit == S_FALSE))
        CoUninitialize();

    memset(lpWMI,0,sizeof(*lpWMI));
    return;
}

static bool WMI_Init(LPCWSTR lpNamespace,WMI *lpWMI)
{
    bool bRet=false;
    lpWMI->lpLocator=NULL;
    lpWMI->lpService=NULL;
    do
    {
        HRESULT hr=lpWMI->hResInit=CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);
        if ((hr != S_OK) && (hr != S_FALSE) && (hr != RPC_E_CHANGED_MODE))
            break;

        hr=CoCreateInstance(CLSID_WbemLocator,NULL,CLSCTX_INPROC_SERVER|CLSCTX_NO_FAILURE_LOG|CLSCTX_NO_CODE_DOWNLOAD,IID_IWbemLocator,(void**)&lpWMI->lpLocator);
        if ((hr != S_OK) || (!lpWMI->lpLocator))
            break;

        hr=lpWMI->lpLocator->ConnectServer((const BSTR)lpNamespace,NULL,NULL,0,NULL,0,0,&lpWMI->lpService);
        if (FAILED(hr))
            break;

        hr=CoSetProxyBlanket(lpWMI->lpService,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,NULL,RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_NONE);
        if (FAILED(hr))
            break;

        bRet=true;
    }
    while (false);

    if (!bRet)
        WMI_Cleanup(lpWMI);

    return bRet;
}

static LPCWSTR WMI_ReadNames(LPCWSTR lpQuery,WMI *lpWMI)
{
    LPWSTR lpResult=NULL;
    IEnumWbemClassObject *lpEnumerator=NULL;
    HRESULT hr=lpWMI->lpService->ExecQuery((const BSTR) dcrW_a9c16e67("WQL"),(const BSTR)lpQuery,WBEM_FLAG_FORWARD_ONLY|WBEM_FLAG_RETURN_IMMEDIATELY,NULL,&lpEnumerator);
    if (SUCCEEDED(hr))
    {
        DWORD dwSize=0;
        while (lpEnumerator)
        {
            VARIANT vtProp;
            IWbemClassObject *pclsObj;
            ULONG uReturn=0;
            lpEnumerator->Next(WBEM_INFINITE,1,&pclsObj,&uReturn);
            if (!uReturn)
                break;

            pclsObj->Get(dcrW_149893f9("displayName"),0,&vtProp,0,0);

            if (lpResult)
                dwSize=StrCatFormatExW(&lpResult,dwSize,dcrW_d3e1843d("%s "),vtProp.bstrVal);
            else
                dwSize=StrCatExW(&lpResult,vtProp.bstrVal,0);

            VariantClear(&vtProp);
        }
    }
    return lpResult;
}

static LPCWSTR GetNameInt(LPCWSTR lpNamespace,LPCWSTR lpQueryString)
{
    LPCWSTR lpName=NULL;
    WMI wmi;
    if (WMI_Init(lpNamespace,&wmi))
    {
        lpName=WMI_ReadNames(lpQueryString,&wmi);
        WMI_Cleanup(&wmi);
    }
    return lpName;
}

static LPCWSTR ExecuteWMIQuery(LPCWSTR lpQueryString)
{
    LPCWSTR lpName=GetNameInt(dcrW_c537b04f("ROOT\\SecurityCenter"),lpQueryString);
    if (!lpName)
        lpName=GetNameInt(dcrW_c80eda62("ROOT\\SecurityCenter2"),lpQueryString);

    return lpName;
}

SYSLIBFUNC(LPCWSTR) GetInstalledFireWallNameW()
{
    return ExecuteWMIQuery(dcrW_e6b870fb("Select * from FirewallProduct"));
}

SYSLIBFUNC(LPCSTR) GetInstalledFireWallNameA()
{
    LPCSTR lpNameA=NULL;
    LPWSTR lpNameW=(LPWSTR)GetInstalledFireWallNameW();
    if (lpNameW)
    {
        lpNameA=StrUnicodeToAnsiEx(lpNameW,0,NULL);
        MemFree(lpNameW);
    }
    return lpNameA;
}

SYSLIBFUNC(LPCWSTR) GetInstalledAntiSpywareNameW()
{
    return ExecuteWMIQuery(dcrW_fac34cf3("Select * from AntiSpywareProduct"));
}

SYSLIBFUNC(LPCSTR) GetInstalledAntiSpywareNameA()
{
    LPCSTR lpNameA=NULL;
    LPWSTR lpNameW=(LPWSTR)GetInstalledAntiSpywareNameW();
    if (lpNameW)
    {
        lpNameA=StrUnicodeToAnsiEx(lpNameW,0,NULL);
        MemFree(lpNameW);
    }
    return lpNameA;
}

SYSLIBFUNC(LPCWSTR) GetInstalledAntiVirusNameW()
{
    return ExecuteWMIQuery(dcrW_49b72ff8("Select * from AntiVirusProduct"));
}

SYSLIBFUNC(LPCSTR) GetInstalledAntiVirusNameA()
{
    LPCSTR lpNameA=NULL;
    LPWSTR lpNameW=(LPWSTR)GetInstalledAntiVirusNameW();
    if (lpNameW)
    {
        lpNameA=StrUnicodeToAnsiEx(lpNameW,0,NULL);
        MemFree(lpNameW);
    }
    return lpNameA;
}

