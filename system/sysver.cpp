#include "sys_includes.h"

#include "sysver.h"

#include "syslib\debug.h"
#include "syslib\mem.h"
#include "syslib\system.h"
#include "syslib\str.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

static LPWSTR GetOSLang()
{
    LPWSTR lpLang=NULL;
    DWORD dwTmp,dwSize=GetFileVersionInfoSizeW(dcrW_30884675("kernel32.dll"),&dwTmp);
    if (dwSize)
    {
        void *lpVerInfo=MemQuickAlloc(dwSize);
        if (lpVerInfo)
        {
            GetFileVersionInfoW(dcrW_30884675("kernel32.dll"),NULL,dwSize,lpVerInfo);
            struct LANGANDCODEPAGE {
                WORD wLanguage;
                WORD wCodePage;
            } *lpTrans=NULL;
            UINT dwTransLen=0;
            VerQueryValueW(lpVerInfo,dcrW_6d95e353("\\VarFileInfo\\Translation"),(void**)&lpTrans,&dwTransLen);
            if (dwTransLen >= sizeof(LANGANDCODEPAGE))
            {
                lpLang=WCHAR_QuickAlloc(256);
                if (lpLang)
                    VerLanguageNameW(MAKELONG(lpTrans->wLanguage,lpTrans->wCodePage),lpLang,256);
            }
            MemFree(lpVerInfo);
        }
    }
    return lpLang;
}

SYSLIBFUNC(DWORD) SysGetSystemVersionW(LPWSTR lpOut,DWORD dwSize)
{
    DWORD dwRequested=0;

    if (!SYSLIB_SAFE::CheckParamWrite(lpOut,dwSize*sizeof(WCHAR)))
        lpOut=NULL;
    else
        *lpOut=0;

    OSVERSIONINFOEXW osvi={0};
    osvi.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEXW);

    if (!GetVersionExW((OSVERSIONINFOW*)&osvi))
    {
        osvi.dwOSVersionInfoSize=sizeof(OSVERSIONINFOW);
        if (!GetVersionExW((OSVERSIONINFOW*)&osvi))
            return 0;
    }

#ifdef _X86_
    BOOL bx64=SysIsWow64();
#endif

    if ((VER_PLATFORM_WIN32_NT == osvi.dwPlatformId) && (osvi.dwMajorVersion > 4))
    {
        ConcateStrAndCalcRequestedSize(dcrW_694589ac("Windows "),sizeof("Windows "));

        if (osvi.dwMajorVersion == 6)
        {
            switch (osvi.dwMinorVersion)
            {
                case 0:
                {
                    if (osvi.wProductType == VER_NT_WORKSTATION)
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_b401f12c("Vista "),sizeof("Vista "));
                    }
                    else
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_8296854e("Server 2008 "),sizeof("Server 2008 "));
                    }
                    break;
                }
                case 1:
                {
                    if (osvi.wProductType == VER_NT_WORKSTATION)
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_a80303e9("7 "),sizeof("7 "));
                    }
                    else
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_b0199154("Server 2008 R2 "),sizeof("Server 2008 R2 "));
                    }
                    break;
                }
                case 2:
                {
                    if (osvi.wProductType == VER_NT_WORKSTATION)
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_ad0b5cf2("8 "),sizeof("8 "));
                    }
                    else
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_0ad41262("Server 2012 "),sizeof("Server 2012 "));
                    }
                    break;
                }
                default:
                {
                    if (osvi.wProductType == VER_NT_WORKSTATION)
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_3b8bd120("8.1 "),sizeof("8.1 "));
                    }
                    else
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_5358a00f("Server 2012 R2 "),sizeof("Server 2012 R2 "));
                    }
                    break;
                }
            }

            _GetProductInfo *pGetProductInfo=(_GetProductInfo*)GetProcAddress(GetModuleHandle(dcr_30884675("kernel32.dll")),dcrA_9510426e("GetProductInfo"));
            if (pGetProductInfo)
            {
                DWORD dwType=0;
                pGetProductInfo(6,0,0,0,&dwType);

                switch (dwType)
                {
                    case PRODUCT_ULTIMATE:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_12c67e9d("Ultimate Edition"),sizeof("Ultimate Edition"));
                        break;
                    }
                    case PRODUCT_HOME_PREMIUM:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_faa62f98("Home Premium Edition"),sizeof("Home Premium Edition"));
                        break;
                    }
                    case PRODUCT_HOME_BASIC:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_6c13bcc9("Home Basic Edition"),sizeof("Home Basic Edition"));
                        break;
                    }
                    case PRODUCT_ENTERPRISE:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_a3d4f69b("Enterprise Edition"),sizeof("Enterprise Edition"));
                        break;
                    }
                    case PRODUCT_BUSINESS:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_3dea6c88("Business Edition"),sizeof("Business Edition"));
                        break;
                    }
                    case PRODUCT_STARTER:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_d605658a("Starter Edition"),sizeof("Starter Edition"));
                        break;
                    }
                    case PRODUCT_CLUSTER_SERVER:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_0e1a818b("Cluster Server Edition"),sizeof("Cluster Server Edition"));
                        break;
                    }
                    case PRODUCT_DATACENTER_SERVER:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_5bcb73da("Datacenter Edition"),sizeof("Datacenter Edition"));
                        break;
                    }
                    case PRODUCT_DATACENTER_SERVER_CORE:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_76b486b4("Datacenter Edition (core installation)"),sizeof("Datacenter Edition (core installation)"));
                        break;
                    }
                    case PRODUCT_ENTERPRISE_SERVER:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_a3d4f69b("Enterprise Edition"),sizeof("Enterprise Edition"));
                        break;
                    }
                    case PRODUCT_ENTERPRISE_SERVER_CORE:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_88d0888c("Enterprise Edition (core installation)"),sizeof("Enterprise Edition (core installation)"));
                        break;
                    }
                    case PRODUCT_ENTERPRISE_SERVER_IA64:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_3051b643("Enterprise Edition for Itanium-based Systems"),sizeof("Enterprise Edition for Itanium-based Systems"));
                        break;
                    }
                    case PRODUCT_SMALLBUSINESS_SERVER:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_b1b91898("Small Business Server"),sizeof("Small Business Server"));
                        break;
                    }
                    case PRODUCT_SMALLBUSINESS_SERVER_PREMIUM:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_f171d9d7("Small Business Server Premium Edition"),sizeof("Small Business Server Premium Edition"));
                        break;
                    }
                    case PRODUCT_STANDARD_SERVER:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_5acbde0e("Standard Edition"),sizeof("Standard Edition"));
                        break;
                    }
                    case PRODUCT_STANDARD_SERVER_CORE:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_2ac85575("Standard Edition (core installation)"),sizeof("Standard Edition (core installation)"));
                        break;
                    }
                    case PRODUCT_WEB_SERVER:
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_b8d41036("Web Server Edition"),sizeof("Web Server Edition"));
                        break;
                    }
                }
            }
#ifdef _X86_
            if (bx64)
            {
#endif
                ConcateStrAndCalcRequestedSize(dcrW_2a5cc5ef(", 64-bit"),sizeof(", 64-bit"));
#ifdef _X86_
            }
            else
            {
                ConcateStrAndCalcRequestedSize(dcrW_34448e4e(", 32-bit"),sizeof(", 32-bit"));
            }
#endif
        }
        else if ((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 2))
        {
            if (GetSystemMetrics(SM_SERVERR2))
            {
                ConcateStrAndCalcRequestedSize(dcrW_3518d9a6("Server 2003 R2, "),sizeof("Server 2003 R2, "));
            }
            else if (osvi.wSuiteMask == VER_SUITE_STORAGE_SERVER)
            {
                ConcateStrAndCalcRequestedSize(dcrW_b8f1117d("Storage Server 2003"),sizeof("Storage Server 2003"));
            }
#ifdef _X86_
            else if ((osvi.wProductType == VER_NT_WORKSTATION) && (bx64))
            {
                ConcateStrAndCalcRequestedSize(dcrW_7323c5ea("XP Professional x86 Edition"),sizeof("XP Professional x86 Edition"));
            }
#else
            else if (osvi.wProductType == VER_NT_WORKSTATION)
            {
                ConcateStrAndCalcRequestedSize(dcrW_1f6557e6("XP Professional x64 Edition"),sizeof("XP Professional x64 Edition"));
            }
#endif
            else
            {
                ConcateStrAndCalcRequestedSize(dcrW_af01774d("Server 2003, "),sizeof("Server 2003, "));
            }

            if (osvi.wProductType != VER_NT_WORKSTATION)
            {
#ifdef _X86_
                if (bx64)
                {
#endif
                    if (osvi.wSuiteMask & VER_SUITE_DATACENTER)
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_19b2cf6c("Datacenter x64 Edition"),sizeof("Datacenter x64 Edition"));
                    }
                    else if (osvi.wSuiteMask & VER_SUITE_ENTERPRISE)
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_44673e10("Enterprise x64 Edition"),sizeof("Enterprise x64 Edition"));
                    }
                    else
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_d409d23d("Standard x64 Edition"),sizeof("Standard x64 Edition"));
                    }
#ifdef _X86_
                }
                else
                {
                    if (osvi.wSuiteMask & VER_SUITE_COMPUTE_SERVER)
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_ab01611b("Compute Cluster Edition"),sizeof("Compute Cluster Edition"));
                    }
                    else if (osvi.wSuiteMask & VER_SUITE_DATACENTER)
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_5bcb73da("Datacenter Edition"),sizeof("Datacenter Edition"));
                    }
                    else if (osvi.wSuiteMask & VER_SUITE_ENTERPRISE)
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_a3d4f69b("Enterprise Edition"),sizeof("Enterprise Edition"));
                    }
                    else if (osvi.wSuiteMask & VER_SUITE_BLADE)
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_0f7301f4("Web Edition"),sizeof("Web Edition"));
                    }
                    else
                    {
                        ConcateStrAndCalcRequestedSize(dcrW_5acbde0e("Standard Edition"),sizeof("Standard Edition"));
                    }
                }
#endif
            }
        }
        else if ((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 1))
        {
            ConcateStrAndCalcRequestedSize(dcrW_b63e2a8f("XP "),sizeof("XP "));
            if (osvi.wSuiteMask & VER_SUITE_PERSONAL)
            {
                ConcateStrAndCalcRequestedSize(dcrW_080ff45a("Home Edition"),sizeof("Home Edition"));
            }
            else
            {
                ConcateStrAndCalcRequestedSize(dcrW_387244a2("Professional"),sizeof("Professional"));
            }
        }
        else if ((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 0))
        {
            ConcateStrAndCalcRequestedSize(dcrW_757e3d6c("2000 "),sizeof("2000 "));
            if (osvi.wProductType == VER_NT_WORKSTATION)
            {
                ConcateStrAndCalcRequestedSize(dcrW_387244a2("Professional"),sizeof("Professional"));
            }
            else
            {
                if (osvi.wSuiteMask & VER_SUITE_DATACENTER)
                {
                    ConcateStrAndCalcRequestedSize(dcrW_7165ffb0("Datacenter Server"),sizeof("Datacenter Server"));
                }
                else if (osvi.wSuiteMask & VER_SUITE_ENTERPRISE)
                {
                    ConcateStrAndCalcRequestedSize(dcrW_9b9a9fd2("Advanced Server"),sizeof("Advanced Server"));
                }
                else
                {
                    ConcateStrAndCalcRequestedSize(dcrW_e5c7b602("Server"),sizeof("Server"));
                }
            }
        }
        else if (lstrlenW(osvi.szCSDVersion) > 0)
        {
            WCHAR szCSDVersion[ARRAYSIZE(osvi.szCSDVersion)+2];
            DWORD dwLen=StrFormatW(szCSDVersion,dcrW_24082cfe(" %s"),osvi.szCSDVersion);
            ConcateStrAndCalcRequestedSize(szCSDVersion,dwLen+1);
        }

        WCHAR szBuild[100];
        DWORD dwLen=StrFormatW(szBuild,dcrW_97f5b762(" (build %d)"),osvi.dwBuildNumber);
        ConcateStrAndCalcRequestedSize(szBuild,dwLen+1);
    }
    else
    {
        ConcateStrAndCalcRequestedSize(dcrW_694589ac("Windows "),sizeof("Windows "));

        if (VER_PLATFORM_WIN32_NT == osvi.dwPlatformId)
        {
            ConcateStrAndCalcRequestedSize(dcrW_a9d619e2("NT "),sizeof("NT "));
            if (osvi.wProductType == VER_NT_WORKSTATION)
            {
                ConcateStrAndCalcRequestedSize(dcrW_47a9fd92("Workstation 4.0 "),sizeof("Workstation 4.0 "));
            }
            else if (osvi.wSuiteMask & VER_SUITE_ENTERPRISE)
            {
                ConcateStrAndCalcRequestedSize(dcrW_e8ce8762("Server 4.0, Enterprise Edition "),sizeof("Server 4.0, Enterprise Edition "));
            }
            else
            {
                ConcateStrAndCalcRequestedSize(dcrW_c94e4e15("Server 4.0 "),sizeof("Server 4.0 "));
            }
        }
        else if ((osvi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) && (osvi.dwMajorVersion == 4))
        {
            if (osvi.dwMinorVersion == 0)
            {
                ConcateStrAndCalcRequestedSize(dcrW_712ff76a("95 "),sizeof("95 "));
                if ((osvi.szCSDVersion[1] == L'C') || (osvi.szCSDVersion[1] == L'B'))
                {
                    ConcateStrAndCalcRequestedSize(dcrW_641b8d3e("OSR2 "),sizeof("OSR2 "));
                }
            }
            else if (osvi.dwMinorVersion == 10)
            {
                ConcateStrAndCalcRequestedSize(dcrW_8da0dc8c("98 "),sizeof("98 "));
                if ((osvi.szCSDVersion[1] == L'A') || (osvi.szCSDVersion[1] == L'B'))
                {
                    ConcateStrAndCalcRequestedSize(dcrW_03c359d8("SE "),sizeof("SE "));
                }
            }
            else if (osvi.dwMinorVersion == 90)
            {
                ConcateStrAndCalcRequestedSize(dcrW_86f789df("Millennium Edition"),sizeof("Millennium Edition"));
            }

            WCHAR szBuild[100];
            DWORD dwLen=StrFormatW(szBuild,dcrW_97f5b762(" (build %d)"),osvi.dwBuildNumber);
            ConcateStrAndCalcRequestedSize(szBuild,dwLen+1);
        }
        else if (osvi.dwPlatformId == VER_PLATFORM_WIN32s)
        {
            ConcateStrAndCalcRequestedSize(dcrW_b8f208e1("Win32s"),sizeof("Win32s"));
        }
    }

    if (dwRequested)
    {
        LPWSTR lpLang=GetOSLang();
        if (lpLang)
        {
            WCHAR szOSLang[256];
            DWORD dwLen=StrFormatW(szOSLang,dcrW_cefd71e7("; %s"),lpLang);
            ConcateStrAndCalcRequestedSize(szOSLang,dwLen+1);

            MemFree(lpLang);
        }
        dwRequested++;
    }
    return dwRequested;
}

SYSLIBFUNC(DWORD) SysGetSystemVersionA(LPSTR lpOut,DWORD dwSize)
{
    LPWSTR lpVerW=WCHAR_QuickAlloc(dwSize);
    DWORD dwRequested=SysGetSystemVersionW(lpVerW,dwSize);
    if (lpVerW)
    {
        if (dwRequested <= dwSize)
            StrUnicodeToAnsi(lpVerW,dwRequested,lpOut,dwSize);

            MemFree(lpVerW);
    }
    return dwRequested;
}

SYSLIBFUNC(LPWSTR) SysGetSystemVersionExW()
{
    DWORD dwBufSize=SysGetSystemVersionW(NULL,0);
    LPWSTR lpVersion=WCHAR_QuickAlloc(dwBufSize);
    if (lpVersion)
        SysGetSystemVersionW(lpVersion,dwBufSize);
    return lpVersion;
}

SYSLIBFUNC(LPSTR) SysGetSystemVersionExA()
{
    DWORD dwBufSize=SysGetSystemVersionW(NULL,0);
    LPSTR lpVersion=(LPSTR)MemQuickAlloc(dwBufSize);
    if (lpVersion)
        SysGetSystemVersionA(lpVersion,dwBufSize);
    return lpVersion;
}

SYSLIBFUNC(SYSTEM_TYPE) SysGetSystemType()
{
    OSVERSIONINFOEXW osvi={0};
    osvi.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEXW);

    if (!GetVersionExW((OSVERSIONINFOW*)&osvi))
    {
        osvi.dwOSVersionInfoSize=sizeof(OSVERSIONINFOW);
        if (!GetVersionExW((OSVERSIONINFOW*)&osvi))
            return SYSTEM_TYPE_UNKNOWN;
    }

    SYSTEM_TYPE dwType;
    if ((VER_PLATFORM_WIN32_NT == osvi.dwPlatformId) && (osvi.dwMajorVersion > 4))
    {
        if (osvi.dwMajorVersion == 6)
        {
            switch (osvi.dwMinorVersion)
            {
                case 0:
                {
                    if (osvi.wProductType == VER_NT_WORKSTATION)
                        dwType=SYSTEM_TYPE_VISTA;
                    else
                        dwType=SYSTEM_TYPE_SRV_2008;
                    break;
                }
                case 1:
                {
                    if (osvi.wProductType == VER_NT_WORKSTATION)
                        dwType=SYSTEM_TYPE_7;
                    else
                        dwType=SYSTEM_TYPE_SRV_2008_R2;
                    break;
                }
                case 2:
                {
                    if (osvi.wProductType == VER_NT_WORKSTATION)
                        dwType=SYSTEM_TYPE_8;
                    else
                        dwType=SYSTEM_TYPE_SRV_2012;
                    break;
                }
                default:
                {
                    if (osvi.wProductType == VER_NT_WORKSTATION)
                        dwType=SYSTEM_TYPE_8_1;
                    else
                        dwType=SYSTEM_TYPE_SRV_2012_R2;
                    break;
                }
            }
        }
        else if ((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 2))
        {
            if (GetSystemMetrics(SM_SERVERR2))
                dwType=SYSTEM_TYPE_SRV_2003_R2;
            else if (osvi.wSuiteMask == VER_SUITE_STORAGE_SERVER)
                dwType=SYSTEM_TYPE_SRV_2003;
            else if (osvi.wProductType == VER_NT_WORKSTATION)
                dwType=SYSTEM_TYPE_XP;
            else
                dwType=SYSTEM_TYPE_SRV_2003;
        }
        else if ((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 1))
            dwType=SYSTEM_TYPE_XP;
        else if ((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 0))
        {
            if (osvi.wProductType == VER_NT_WORKSTATION)
                dwType=SYSTEM_TYPE_2000;
            else
                dwType=SYSTEM_TYPE_SRV_2000;
        }
    }
    else
    {
        if (VER_PLATFORM_WIN32_NT == osvi.dwPlatformId)
        {
            if (osvi.wProductType == VER_NT_WORKSTATION)
                dwType=SYSTEM_TYPE_NT;
            else
                dwType=SYSTEM_TYPE_NT_SRV_4;
        }
        else if ((osvi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) && (osvi.dwMajorVersion == 4))
        {
            if (osvi.dwMinorVersion == 0)
            {
                if ((osvi.szCSDVersion[1] == L'C') || (osvi.szCSDVersion[1] == L'B'))
                    dwType=SYSTEM_TYPE_95_OSR2;
                else
                    dwType=SYSTEM_TYPE_95;
            }
            else if (osvi.dwMinorVersion == 10)
            {
                if ((osvi.szCSDVersion[1] == L'A') || (osvi.szCSDVersion[1] == L'B'))
                    dwType=SYSTEM_TYPE_98_SE;
                else
                    dwType=SYSTEM_TYPE_98;
            }
            else if (osvi.dwMinorVersion == 90)
                dwType=SYSTEM_TYPE_ME;
        }
        else if (osvi.dwPlatformId == VER_PLATFORM_WIN32s)
            dwType=SYSTEM_TYPE_WIN32s;
    }
    return dwType;
}

