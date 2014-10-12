#ifndef SYSLIB_SYSTRAY_H_INCLUDED
#define SYSLIB_SYSTRAY_H_INCLUDED

#include <commctrl.h>
#include "syslib_exp.h"

typedef struct
{
#ifdef _X86_
    HWND hWnd;
#else
    DWORD32 hWnd;
#endif
    UINT uID;
    UINT uCallbackMessage;
    DWORD dwState;
    UINT uVersion;
#ifdef _X86_
    HICON hIcon;
#else
    DWORD32 hIcon;
#endif
} TNPRIVICON_X86, *PTNPRIVICON_X86;

typedef struct
{
    union
    {
        HWND hWnd;
        DWORD64 tmp1;
    };
    UINT uID;
    UINT uCallbackMessage;
    DWORD dwState;
    UINT uVersion;
    union
    {
        HICON hIcon;
        DWORD64 tmp2;
    };
} TNPRIVICON_X64, *PTNPRIVICON_X64;

#ifdef _X86_
#define TNPRIVICON TNPRIVICON_X86
#define PTNPRIVICON PTNPRIVICON_X86
#else
#define PTNPRIVICON PTNPRIVICON_X64
#define TNPRIVICON TNPRIVICON_X64
#endif

typedef BOOL __EnumIconsProc(HWND hTray,DWORD dwItemId,PTNPRIVICON lpIconInfo,LPVOID lpParam);
SYSLIBEXP(void) TrayEnumIcons(__EnumIconsProc *lpProc,LPVOID lpParam);

#endif // SYSLIB_SYSTRAY_H_INCLUDED
