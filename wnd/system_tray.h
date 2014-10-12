#ifndef SYSTEM_TRAY_H_INCLUDED
#define SYSTEM_TRAY_H_INCLUDED

#include <shlobj.h>
#include <tchar.h>

struct _TRAY_ENUM_WND
{
    HANDLE hProc;
    void *lpData;
    __EnumIconsProc *lpEnumProc;
    LPVOID lpParam;
    bool b64;
};

typedef struct _TBBUTTON_X86 {
    int iBitmap;
    int idCommand;
    BYTE fsState;
    BYTE fsStyle;
    BYTE bReserved[2];
    DWORD dwData;
    INT iString;
} TBBUTTON_X86, *PTBBUTTON_X86;

typedef struct _TBBUTTON_X64 {
    int iBitmap;
    int idCommand;
    BYTE fsState;
    BYTE fsStyle;
    BYTE bReserved[6];
    DWORD64 dwData;
    INT64 iString;
} TBBUTTON_X64, *PTBBUTTON_X64;

#endif // SYSTEM_TRAY_H_INCLUDED
