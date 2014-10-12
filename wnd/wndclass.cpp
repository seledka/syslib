#include "sys_includes.h"

#include "syslib\mem.h"
#include "syslib\str.h"
#include "syslib\ldr.h"

static LRESULT WINAPI FakeWndProc(HWND hWnd,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
    return DefWindowProc(hWnd,uMsg,wParam,lParam);
}

SYSLIBFUNC(void) GenerateUniqueWndClassNameW(LPWSTR lpWndClassName,DWORD dwWndClassNameSize)
{
    WNDCLASSEXW wc={0};
    wc.cbSize=sizeof(wc);
    wc.lpfnWndProc=FakeWndProc;
    wc.hInstance=hImageBase;
    wc.lpszClassName=lpWndClassName;

    do
    {
        StrGenerateW((LPWSTR)wc.lpszClassName,dwWndClassNameSize,STRGEN_STRONGPASS);
    }
    while (!RegisterClassExW(&wc));

    UnregisterClassW(wc.lpszClassName,wc.hInstance);
    return;
}

SYSLIBFUNC(void) GenerateUniqueWndClassNameA(LPSTR lpWndClassName,DWORD dwWndClassNameSize)
{
    WNDCLASSEXA wc={0};
    wc.cbSize=sizeof(wc);
    wc.lpfnWndProc=FakeWndProc;
    wc.hInstance=hImageBase;
    wc.lpszClassName=lpWndClassName;

    do
    {
        StrGenerateA((LPSTR)wc.lpszClassName,dwWndClassNameSize,STRGEN_STRONGPASS);
    }
    while (!RegisterClassExA(&wc));

    UnregisterClassA(wc.lpszClassName,wc.hInstance);
    return;
}

