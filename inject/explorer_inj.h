#ifndef EXPLORER_INJ_H_INCLUDED
#define EXPLORER_INJ_H_INCLUDED

struct INJ_INTERNAL
{
    union
    {
        ULONG_PTR dwAddr32;
        DWORD64 dwAddr64;
    } uPreAddr;

    DWORD32 dwAddr32_1;
    DWORD32 dwAddr32_2;
    DWORD32 dwAddr32_3;

    DWORD64 dwAddr64_1;
    DWORD64 dwAddr64_2;
    DWORD64 dwAddr64_3;

    union
    {
        HWND hWnd;
        DWORD64 tmp;
    } uHwnd;

    union
    {
        SIZE_T dwParam;
        DWORD64 dwParam64;
    } dwOldParam;

    union
    {
        HANDLE hEvent;
        DWORD64 dwEvent;
    } Event;
};

struct INJ_STRUCT
{
    INJ_INTERNAL iiInternal;

    DWORD dwParamSize;
    byte bParam[0];
};

#endif // EXPLORER_INJ_H_INCLUDED
