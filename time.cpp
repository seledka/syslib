#include "sys_includes.h"

SYSLIBFUNC(DWORD) Now()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    LARGE_INTEGER liTime={ft.dwLowDateTime,ft.dwHighDateTime};
    DWORD dwNow;
    RtlTimeToSecondsSince1980(&liTime,&dwNow);
    return dwNow;
}

