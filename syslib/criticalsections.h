#ifndef SYSLIB_CRITICALSECTIONS_H_INCLUDED
#define SYSLIB_CRITICALSECTIONS_H_INCLUDED

#include "syslib_exp.h"

typedef struct _SAFE_CRITICAL_SECTION
{
    DWORD_PTR dwReserved0;
    DWORD_PTR dwReserved1;
    CRITICAL_SECTION cs;
} SAFE_CRITICAL_SECTION, *LPSAFE_CRITICAL_SECTION;

SYSLIBEXP(BOOL) InitializeSafeCriticalSection(LPSAFE_CRITICAL_SECTION lpSafeCriticalSection);
SYSLIBEXP(void) EnterSafeCriticalSection(LPSAFE_CRITICAL_SECTION lpSafeCriticalSection);
SYSLIBEXP(void) EnterSafeCriticalSectionDeadlockFree(LPSAFE_CRITICAL_SECTION lpSafeCriticalSection);
SYSLIBEXP(BOOL) TryEnterSafeCriticalSection(LPSAFE_CRITICAL_SECTION lpSafeCriticalSection);
SYSLIBEXP(void) LeaveSafeCriticalSection(LPSAFE_CRITICAL_SECTION lpSafeCriticalSection);
SYSLIBEXP(void) DeleteSafeCriticalSection(LPSAFE_CRITICAL_SECTION lpSafeCriticalSection);

#endif // SYSLIB_CRITICALSECTIONS_H_INCLUDED
