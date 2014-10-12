#ifndef SYSLIB_HOOKS_H_INCLUDED
#define SYSLIB_HOOKS_H_INCLUDED

#include "syslib_exp.h"

typedef void* HPROCHOOK;

SYSLIBEXP(HPROCHOOK) SetProcessWindowsHookEx(int idHook,HOOKPROC lpfn);
SYSLIBEXP(BOOL) UnhookProcessWindowsHookEx(HPROCHOOK hhk);
SYSLIBEXP(void) RemoveProcessWindowsHooks();

#endif // SYSLIB_HOOKS_H_INCLUDED
