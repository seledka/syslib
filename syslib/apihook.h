#ifndef SYSLIB_APIHOOK_H_INCLUDED
#define SYSLIB_APIHOOK_H_INCLUDED

#include "syslib_exp.h"

#define APIHOOKER_REMOVE_OLD_HOOK 1
SYSLIBEXP(LPVOID) HookAPI_HookEx(LPVOID lpFunc,LPVOID lpHandler,DWORD dwFlags);
SYSLIBEXP(LPVOID) HookAPI_Hook(LPVOID lpFunc,LPVOID lpHandler);

SYSLIBEXP(BOOL) HookAPI_Enable(LPVOID lpFunc,BOOL bEnable);
SYSLIBEXP(BOOL) HookAPI_EnableForCallingThread(LPVOID lpFunc,BOOL bEnable);

SYSLIBEXP(void) HookAPI_UnhookModule(HMODULE hModule);
SYSLIBEXP(BOOL) HookAPI_Unhook(LPVOID lpFunc);
SYSLIBEXP(BOOL) HookAPI_UnhookAll();

SYSLIBEXP(LPVOID) HookAPI_GetRealFunc(LPVOID lpHandler);
SYSLIBEXP(LPVOID) HookAPI_GetReturnAddress(LPVOID lpFunc);

#define _GetRealFunc(x) __##x *p##x;\
                        p##x = (__##x*) HookAPI_GetRealFunc(&x##_handler)

#define hook(x) HookAPI_Hook(x,x##_handler)

#endif // SYSLIB_APIHOOK_H_INCLUDED
