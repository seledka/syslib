#ifndef SYSLIB_MEM_H_INCLUDED
#define SYSLIB_MEM_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(LPVOID) MemAlloc(size_t dwSize);
SYSLIBEXP(LPVOID) MemQuickAlloc(size_t dwSize);
SYSLIBEXP(LPVOID) MemRealloc(LPVOID lpMem,size_t dwSize);

SYSLIBEXP(void) MemFree(LPVOID lpMem);
SYSLIBEXP(void) MemZeroAndFree(LPVOID lpMem);

SYSLIBEXP(LPVOID) MemCopyEx(LPCVOID lpMem,size_t dwSize);

#define CHAR_Alloc(size)       (PCHAR)MemAlloc((size)*sizeof(CHAR))
#define CHAR_QuickAlloc(size)  (PCHAR)MemQuickAlloc((size)*sizeof(CHAR))
#define CHAR_Realloc(ptr,size) (PCHAR)MemRealloc(ptr,(size)*sizeof(CHAR))

#define WCHAR_Alloc(size)       (PWCHAR)MemAlloc((size)*sizeof(WCHAR))
#define WCHAR_QuickAlloc(size)  (PWCHAR)MemQuickAlloc((size)*sizeof(WCHAR))
#define WCHAR_Realloc(ptr,size) (PWCHAR)MemRealloc(ptr,(size)*sizeof(WCHAR))

#define TCHAR_Alloc(size)       (PTCHAR)MemAlloc((size)*sizeof(TCHAR))
#define TCHAR_QuickAlloc(size)  (PTCHAR)MemQuickAlloc((size)*sizeof(TCHAR))
#define TCHAR_Realloc(ptr,size) (PTCHAR)MemRealloc(ptr,(size)*sizeof(TCHAR))

SYSLIBEXP(void) MemFreeArrayOfPointers(LPVOID *lppMem,DWORD dwCount);

#endif // SYSLIB_MEM_H_INCLUDED
