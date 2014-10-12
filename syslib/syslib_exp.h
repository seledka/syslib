#ifndef SYSLIB_EXP_H_INCLUDED
#define SYSLIB_EXP_H_INCLUDED

#ifdef __cplusplus
#define extern_C extern "C"
#else
#define extern_C extern
#endif


#define SYSLIBEXP(x) extern_C x __cdecl

#endif // SYSLIB_EXP_H_INCLUDED
