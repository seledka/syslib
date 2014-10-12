#ifndef SYSLIBSAFE_H_INCLUDED
#define SYSLIBSAFE_H_INCLUDED

#define SYSLIB_STR_MAX_LEN 1024*5

#define SYSLIB_STR_MAX_SIZEA SYSLIB_STR_MAX_LEN*sizeof(char)
#define SYSLIB_STR_MAX_SIZEW SYSLIB_STR_MAX_LEN*sizeof(WCHAR)

namespace SYSLIB_SAFE
{
    bool CheckCodePtr(LPVOID lpFunc);

    bool CheckParamRead(LPVOID lpParam,DWORD dwSize);
    bool CheckParamWrite(LPVOID lpParam,DWORD dwSize);

    bool CheckStrParamW(LPCWSTR lpSource,DWORD dwSourceSize);
    bool CheckStrParamA(LPCSTR lpSource,DWORD dwSourceSize);

    bool CheckStrParamsExW(LPCWSTR lpSource,DWORD dwSourceSize,LPDWORD *lppOutSize);
    bool CheckStrParamsExA(LPCSTR lpSource,DWORD dwSourceSize,LPDWORD *lppOutSize);
}

#endif // SYSLIBSAFE_H_INCLUDED
