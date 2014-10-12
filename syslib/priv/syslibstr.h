#ifndef SYSLIBSTR_H_INCLUDED
#define SYSLIBSTR_H_INCLUDED

namespace SYSLIB
{
    int StrCmpFmtExW(LPCWSTR lpStr,LPCWSTR lpMask,LPDWORD lpdwSubStrSize,WCHAR wMaskChar,bool bInsensitive);
    int StrCmpFmtExA(LPCSTR lpStr,LPCSTR lpMask,LPDWORD lpdwSubStrSize,char cMaskChar,bool bInsensitive);

    LPWSTR StrStrFmtExW(LPCWSTR lpStr,LPCWSTR lpMask,LPDWORD lpdwSize,WCHAR wMaskChar,bool bInsensitive);
    LPSTR StrStrFmtExA(LPCSTR lpStr,LPCSTR lpMask,LPDWORD lpdwSize,char cMaskChar,bool bInsensitive);

    DWORD StrFmt_FormatStringW(LPWSTR lpDest,LPCWSTR lpFormat,va_list args);
    DWORD StrFmt_FormatStringA(LPSTR lpDest,LPCSTR lpFormat,va_list args);

    DWORD StrFmt_ScanStringW(LPCWSTR lpString,LPCWSTR lpFormat,va_list args);
    DWORD StrFmt_ScanStringA(LPCSTR lpString,LPCSTR lpFormat,va_list args);

    DWORD wsprintfExW(LPWSTR *lppBuffer,DWORD dwOffset,LPCWSTR lpFormat,va_list args);
    DWORD wsprintfExA(LPSTR *lppBuffer,DWORD dwOffset,LPCSTR lpFormat,va_list args);
}

#endif // SYSLIBSTR_H_INCLUDED
