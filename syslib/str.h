#ifndef SYSLIB_STR_H_INCLUDED
#define SYSLIB_STR_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(DWORD) StrUnicodeToAnsi(LPCWSTR lpSource,DWORD dwSourceSize,LPSTR lpDest,DWORD dwDestSize);
SYSLIBEXP(DWORD) StrAnsiToUnicode(LPCSTR lpSource,DWORD dwSourceSize,LPWSTR lpDest,DWORD dwDestSize);
SYSLIBEXP(DWORD) StrAnsiToUtf8(LPCSTR lpSource,DWORD dwSourceSize,LPSTR lpDest,DWORD dwDestSize);
SYSLIBEXP(DWORD) StrUtf8ToAnsi(LPCSTR lpSource,DWORD dwSourceSize,LPSTR lpDest,DWORD dwDestSize);
SYSLIBEXP(DWORD) StrUtf8ToUnicode(LPCSTR lpSource,DWORD dwSourceSize,LPWSTR lpDest,DWORD dwDestSize);
SYSLIBEXP(DWORD) StrUnicodeToOem(LPCWSTR lpSource,DWORD dwSourceSize,LPSTR lpDest,DWORD dwDestSize);
SYSLIBEXP(DWORD) StrOemToUnicode(LPCSTR lpSource,DWORD dwSourceSize,LPWSTR lpDest,DWORD dwDestSize);
SYSLIBEXP(DWORD) StrUnicodeToUtf8(LPCWSTR lpSource,DWORD dwSourceSize,LPSTR lpDest,DWORD dwDestSize);

SYSLIBEXP(LPSTR) StrUnicodeToAnsiEx(LPCWSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize);
SYSLIBEXP(LPWSTR) StrAnsiToUnicodeEx(LPCSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize);
SYSLIBEXP(LPSTR) StrAnsiToUtf8Ex(LPCSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize);
SYSLIBEXP(LPSTR) StrUtf8ToAnsiEx(LPCSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize);
SYSLIBEXP(LPWSTR) StrUtf8ToUnicodeEx(LPCSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize);
SYSLIBEXP(LPSTR) StrUnicodeToOemEx(LPCWSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize);
SYSLIBEXP(LPWSTR) StrOemToUnicodeEx(LPCSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize);
SYSLIBEXP(LPSTR) StrUnicodeToUtf8Ex(LPCWSTR lpSource,DWORD dwSourceSize,LPDWORD lpOutSize);

SYSLIBEXP(LPSTR) StrDuplicateA(LPCSTR lpSource,DWORD dwLen);
SYSLIBEXP(LPWSTR) StrDuplicateW(LPCWSTR lpSource,DWORD dwLen);

#ifdef UNICODE
#define StrDuplicate StrDuplicateW
#else
#define StrDuplicate StrDuplicateA
#endif


SYSLIBEXP(DWORD) StrToHexW(LPCWSTR lpStr);
SYSLIBEXP(DWORD) StrToHexA(LPCSTR lpStr);

#ifdef UNICODE
#define StrToHex StrToHexW
#else
#define StrToHex StrToHexA
#endif


SYSLIBEXP(DWORD64) StrToHex64W(LPCWSTR lpStr);
SYSLIBEXP(DWORD64) StrToHex64A(LPCSTR lpStr);

#ifdef UNICODE
#define StrToHex64 StrToHex64W
#else
#define StrToHex64 StrToHex64A
#endif


SYSLIBEXP(DWORD) StrFormatW(LPWSTR lpDest,LPCWSTR lpFormat,...);
SYSLIBEXP(DWORD) StrFormatA(LPSTR lpDest,LPCSTR lpFormat,...);

#ifdef UNICODE
#define StrFormat StrFormatW
#else
#define StrFormat StrFormatA
#endif


SYSLIBEXP(DWORD) StrFormatExW(LPWSTR *lppDest,LPCWSTR lpFormat,...);
SYSLIBEXP(DWORD) StrFormatExA(LPSTR *lppDest,LPCSTR lpFormat,...);

#ifdef UNICODE
#define StrFormatEx StrFormatExW
#else
#define StrFormatEx StrFormatExA
#endif


SYSLIBEXP(DWORD) StrCatFormatExW(LPWSTR *lppDest,DWORD dwDestSize,LPCWSTR lpFormat,...);
SYSLIBEXP(DWORD) StrCatFormatExA(LPSTR *lppDest,DWORD dwDestSize,LPCSTR lpFormat,...);

#ifdef UNICODE
#define StrCatFormatEx StrCatFormatExW
#else
#define StrCatFormatEx StrCatFormatExA
#endif


SYSLIBEXP(DWORD) StrCatFormatW(LPWSTR lpDest,DWORD dwDestSize,LPCWSTR lpFormat,...);
SYSLIBEXP(DWORD) StrCatFormatA(LPSTR lpDest,DWORD dwDestSize,LPCSTR lpFormat,...);

#ifdef UNICODE
#define StrCatFormat StrCatFormatW
#else
#define StrCatFormat StrCatFormatA
#endif


SYSLIBEXP(DWORD) StrCatExW(LPWSTR *lppDest,LPCWSTR lpSource,DWORD dwSourceSize);
SYSLIBEXP(DWORD) StrCatExA(LPSTR *lppDest,LPCSTR lpSource,DWORD dwSourceSize);

#ifdef UNICODE
#define StrCatEx StrCatExW
#else
#define StrCatEx StrCatExA
#endif


SYSLIBEXP(DWORD) StrScanFormatW(LPCWSTR lpString,LPCWSTR lpFormat,...);
SYSLIBEXP(DWORD) StrScanFormatA(LPCSTR lpString,LPCSTR lpFormat,...);

#ifdef UNICODE
#define StrScanFormat StrScanFormatW
#else
#define StrScanFormat StrScanFormatA
#endif


#ifdef UNICODE
#define CharToTCHAR(lpTo,lpFrom) StrAnsiToUnicode(lpFrom,0,lpTo,0);
#else
#define CharToTCHAR(lpTo,lpFrom) lstrcpyA(lpTo,lpFrom);
#endif

#ifdef UNICODE
#define TCHARToChar(lpTo,lpFrom) StrUnicodeToAnsi(lpFrom,0,lpTo,0);
#else
#define TCHARToChar(lpTo,lpFrom) lstrcpyA(lpTo,lpFrom);
#endif


SYSLIBEXP(int) StrCmpIFmtW(LPCWSTR lpStr,LPCWSTR lpMask);
SYSLIBEXP(int) StrCmpIFmtA(LPCSTR lpStr,LPCSTR lpMask);

#ifdef UNICODE
#define StrCmpIFmt StrCmpIFmtW
#else
#define StrCmpIFmt StrCmpIFmtA
#endif


SYSLIBEXP(int) StrCmpFmtW(LPCWSTR lpStr,LPCWSTR lpMask);
SYSLIBEXP(int) StrCmpFmtA(LPCSTR lpStr,LPCSTR lpMask);

#ifdef UNICODE
#define StrCmpFmt StrCmpFmtW
#else
#define StrCmpFmt StrCmpFmtA
#endif


#define STRGEN_UPPERCASE 0x1
#define STRGEN_LOWERCASE 0x2
#define STRGEN_DIGITS    0x4
#define STRGEN_MINUS     0x8
#define STRGEN_UNDERLINE 0x10
#define STRGEN_SPACE     0x20
#define STRGEN_SPECIAL   0x40
#define STRGEN_BRACKETS  0x80

#define STRGEN_STRONGPASS (STRGEN_UPPERCASE|STRGEN_LOWERCASE|STRGEN_DIGITS|STRGEN_MINUS|STRGEN_UNDERLINE|STRGEN_SPACE|STRGEN_SPECIAL|STRGEN_BRACKETS)

SYSLIBEXP(BOOL) StrGenerateW(LPWSTR lpStr,DWORD dwSize,DWORD dwFlags);
SYSLIBEXP(BOOL) StrGenerateA(LPSTR lpStr,DWORD dwSize,DWORD dwFlags);

#ifdef UNICODE
#define StrGenerate StrGenerateW
#else
#define StrGenerate StrGenerateA
#endif


SYSLIBEXP(LPWSTR) StrStrFmtW(LPCWSTR lpStr,LPCWSTR lpMask,LPDWORD lpdwSize);
SYSLIBEXP(LPSTR) StrStrFmtA(LPCSTR lpStr,LPCSTR lpMask,LPDWORD lpdwSize);

#ifdef UNICODE
#define StrStrFmt StrStrFmtW
#else
#define StrStrFmt StrStrFmtA
#endif


SYSLIBEXP(LPWSTR) StrStrFmtIW(LPCWSTR lpStr,LPCWSTR lpMask,LPDWORD lpdwSize);
SYSLIBEXP(LPSTR) StrStrFmtIA(LPCSTR lpStr,LPCSTR lpMask,LPDWORD lpdwSize);

#ifdef UNICODE
#define StrStrFmtI StrStrFmtIW
#else
#define StrStrFmtI StrStrFmtIA
#endif


#define STRSPLIT_USE_SEPARATOR 0x1

SYSLIBEXP(DWORD) StrSplitToStringsExW(LPCWSTR lpSource,DWORD dwSourceSize,LPWSTR **lpppStrings,DWORD dwFlags,WCHAR wSeparator);
SYSLIBEXP(DWORD) StrSplitToStringsExA(LPCSTR lpSource,DWORD dwSourceSize,LPSTR **lpppStrings,DWORD dwFlags,char cSeparator);

#ifdef UNICODE
#define StrSplitToStringsEx StrSplitToStringsExW
#else
#define StrSplitToStringsEx StrSplitToStringsExA
#endif


SYSLIBEXP(DWORD) StrSplitToStringsW(LPCWSTR lpSource,DWORD dwSourceSize,LPWSTR **lpppStrings);
SYSLIBEXP(DWORD) StrSplitToStringsA(LPCSTR lpSource,DWORD dwSourceSize,LPSTR **lpppStrings);

#ifdef UNICODE
#define StrSplitToStrings StrSplitToStringsW
#else
#define StrSplitToStrings StrSplitToStringsA
#endif


SYSLIBEXP(BOOL) StrReverseW(LPCWSTR lpSource,DWORD dwSourceSize,LPWSTR lpOut);
SYSLIBEXP(BOOL) StrReverseA(LPCSTR lpSource,DWORD dwSourceSize,LPSTR lpOut);

#ifdef UNICODE
#define StrReverse StrReverseW
#else
#define StrReverse StrReverseA
#endif


SYSLIBEXP(LPWSTR) StrReverseExW(LPCWSTR lpSource,DWORD dwSourceSize);
SYSLIBEXP(LPSTR) StrReverseExA(LPCSTR lpSource,DWORD dwSourceSize);

#ifdef UNICODE
#define StrReverseEx StrReverseExW
#else
#define StrReverseEx StrReverseExA
#endif


SYSLIBEXP(DWORD) BinToHexW(LPBYTE lpData,DWORD dwSize,LPWSTR lpStrOut);
SYSLIBEXP(DWORD) BinToHexA(LPBYTE lpData,DWORD dwSize,LPSTR lpStrOut);

#ifdef UNICODE
#define BinToHex BinToHexW
#else
#define BinToHex BinToHexA
#endif


SYSLIBEXP(LPWSTR) BinToHexExW(LPBYTE lpData,DWORD dwSize,LPDWORD lpdwOutSize);
SYSLIBEXP(LPSTR) BinToHexExA(LPBYTE lpData,DWORD dwSize,LPDWORD lpdwOutSize);

#ifdef UNICODE
#define BinToHexEx BinToHexExW
#else
#define BinToHexEx BinToHexExA
#endif


SYSLIBEXP(DWORD) HexToBinW(LPCWSTR lpStr,LPBYTE lpOut,DWORD dwSize);
SYSLIBEXP(DWORD) HexToBinA(LPCSTR lpStr,LPBYTE lpOut,DWORD dwSize);

#ifdef UNICODE
#define HexToBin HexToBinW
#else
#define HexToBin HexToBinA
#endif


SYSLIBEXP(LPBYTE) HexToBinExW(LPCWSTR lpStr,LPDWORD lpdwOutSize);
SYSLIBEXP(LPBYTE) HexToBinExA(LPCSTR lpStr,LPDWORD lpdwOutSize);

#ifdef UNICODE
#define HexToBinEx HexToBinExW
#else
#define HexToBinEx HexToBinExA
#endif


#endif // SYSLIB_STR_H_INCLUDED
