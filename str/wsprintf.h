#ifndef WSPRINTF_H_INCLUDED
#define WSPRINTF_H_INCLUDED

/// #define _WSPRINTF_USE_DOUBLE 1

#define WPRINTF_LEFTALIGN         0x0001           /// Align output on the left ('-' prefix)
#define WPRINTF_SPECIALFLAG       0x0002           /// Prefix hex with 0x ('#' prefix)
#define WPRINTF_ZEROPAD           0x0004           /// Pad with zeros ('0' prefix)
#define WPRINTF_LONG              0x0008           /// Long arg ('l' prefix)
#define WPRINTF_LONGLONG          WPRINTF_INT64    /// Long long arg ('ll' prefix)
#define WPRINTF_SHORT             0x0010           /// Short arg ('h' prefix)
#define WPRINTF_UPPER             0x0020           /// Upper-case ('X','A','G','E' specifier)
#define WPRINTF_WIDE              0x0040           /// Wide arg ('w' prefix)
#define WPRINTF_INT32             0x0080           /// 32-bit arg ('I32' prefix)
#define WPRINTF_INT64             0x0100           /// 64-bit arg ('I64' prefix)
#define WPRINTF_INTPTR            WPRINTF_PTR      /// Pointer-size arg ('I' prefix)
#define WPRINTF_FORCESIGN         0x0200           /// Output value with a sign (+ or –) if the output value is of a signed type ('+' prefix)
#define WPRINTF_FORCESIGNSP       0x0400           /// Output value with a blank if the output value is signed and positive (' ' prefix)
#define WPRINTF_PTR               0x0800           /// Pointer-size arg ('P' prefix)

#define WPRINTF_USE_PREFIX_ANYWAY 0x1000           /// ...

#ifdef _WSPRINTF_USE_DOUBLE
#define WPRINTF_LONGDOUBLE       WPRINTF_LONGLONG /// Long-double arg ('L' prefix)
#endif

enum WPRINTF_TYPE
{
    WPT_UNKNOWN,
    WPT_CHAR,
    WPT_WCHAR,
    WPT_STRINGA,
    WPT_STRINGW,
    WPT_SIGNED,
    WPT_UNSIGNED,
    WPT_HEX,
    WPT_OCT,
#ifdef _WSPRINTF_USE_DOUBLE
    WPT_DOUBLE
#endif
};

struct WPRINTF_FORMAT
{
    WPRINTF_TYPE dwType;
    DWORD dwFlags;
    DWORD dwWidth;
    DWORD dwPrecision;
};

union WPRINTF_DATA
{
    WCHAR wChr;
    char cChr;
    LPCSTR lpStrA;
    LPCWSTR lpStrW;
    LONGLONG dwInt;
#ifdef _WSPRINTF_USE_DOUBLE
    long double ldDouble;
#endif
};

namespace SYSLIB
{
    DWORD StrFmt_FormatStringW(LPWSTR lpDest,LPCWSTR lpFormat,va_list arguments);
    DWORD StrFmt_FormatStringA(LPSTR lpDest,LPCSTR lpFormat,va_list arguments);

    #define MAXPRECISION 17

    DWORD GetIntParamA(LPCSTR *lppFormat);
    DWORD GetIntParamW(LPCWSTR *lppFormat);
};

#endif // WSPRINTF_H_INCLUDED
