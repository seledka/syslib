#ifndef SCANF_H_INCLUDED
#define SCANF_H_INCLUDED

///#define _SCANF_USE_DOUBLE 1

#define SCANF_LONG             0x0001         /// Long arg ('l' prefix)
#define SCANF_LONGLONG         SCANF_INT64    /// Long long arg ('ll' prefix)
#define SCANF_SHORT            0x0002         /// Short arg ('h' prefix)
#define SCANF_WIDE             0x0004         /// Wide arg ('w' prefix)
#define SCANF_INT32            0x0008         /// 32-bit arg ('I32' prefix)
#define SCANF_INT64            0x0010         /// 64-bit arg ('I64' prefix)
#define SCANF_PTR              0x0020         /// Ptr arg ('p' prefix)
#define SCANF_SUPPRESS         0x0040         /// Dont store arg ('*' prefix)

enum SCANF_TYPE
{
    SCT_UNKNOWN,
    SCT_CHAR,
    SCT_WCHAR,
    SCT_STRINGA,
    SCT_STRINGW,
    SCT_SIGNED,
    SCT_UNSIGNED,
    SCT_HEX,
    SCT_OCT,
    SCT_BITMAP,
#ifdef _SCANF_USE_DOUBLE
    SCT_DOUBLE
#endif
};

struct SCANF_FORMAT
{
    SCANF_TYPE dwType;
    DWORD dwFlags;
    int dwWidth;
    struct
    {
        bool bInvert;
        union
        {
            char *lpBitsMapA;
            WCHAR *lpBitsMapW;
        };
    } bitmap;
};

union SCANF_DATA
{
    PWCHAR lpWChr;
    PCHAR lpChr;
    LPSTR lpStrA;
    LPWSTR lpStrW;
    PLONGLONG lpInt;
#ifdef _SCANF_USE_DOUBLE
    long double *lpLongDouble;
#endif
};

namespace SYSLIB
{
    DWORD StrFmt_ScanStringW(LPCWSTR lpString,LPCWSTR lpFormat,va_list args);
    DWORD StrFmt_ScanStringA(LPCSTR lpString,LPCSTR lpFormat,va_list args);
};

#define ASCII             32
#define ANSI_TABLESIZE    ASCII
#define UNICODE_TABLESIZE (ASCII*256)

#define SCANF_SET_TBL_BIT(x)    lpTable[x >> 3]|=(1 << (x & 7))
#define SCANF_IS_TBL_BIT_SET(x) (lpTable[x >> 3] & (1 << (x & 7)))
#endif // SCANF_H_INCLUDED
