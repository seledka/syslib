#include "sys_includes.h"

#include "wsprintf.h"

#include "syslib\debug.h"
#include "syslib\str.h"

#include <syslib\strcrypt.h>
#include "str_crx.h"

namespace SYSLIB
{
        static DWORD GetArgumentLen(WPRINTF_FORMAT *lpFormat,WPRINTF_DATA wpdArg,LPSTR lpNumber)
    {
        DWORD dwLen=0;

        if (lpFormat->dwFlags & WPRINTF_LEFTALIGN)
            lpFormat->dwFlags &= ~WPRINTF_ZEROPAD;

        switch (lpFormat->dwType)
        {
            case WPT_CHAR:
            case WPT_WCHAR:
            {
                lpFormat->dwPrecision=dwLen=1;
                break;
            }
            case WPT_STRINGA:
            {
                if (!wpdArg.lpStrA)
                    break;

                for (dwLen=0; ((!lpFormat->dwPrecision) || (dwLen < lpFormat->dwPrecision)); dwLen++)
                {
                    if (!wpdArg.lpStrA[dwLen])
                        break;
                }

                lpFormat->dwPrecision=dwLen;
                break;
            }
            case WPT_STRINGW:
            {
                if (!wpdArg.lpStrW)
                    break;

                for (dwLen=0; ((!lpFormat->dwPrecision) || (dwLen < lpFormat->dwPrecision)); dwLen++)
                {
                    if (!wpdArg.lpStrW[dwLen])
                        break;
                }

                lpFormat->dwPrecision=dwLen;
                break;
            }
            case WPT_OCT:
            case WPT_SIGNED:
            case WPT_UNSIGNED:
            case WPT_HEX:
            {
                char cHexAdd=(lpFormat->dwFlags & WPRINTF_UPPER) ? ('A'-'9'-1) : ('a'-'9'-1);
                DWORD dwBase=10;

                if (lpFormat->dwType == WPT_HEX)
                    dwBase=16;
                else if (lpFormat->dwType == WPT_OCT)
                    dwBase=8;

                char cBuf[256],
                     *p=cBuf,
                     *lpDst=lpNumber;

                unsigned __int64 uNumber;
                __int64 iNumber=wpdArg.dwInt;
                if (lpFormat->dwType == WPT_SIGNED)
                {
                    if (iNumber < 0)
                        *lpDst++='-';
                    else if (iNumber > 0)
                    {
                        if (lpFormat->dwFlags & WPRINTF_FORCESIGN)
                            *lpDst++='+';
                        else if (lpFormat->dwFlags & WPRINTF_FORCESIGNSP)
                            *lpDst++=' ';
                    }
                }

                if ((lpFormat->dwType == WPT_SIGNED) && (iNumber < 0))
                    uNumber=-iNumber;
                else
                    uNumber=iNumber;

                if (!(lpFormat->dwFlags & WPRINTF_INT64))
                    uNumber&=0xFFFFFFFF;

                do
                {
                    char cDigit=(char)(uNumber % dwBase)+'0';
                    uNumber/=dwBase;

                    if (cDigit > '9')
                        cDigit+=cHexAdd;

                    *p++=cDigit;
                }
                while (uNumber);

                while (p > cBuf)
                    *lpDst++=*(--p);

                *lpDst=0;
                dwLen=lpDst-lpNumber;

                if (lpFormat->dwPrecision < dwLen)
                    lpFormat->dwPrecision=dwLen;

                if ((lpFormat->dwFlags & WPRINTF_ZEROPAD) && (lpFormat->dwWidth > lpFormat->dwPrecision))
                    lpFormat->dwPrecision=lpFormat->dwWidth;
                break;
            }
    #ifdef _WSPRINTF_USE_DOUBLE
            case WPT_DOUBLE:
            {
                ///
            }
    #endif
        }
        return dwLen;
    }

    DWORD GetIntParamW(LPCWSTR *lppFormat)
    {
        DWORD dwParam=0;
        LPCWSTR p=*lppFormat;
        while ((*p >= L'0') && (*p <= L'9'))
        {
            dwParam=dwParam*10+(*p-L'0');
            p++;
        }
        *lppFormat=p;

        return dwParam;
    }

    static WPRINTF_TYPE PrepareFormatValue(char cSwitch,WPRINTF_FORMAT *lpArg,bool bAnsi)
    {
        switch (cSwitch)
        {
            case 'c':
            {
                if (!bAnsi)
                    lpArg->dwType=(lpArg->dwFlags & WPRINTF_LONG) ? WPT_CHAR : WPT_WCHAR;
                else
                    lpArg->dwType=(lpArg->dwFlags & WPRINTF_LONG) ? WPT_WCHAR : WPT_CHAR;
                break;
            }
            case 'C':
            {
                if (!bAnsi)
                    lpArg->dwType=(lpArg->dwFlags & WPRINTF_SHORT) ? WPT_WCHAR : WPT_CHAR;
                else
                    lpArg->dwType=(lpArg->dwFlags & WPRINTF_SHORT) ? WPT_CHAR : WPT_WCHAR;
                break;
            }
            case 'd':
            case 'i':
            {
                lpArg->dwType=WPT_SIGNED;
                break;
            }
            case 's':
            {
                if (!bAnsi)
                    lpArg->dwType=(lpArg->dwFlags & (WPRINTF_LONG|WPRINTF_WIDE)) ? WPT_STRINGA : WPT_STRINGW;
                else
                    lpArg->dwType=(lpArg->dwFlags & (WPRINTF_LONG|WPRINTF_WIDE)) ? WPT_STRINGW : WPT_STRINGA;
                break;
            }
            case 'S':
            {
                if (!bAnsi)
                    lpArg->dwType=(lpArg->dwFlags & (WPRINTF_SHORT|WPRINTF_WIDE)) ? WPT_STRINGW : WPT_STRINGA;
                else
                    lpArg->dwType=(lpArg->dwFlags & (WPRINTF_SHORT|WPRINTF_WIDE)) ? WPT_STRINGA : WPT_STRINGW;
                break;
            }
            case 'u':
            {
                lpArg->dwType=WPT_UNSIGNED;
                break;
            }
            case 'P':
            {
                lpArg->dwFlags|=WPRINTF_UPPER;
            }
            case 'p':
            {
                lpArg->dwWidth=sizeof(DWORD_PTR)*2;
                lpArg->dwFlags|=WPRINTF_ZEROPAD|WPRINTF_PTR;
                goto _x;
            }
            case 'X':
            {
                lpArg->dwFlags|=WPRINTF_UPPER;
            }
            case 'x':
            {
    _x:
                lpArg->dwType=WPT_HEX;
                break;
            }
            case 'o':
            {
                lpArg->dwType=WPT_OCT;
                break;
            }
    #ifdef _WSPRINTF_USE_DOUBLE
            case 'A':
            case 'G':
            case 'E':
            {
                lpArg->dwFlags|=WPRINTF_UPPER;
            }
            case 'a':
            {
                cSwitch=tolower(cSwitch);
                if (cSwitch == 'a')
                    lpArg->dwType=WPT_HEX;
            }
            case 'g':
            case 'e':
            case 'f':
            {
                lpArg->dwType=WPT_DOUBLE;

                if (lpArg->dwPrecision < 0)
                    lpArg->dwPrecision=6;
                else if ((lpArg->dwPrecision == 0) && (cSwitch == 'g'))
                    lpArg->dwPrecision=1;
                else if (lpArg->dwPrecision > MAXPRECISION)
                        lpArg->dwPrecision=MAXPRECISION;
                break;
            }
    #endif
            default:
            {
                lpArg->dwType=WPT_UNKNOWN;
                break;
            }
        }
        return lpArg->dwType;
    }

    static DWORD ParseFormatW(LPCWSTR lpFormat,WPRINTF_FORMAT *lpArg)
    {
        LPCWSTR p=lpFormat;
        memset(lpArg,0,sizeof(*lpArg));

        if (*p == L'-')
        {
            lpArg->dwFlags|=WPRINTF_LEFTALIGN;
            p++;
        }

        if (*p == L'+')
        {
            lpArg->dwFlags &= ~WPRINTF_FORCESIGNSP;
            lpArg->dwFlags|=WPRINTF_FORCESIGN;
            p++;
        }

        if (*p == L' ')
        {
            if (!(lpArg->dwFlags & WPRINTF_FORCESIGN))
                lpArg->dwFlags|=WPRINTF_FORCESIGNSP;
            p++;
        }

        if (*p == L'#')
        {
            lpArg->dwFlags|=WPRINTF_SPECIALFLAG;
            p++;
        }

        if (*p == L'0')
        {
            lpArg->dwFlags|=WPRINTF_ZEROPAD|WPRINTF_USE_PREFIX_ANYWAY;
            p++;
        }

        lpArg->dwWidth=GetIntParamW(&p);
        if ((lpArg->dwWidth) && (lpArg->dwFlags & WPRINTF_SPECIALFLAG))
            lpArg->dwFlags|=WPRINTF_USE_PREFIX_ANYWAY;

        if (*p == L'.')
        {
            p++;
            lpArg->dwPrecision=GetIntParamW(&p);
        }

        if (*p == L'l')
        {
            p++;
            if (*p == L'l')
            {
                p++;
                lpArg->dwFlags|=WPRINTF_LONGLONG;
            }
            else
                lpArg->dwFlags|=WPRINTF_LONG;
        }
        else if (*p == L'h')
        {
            lpArg->dwFlags|=WPRINTF_SHORT;
            p++;
        }
        else if (*p == L'w')
        {
            lpArg->dwFlags|=WPRINTF_WIDE;
            p++;
        }
    #ifdef _WSPRINTF_USE_DOUBLE
        else if (*p == L'L')
        {
            lpArg->dwFlags|=WPRINTF_LONGDOUBLE;
            p++;
        }
    #endif
        else if (*p == L'I')
        {
            if ((p[1] == L'6') && (p[2] == L'4'))
            {
                lpArg->dwFlags&=~WPRINTF_INT32;
                lpArg->dwFlags|=WPRINTF_INT64;
                p+=3;
            }
            else if ((p[1] == L'3') && (p[2] == L'2'))
            {
                lpArg->dwFlags&=~WPRINTF_INT64;
                lpArg->dwFlags|=WPRINTF_INT32;
                p+=3;
            }
            else
            {
                lpArg->dwFlags&=~(WPRINTF_INT32|WPRINTF_INT64);
                lpArg->dwFlags|=WPRINTF_INTPTR;
                p++;
            }
        }

        if (PrepareFormatValue((char)*p,lpArg,false) == WPT_UNKNOWN)
            p=lpFormat-1;

        return (p-lpFormat)+1;
    }

    DWORD StrFmt_FormatStringW(LPWSTR lpDest,LPCWSTR lpFormat,va_list args)
    {
        DWORD dwSize=0;
        LPWSTR p=lpDest;

        while (*lpFormat)
        {
            if (*lpFormat != L'%')
            {
                if (p)
                    *p++=*lpFormat;
                lpFormat++;

                dwSize++;
                continue;
            }

            lpFormat++;

            if (*lpFormat == L'%')
            {
                if (p)
                    *p++=*lpFormat;
                lpFormat++;

                dwSize++;
                continue;
            }

            WPRINTF_FORMAT wpfFormat;
            lpFormat+=ParseFormatW(lpFormat,&wpfFormat);

            WPRINTF_DATA wpfArgData;
            switch (wpfFormat.dwType)
            {
                case WPT_WCHAR:
                {
                    wpfArgData.wChr=va_arg(args,WCHAR);
                    break;
                }
                case WPT_CHAR:
                {
                    wpfArgData.cChr=va_arg(args,char);
                    break;
                }
                case WPT_STRINGA:
                {
                    wpfArgData.lpStrA=va_arg(args,LPCSTR);
                    break;
                }
                case WPT_STRINGW:
                {
                    wpfArgData.lpStrW=va_arg(args,LPCWSTR);
                    break;
                }
                case WPT_OCT:
                case WPT_HEX:
                case WPT_SIGNED:
                case WPT_UNSIGNED:
                {
                    if (wpfFormat.dwFlags & WPRINTF_PTR)
                        wpfArgData.dwInt=va_arg(args,LONG_PTR);
                    else if (wpfFormat.dwFlags & WPRINTF_INT32)
                        wpfArgData.dwInt=va_arg(args,LONG32);
                    else if (wpfFormat.dwFlags & WPRINTF_INT64)
                        wpfArgData.dwInt=va_arg(args,LONGLONG);
                    else
                        wpfArgData.dwInt=va_arg(args,int);
                    break;
                }
                default:
                {
                    wpfArgData.wChr=0;
                    break;
                }
            }

            char cNumber[256];
            DWORD dwLen=GetArgumentLen(&wpfFormat,wpfArgData,cNumber);
            dwSize+=dwLen;

            if (!(wpfFormat.dwFlags & WPRINTF_LEFTALIGN))
            {
                for (DWORD i=wpfFormat.dwPrecision; i < wpfFormat.dwWidth; i++, dwSize++)
                {
                    if (p)
                        *p++=L' ';
                }
            }

            DWORD dwSign=0;
            switch (wpfFormat.dwType)
            {
                case WPT_WCHAR:
                {
                    if (p)
                        *p++=wpfArgData.wChr;
                    break;
                }
                case WPT_CHAR:
                {
                    if (p)
                        *p++=(WCHAR)wpfArgData.cChr;
                    break;
                }
                case WPT_STRINGA:
                {
                    if (p)
                    {
                        LPCSTR lpSrc=wpfArgData.lpStrA;
                        for (DWORD i=0; i < dwLen; i++)
                        {
                            char szTmp[2]={lpSrc[i],0};
                            StrAnsiToUnicode(szTmp,1,p++,1);
                        }
                    }
                    break;
                }
                case WPT_STRINGW:
                {
                    if (p)
                    {
                        LPCWSTR lpSrc=wpfArgData.lpStrW;
                        for (DWORD i=0; i < dwLen; i++)
                            *p++=lpSrc[i];
                    }
                    break;
                }
                case WPT_OCT:
                case WPT_HEX:
                {
                    /**
                        MSDN:
                        When used with the o, x, or X format, the # flag prefixes any nonzero
                        output value with 0, 0x, or 0X, respectively.
                    **/
                    if ((wpfFormat.dwFlags & WPRINTF_SPECIALFLAG) && ((wpfArgData.dwInt) || (wpfFormat.dwFlags & WPRINTF_USE_PREFIX_ANYWAY)))
                    {
                        if (p)
                            *p++=L'0';
                        dwSize++;

                        if (wpfFormat.dwType == WPT_HEX)
                        {
                            if (p)
                                *p++=(wpfFormat.dwFlags & WPRINTF_UPPER) ? L'X' : L'x';
                            dwSize++;
                        }
                    }
                }
                case WPT_SIGNED:
                {
                    if ((p) && (cNumber[0] == '-'))
                    {
                        *p++=L'-';
                        dwSign=1;
                    }
                }
                case WPT_UNSIGNED:
                {
                    for (DWORD i=dwLen; i < wpfFormat.dwPrecision; i++, dwSize++)
                    {
                        if (p)
                            *p++=L'0';
                    }

                    if (p)
                    {
                        for (DWORD i=dwSign; i < dwLen; i++)
                            *p++=(WCHAR)cNumber[i];
                    }
                    break;
                }
                case WPT_UNKNOWN:
                {
                    continue;
                }
            }

            if (wpfFormat.dwFlags & WPRINTF_LEFTALIGN)
            {
                for (DWORD i=wpfFormat.dwPrecision; i < wpfFormat.dwWidth; i++, dwSize++)
                {
                    if (p)
                        *p++=L' ';
                }
            }
        }

        if ((dwSize) && (lpDest))
            lpDest[dwSize]=0;

        return dwSize;
    }

    DWORD GetIntParamA(LPCSTR *lppFormat)
    {
        DWORD dwParam=0;
        LPCSTR p=*lppFormat;
        while ((*p >= '0') && (*p <= '9'))
        {
            dwParam=dwParam*10+(*p-'0');
            p++;
        }
        *lppFormat=p;

        return dwParam;
    }

    static DWORD ParseFormatA(LPCSTR lpFormat,WPRINTF_FORMAT *lpArg)
    {
        LPCSTR p=lpFormat;
        memset(lpArg,0,sizeof(*lpArg));

        if (*p == '-')
        {
            lpArg->dwFlags|=WPRINTF_LEFTALIGN;
            p++;
        }

        if (*p == '+')
        {
            lpArg->dwFlags &= ~WPRINTF_FORCESIGNSP;
            lpArg->dwFlags|=WPRINTF_FORCESIGN;
            p++;
        }

        if (*p == ' ')
        {
            if (!(lpArg->dwFlags & WPRINTF_FORCESIGN))
                lpArg->dwFlags|=WPRINTF_FORCESIGNSP;
            p++;
        }

        if (*p == '#')
        {
            lpArg->dwFlags|=WPRINTF_SPECIALFLAG;
            p++;
        }

        if (*p == '0')
        {
            lpArg->dwFlags|=WPRINTF_ZEROPAD|WPRINTF_USE_PREFIX_ANYWAY;
            p++;
        }

        lpArg->dwWidth=GetIntParamA(&p);
        if ((lpArg->dwWidth) && (lpArg->dwFlags & WPRINTF_SPECIALFLAG))
            lpArg->dwFlags|=WPRINTF_USE_PREFIX_ANYWAY;

        if (*p == '.')
        {
            p++;
            lpArg->dwPrecision=GetIntParamA(&p);
        }

        if (*p == 'l')
        {
            p++;
            if (*p == 'l')
            {
                p++;
                lpArg->dwFlags|=WPRINTF_LONGLONG;
            }
            else
                lpArg->dwFlags|=WPRINTF_LONG;
        }
        else if (*p == 'h')
        {
            lpArg->dwFlags|=WPRINTF_SHORT;
            p++;
        }
        else if (*p == 'w')
        {
            lpArg->dwFlags|=WPRINTF_WIDE;
            p++;
        }
    #ifdef _WSPRINTF_USE_DOUBLE
        else if (*p == 'L')
        {
            lpArg->dwFlags|=WPRINTF_LONGDOUBLE;
            p++;
        }
    #endif
        else if (*p == 'I')
        {
            if ((p[1] == '6') && (p[2] == '4'))
            {
                lpArg->dwFlags&=~WPRINTF_INT32;
                lpArg->dwFlags|=WPRINTF_INT64;
                p+=3;
            }
            else if ((p[1] == '3') && (p[2] == '2'))
            {
                lpArg->dwFlags&=~WPRINTF_INT64;
                lpArg->dwFlags|=WPRINTF_INT32;
                p+=3;
            }
            else
            {
                lpArg->dwFlags&=~(WPRINTF_INT32|WPRINTF_INT64);
                lpArg->dwFlags|=WPRINTF_INTPTR;
                p++;
            }
        }

        if (PrepareFormatValue(*p,lpArg,true) == WPT_UNKNOWN)
            p=lpFormat-1;

        return (p-lpFormat)+1;
    }

    DWORD StrFmt_FormatStringA(LPSTR lpDest,LPCSTR lpFormat,va_list args)
    {
        DWORD dwSize=0;
        LPSTR p=lpDest;

        while (*lpFormat)
        {
            if (*lpFormat != '%')
            {
                if (p)
                    *p++=*lpFormat;
                lpFormat++;

                dwSize++;
                continue;
            }

            lpFormat++;

            if (*lpFormat == '%')
            {
                if (p)
                    *p++=*lpFormat;
                lpFormat++;

                dwSize++;
                continue;
            }

            WPRINTF_FORMAT wpfFormat;
            lpFormat+=ParseFormatA(lpFormat,&wpfFormat);

            WPRINTF_DATA wpfArgData;
            switch (wpfFormat.dwType)
            {
                case WPT_WCHAR:
                {
                    wpfArgData.wChr=va_arg(args,WCHAR);
                    break;
                }
                case WPT_CHAR:
                {
                    wpfArgData.cChr=va_arg(args,char);
                    break;
                }
                case WPT_STRINGA:
                {
                    wpfArgData.lpStrA=va_arg(args,LPCSTR);
                    break;
                }
                case WPT_STRINGW:
                {
                    wpfArgData.lpStrW=va_arg(args,LPCWSTR);
                    break;
                }
                case WPT_OCT:
                case WPT_HEX:
                case WPT_SIGNED:
                case WPT_UNSIGNED:
                {
                    if (wpfFormat.dwFlags & WPRINTF_PTR)
                        wpfArgData.dwInt=va_arg(args,LONG_PTR);
                    else if (wpfFormat.dwFlags & WPRINTF_INT32)
                        wpfArgData.dwInt=va_arg(args,LONG32);
                    else if (wpfFormat.dwFlags & WPRINTF_INT64)
                        wpfArgData.dwInt=va_arg(args,LONGLONG);
                    else
                        wpfArgData.dwInt=va_arg(args,int);
                    break;
                }
                default:
                {
                    wpfArgData.wChr=0;
                    break;
                }
            }

            char cNumber[256];
            DWORD dwLen=GetArgumentLen(&wpfFormat,wpfArgData,cNumber);
            dwSize+=dwLen;

            if (!(wpfFormat.dwFlags & WPRINTF_LEFTALIGN))
            {
                for (DWORD i=wpfFormat.dwPrecision; i < wpfFormat.dwWidth; i++, dwSize++)
                {
                    if (p)
                        *p++=' ';
                }
            }

            DWORD dwSign=0;
            switch (wpfFormat.dwType)
            {
                case WPT_WCHAR:
                {
                    if (p)
                        *p++=(char)wpfArgData.wChr;
                    break;
                }
                case WPT_CHAR:
                {
                    if (p)
                        *p++=wpfArgData.cChr;
                    break;
                }
                case WPT_STRINGA:
                {
                    if (p)
                    {
                        LPCSTR lpSrc=wpfArgData.lpStrA;
                        for (DWORD i=0; i < dwLen; i++)
                            *p++=lpSrc[i];
                    }
                    break;
                }
                case WPT_STRINGW:
                {
                    if (p)
                    {
                        LPCWSTR lpSrc=wpfArgData.lpStrW;
                        for (DWORD i=0; i < dwLen; i++)
                        {
                            WCHAR szTmp[2]={lpSrc[i],0};
                            StrUnicodeToAnsi(szTmp,1,p++,1);
                        }
                    }
                    break;
                }
                case WPT_OCT:
                case WPT_HEX:
                {
                    /**
                        MSDN:
                        When used with the o, x, or X format, the # flag prefixes any nonzero
                        output value with 0, 0x, or 0X, respectively.
                    **/
                    if ((wpfFormat.dwFlags & WPRINTF_SPECIALFLAG) && ((wpfArgData.dwInt) || (wpfFormat.dwFlags & WPRINTF_USE_PREFIX_ANYWAY)))
                    {
                        if (p)
                            *p++='0';
                        dwSize++;

                        if (wpfFormat.dwType == WPT_HEX)
                        {
                            if (p)
                                *p++=(wpfFormat.dwFlags & WPRINTF_UPPER) ? 'X' : 'x';
                            dwSize++;
                        }
                    }
                }
                case WPT_SIGNED:
                {
                    if ((p) && (cNumber[0] == '-'))
                    {
                        *p++='-';
                        dwSign=1;
                    }
                }
                case WPT_UNSIGNED:
                {
                    for (DWORD i=dwLen; i < wpfFormat.dwPrecision; i++, dwSize++)
                    {
                        if (p)
                            *p++='0';
                    }

                    if (p)
                    {
                        for (DWORD i=dwSign; i < dwLen; i++)
                            *p++=cNumber[i];
                    }
                    break;
                }
                case WPT_UNKNOWN:
                {
                    continue;
                }
            }

            if (wpfFormat.dwFlags & WPRINTF_LEFTALIGN)
            {
                for (DWORD i=wpfFormat.dwPrecision; i < wpfFormat.dwWidth; i++, dwSize++)
                {
                    if (p)
                        *p++=' ';
                }
            }
        }

        if ((dwSize) && (lpDest))
            lpDest[dwSize]=0;
        return dwSize;
    }
}

