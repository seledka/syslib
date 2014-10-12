#ifndef SYSLIB_SCRNSHOT_H_INCLUDED
#define SYSLIB_SCRNSHOT_H_INCLUDED

#include "syslib_exp.h"

enum SCREENSHOT_COMPRESSOR_TYPE
{
    BMP,
    JPEG,
    GIF,
    PNG,
    TIFF
};

SYSLIBEXP(BOOL) TakeScreenShot(SCREENSHOT_COMPRESSOR_TYPE dwCompressor,DWORD dwQuality,WORD wRectSize,BOOL bDrawCursor,LPBYTE *lppBuf,LPDWORD lpdwBufSize);

#endif // SYSLIB_SCRNSHOT_H_INCLUDED
