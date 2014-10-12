#ifndef SCREENSHOT_H_INCLUDED
#define SCREENSHOT_H_INCLUDED

typedef Gdiplus::GpStatus (WINGDIPAPI *GDIPLUSSTARTUP)(ULONG_PTR *token, const Gdiplus::GdiplusStartupInput *input, Gdiplus::GdiplusStartupOutput *output);
typedef void (WINGDIPAPI *GDIPLUSSHUTDOWN)(ULONG_PTR token);
typedef Gdiplus::GpStatus (WINGDIPAPI *GDIPCREATEBITMAPFROMHBITMAP)(HBITMAP hbm, HPALETTE hpal, Gdiplus::GpBitmap** bitmap);
typedef Gdiplus::GpStatus (WINGDIPAPI *GDIPDISPOSEIMAGE)(Gdiplus::GpImage *image);
typedef Gdiplus::GpStatus (WINGDIPAPI *GDIPGETIMAGEENCODERSSIZE)(UINT *numEncoders, UINT *size);
typedef Gdiplus::GpStatus (WINGDIPAPI *GDIPGETIMAGEENCODERS)(UINT numEncoders, UINT size, Gdiplus::ImageCodecInfo *encoders);
typedef Gdiplus::GpStatus (WINGDIPAPI *GDIPSAVEIMAGETOSTREAM)(Gdiplus::GpImage *image, IStream* stream, GDIPCONST CLSID* clsidEncoder, GDIPCONST Gdiplus::EncoderParameters* encoderParams);

#define OCR_NORMAL 32512

#endif // SCREENSHOT_H_INCLUDED
