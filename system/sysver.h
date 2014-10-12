#ifndef SYSVER_H_INCLUDED
#define SYSVER_H_INCLUDED

typedef BOOL WINAPI _GetProductInfo(DWORD dwOSMajorVersion,DWORD dwOSMinorVersion,DWORD dwSpMajorVersion,DWORD dwSpMinorVersion,PDWORD pdwReturnedProductType);

#define ConcateStrAndCalcRequestedSize(str,size) dwRequested+=size-1;\
                                                 if (lpOut)\
                                                 {\
                                                     if (dwSize < dwRequested)\
                                                         lpOut=NULL;\
                                                     else\
                                                     {\
                                                         lstrcatW(lpOut,str);\
                                                         lpOut+=size-1;\
                                                     }\
                                                 }

#endif // SYSVER_H_INCLUDED
