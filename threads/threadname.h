#ifndef THREADNAME_H_INCLUDED
#define THREADNAME_H_INCLUDED

#define MS_VC_EXCEPTION 0x406D1388

#pragma pack(push,8)
typedef struct _THREADNAME_INFO
{
   DWORD dwType;
   LPCSTR szName;
   DWORD dwThreadID;
   DWORD dwFlags;
} THREADNAME_INFO, *PTHREADNAME_INFO;
#pragma pack(pop)

#endif // THREADNAME_H_INCLUDED
