#ifndef WOW64_H_INCLUDED
#define WOW64_H_INCLUDED

union reg64
{
        DWORD dw[2];
        DWORD64 v;
};

#define EMIT(a) __asm __emit (a)

#define X64_Start_with_CS(_cs) \
        { \
        EMIT(0x6A) EMIT(_cs)                         /*  push   _cs             */ \
        EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)   /*  call   $+5             */ \
        EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(5)        /*  add    dword [esp], 5  */ \
        EMIT(0xCB)                                   /*  retf                   */ \
        }

#define X64_End_with_CS(_cs) \
        { \
        EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                 /*  call   $+5                   */ \
        EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(4) EMIT(_cs) EMIT(0) EMIT(0) EMIT(0) /*  mov    dword [rsp + 4], _cs  */ \
        EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(0xD)                                    /*  add    dword [rsp], 0xD      */ \
        EMIT(0xCB)                                                                 /*  retf                         */ \
        }

#define X64_Start() X64_Start_with_CS(0x33)
#define X64_End() X64_End_with_CS(0x23)

#define _RAX  0
#define _RCX  1
#define _RDX  2
#define _RBX  3
#define _RSP  4
#define _RBP  5
#define _RSI  6
#define _RDI  7
#define _R8   8
#define _R9   9
#define _R10 10
#define _R11 11
#define _R12 12
#define _R13 13
#define _R14 14
#define _R15 15

#define X64_Push(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x50 | ((r) & 7))
#define X64_Pop(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))

typedef short CSHORT;

typedef struct _PORT_MESSAGE64 {
    union {
        struct {
            CSHORT DataLength;
            CSHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            CSHORT Type;
            CSHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID64 ClientId;
        double DoNotUseThisField;       // Force quadword alignment
    };
    ULONG MessageId;
    union {
        DWORD64 ClientViewSize;          // Only valid on LPC_CONNECTION_REQUEST message
        ULONG CallbackId;                   // Only valid on LPC_REQUEST message
    };
//  UCHAR Data[];
} PORT_MESSAGE64, *PPORT_MESSAGE64;

typedef struct _BASE_CREATETHREAD_MSG64
{
    DWORD64 ThreadHandle;
    CLIENT_ID64 ClientId;
} BASE_CREATETHREAD_MSG64, *PBASE_CREATETHREAD_MSG64;

typedef ULONG CSR_API_NUMBER;

typedef struct _BASE_API_MSG64
{
    PORT_MESSAGE64 Header;
    DWORD64 CaptureBuffer;
    CSR_API_NUMBER ApiNumber;
    ULONG ReturnValue;
    ULONG Reserved;
    union
    {
        BASE_CREATETHREAD_MSG64 CreateThreadRequest;
    } u;
} BASE_API_MSG64, *PBASE_API_MSG64;


typedef WINBASEAPI BOOL WINAPI __Wow64DisableWow64FsRedirection(PVOID *OldValue);
typedef WINBASEAPI BOOL WINAPI __Wow64RevertWow64FsRedirection(PVOID OldValue);

typedef struct _WNDMSG64
{
  DWORD maxMsgs;
  DWORD64 abMsgs;
} WNDMSG64, *PWNDMSG64;

typedef struct
{
    ULONG ulVersion;
    ULONG ulCurrentVersion;
    DWORD dwDispatchCount;
    struct
    {
      DWORD64  psi;
      DWORD64  aheList;

      DWORD64  pDisplayInfo;
      DWORD64  ulSharedDelta;
      WNDMSG64 awmControl[31];
      WNDMSG64 DefWindowMsgs;
      WNDMSG64 DefWindowSpecMsgs;
    } siClient;
} USERCONNECT64, *PUSERCONNECT64;

struct MESSAGE64
{
    PORT_MESSAGE64 hdr;
    byte bTmp[512];
};

typedef struct _PORT_VIEW64
{
    ULONG Length;
    DWORD64 SectionHandle;
    ULONG SectionOffset;
    DWORD64 ViewSize;
    DWORD64 ViewBase;
    DWORD64 ViewRemoteBase;
} PORT_VIEW64, *PPORT_VIEW64;

typedef struct _REMOTE_PORT_VIEW64
{
    ULONG Length;
    DWORD64 ViewSize;
    DWORD64 ViewBase;
} REMOTE_PORT_VIEW64, *PREMOTE_PORT_VIEW64;

#endif // WOW64_H_INCLUDED
