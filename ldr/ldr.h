#ifndef LDR_H_INCLUDED
#define LDR_H_INCLUDED

#define LDR_GET_BY_HASH 1
typedef HMODULE WINAPI __LoadLibraryExA(LPCSTR lpFileName,HANDLE hFile,DWORD dwFlags);
typedef FARPROC WINAPI __GetProcAddress(HMODULE hModule,LPCSTR lpProcName);

typedef struct
{
    WORD	Offset:12;
    WORD	Type:4;
} IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;

struct OUR_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct PEB_LDR_MODULE{
  LIST_ENTRY              InLoadOrderModuleList;
  LIST_ENTRY              InMemoryOrderModuleList;
  LIST_ENTRY              InInitializationOrderModuleList;
  PVOID                   BaseAddress;
  PVOID                   EntryPoint;
  SIZE_T                  SizeOfImage;
  OUR_UNICODE_STRING      FullDllName;
  OUR_UNICODE_STRING      BaseDllName;
  ULONG                   Flags;
  SHORT                   LoadCount;
  SHORT                   TlsIndex;
  LIST_ENTRY              HashTableEntry;
  ULONG                   TimeDateStamp;
};

typedef bool (__stdcall *_DllEntry)(HINSTANCE hinstDLL,DWORD fdwReason,LPDWORD lpvReserved);
typedef bool (__stdcall *_EntryPoint)();

#define MAX_FILE_ALIGMENT 64*1024
#define MIN_FILE_ALIGMENT 512
#define MAX_VIRTUAL_ALIGMENT 64*1024
#define MIN_VIRTUAL_ALIGMENT 512

#define IMAGE_REL_BASED_HIGHADJ          4
#define IMAGE_REL_BASED_SECTION          6
#define IMAGE_REL_BASED_REL32            7
#define	IMAGE_REL_BASED_HIGH3ADJ		11
#define LDRP_RELOCATION_INCREMENT		0x1
#define LDRP_RELOCATION_FINAL			0x2

#endif // LDR_H_INCLUDED
