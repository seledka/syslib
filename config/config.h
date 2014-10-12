#ifndef CONFIG_H_INCLUDED
#define CONFIG_H_INCLUDED

#define LDR_IS_DATAFILE(handle)      (((ULONG_PTR)(handle)) &  (ULONG_PTR)1)
#define LDR_IS_IMAGEMAPPING(handle)  (((ULONG_PTR)(handle)) & (ULONG_PTR)2)
#define LDR_IS_RESOURCE(handle)      (LDR_IS_IMAGEMAPPING(handle) || LDR_IS_DATAFILE(handle))

#define CONFIG_MAGIC 0xDEAD
#define CONFIG_START_MARKER 'GFC!'

#pragma warning(disable:4200)

typedef struct _CONFIG
{
    DWORD dwCheckSum;
    WORD wMagicWord;
    DWORD dwStructSize;
    bool bLastItem;
    DWORD dwSize;
    bool bEncrypted;
    bool bIntName;
    union
    {
        DWORD dwIntName;
        char szName[50];
    };
    byte bData[0];
} CONFIG, *HCONFIG;

typedef bool (CALLBACK* ENUMCONFNAMEPROCA)(HMODULE hModule,LPSTR lpName,LONG_PTR lParam);
typedef bool (CALLBACK* ENUMCONFNAMEPROCW)(HMODULE hModule,LPWSTR lpName,LONG_PTR lParam);

struct CONFIG_DIR_ENTRY
{
    bool bIntName;
    union
    {
        DWORD dwIntName;
        char szName[50];
    };

    DWORD dwNameHash;
    void *lpData;
    DWORD dwSize;

    CONFIG_DIR_ENTRY *lpNext;
};

typedef struct _UPDATECONFIG
{
    CRITICAL_SECTION csUpdate;
    WCHAR szFile[MAX_PATH];
    CONFIG_DIR_ENTRY *lpNewConfigsDir;
    HPE_REBUILD hPE;
} UPDATECONFIG, *HUPDATECONFIG;

struct ENUM_CONFIGS_INT
{
    LONG_PTR lParam;
    bool bUnicode;
    union
    {
        ENUMCONFNAMEPROCA lpAnsi;
        ENUMCONFNAMEPROCW lpUnicode;
    };
};

#endif // CONFIG_H_INCLUDED
