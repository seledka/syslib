#ifndef REG_H_INCLUDED
#define REG_H_INCLUDED

#pragma warning(disable:4200)

#include <pshpack1.h>
struct REG_ITEM
{
    DWORD dwItemMagic;

    DWORD dwType;
    DWORD dwDeepLevel;
    DWORD dwNameSize;
    DWORD dwItemSize;
    union
    {
        WCHAR wItemName[0];
        byte bItemData[0];
    };
};

struct  REG_FILE_FMT_HDR
{
    DWORD dwFileMagic;
    WORD wVersion;
    DWORD dwFlags;
};

struct  REG_FILE_FMT
{
    REG_FILE_FMT_HDR hdr;

    REG_ITEM riFirstItem;
};
#include <poppack.h>

#define REG_ITEM_FMT_MAGIC 'IGER'
#define REG_FILE_FMT_MAGIC 'FGER'
#define REG_CUR_VERSION 0x100

#endif // REG_H_INCLUDED
