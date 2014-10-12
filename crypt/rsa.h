#ifndef RSA_H_INCLUDED
#define RSA_H_INCLUDED

#pragma warning(disable:4200)

#define RSA_KEY_MAGIC   0x101049A
#define RSA_CRYPT_MAGIC 0x1802087

enum RSA_KEY_TYPE
{
    RSA_PUB_KEY=1,
    RSA_SEC_KEY
};

struct _RSA_PUBLIC_KEY
{
    RSA_KEY_TYPE bType;
    BIGD n;
    BIGD e;
};

struct _RSA_SECRET_KEY
{
    RSA_KEY_TYPE bType;
    BIGD n;
    BIGD e;
    BIGD d;
};


struct _RSA_KEY_DUMP_COMMON_HDR
{
    DWORD dwMagic;
    DWORD dwKeyID;
    DWORD dwKeyLen;
    RSA_KEY_TYPE bType;
};

struct _RSA_PUBLIC_KEY_DUMP
{
    _RSA_KEY_DUMP_COMMON_HDR hdr;
    union
    {
        byte bN[0];
        byte bE[0];
    };
};

struct _RSA_SECRET_KEY_DUMP
{
    _RSA_KEY_DUMP_COMMON_HDR hdr;
    union
    {
        byte bN[0];
        byte bE[0];
        byte bD[0];
    };
};

struct ENCRYPTED_HDR
{
    DWORD dwMagic;
    DWORD dwRandomShit;
    DWORD dwSize;
    DWORD dwChksum;
    byte rc4key[256];
    char cData[0];
};

#define N_SMALL_PRIMES (sizeof(SMALL_PRIMES)/sizeof(bdigit_t))

#endif // RSA_H_INCLUDED
