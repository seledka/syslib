#ifndef STRCRYPT_H_INCLUDED
#define STRCRYPT_H_INCLUDED

struct STR_DECRYPT
{
    DWORD dwCryptedStrHash;
    DWORD dwStrLen;

    char *lpDecryptedStrA;
    WCHAR *lpDecryptedStrW;

    STR_DECRYPT *lpNextStr;
};

#endif // STRCRYPT_H_INCLUDED
