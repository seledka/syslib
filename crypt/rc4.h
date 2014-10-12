#ifndef RC4_H_INCLUDED
#define RC4_H_INCLUDED

#define swap_byte(a, b) {swapByte = a; a = b; b = swapByte;}

typedef struct
{
    BYTE state[256];
    BYTE x;
    BYTE y;
} RC4KEY;


#endif // RC4_H_INCLUDED
