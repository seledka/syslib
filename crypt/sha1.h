#ifndef SHA1_H
#define SHA1_H

typedef struct {
  DWORD H[5];
  DWORD W[80];
  int lenW;
  DWORD sizeHi, sizeLo;
} SHA1_CTX;

#define SHA_ROTL(X, n) (((X) << (n)) | ((X) >> (32-(n))))

#endif /* sha1.h */