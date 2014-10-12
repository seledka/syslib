#include "sys_includes.h"

#include "bigd\bigd.h"
#include "bigd\bigdRand.h"
#include "bigd\mem.h"

#include "rsa.h"
#include "system\system.h"

#include "syslib\hash.h"
#include "syslib\system.h"
#include "syslib\chksum.h"
#include "syslib\utils.h"
#include "syslib\rsa.h"
#include "syslib\str.h"
#include "syslib\rc4.h"
#include "syslib\debug.h"

static int MyRand(LPBYTE lpBytes,size_t nBytes,LPBYTE lpSeed,size_t dwSeedLen)
{
	DWORD dwSeed=GetTickCount();
	if (lpSeed)
	{
		for (int dwOffset=0, i=0; i < dwSeedLen; i++, dwOffset=(dwOffset+1) % sizeof(DWORD))
			dwSeed^=((DWORD)lpSeed[i] << (dwOffset*8));
	}

	while (nBytes--)
	{
		*lpBytes=xor128(dwSeed) & 0xFF;
		lpBytes++;
	}
	return 0;
}

static bdigit_t SMALL_PRIMES[]=
{
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
    47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
    103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
    283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
    353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
    419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
    467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
    547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
    607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
    739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
    811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
    877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
    947, 953, 967, 971, 977, 983, 991, 997,
};

static int GenerateRSAPrime(BIGD p, size_t nbits, bdigit_t e, size_t ntests, const unsigned char *seed, size_t seedlen, BD_RANDFUNC randFunc)
{
	size_t i, j, iloop, maxloops, maxodd;
	int done, overflow, failedtrial;
	int count = 0;
	bdigit_t r[N_SMALL_PRIMES];

	/* Create a temp */
	BIGD u = bdNew();

	maxodd = nbits * 100;
	maxloops = 5;

	done = 0;
	for (iloop = 0; !done && iloop < maxloops; iloop++)
	{
		/* Set candidate n0 as random odd number */
		bdRandomSeeded(p, nbits, seed, seedlen, randFunc);
		/* Set two highest and low bits */
		bdSetBit(p, nbits - 1, 1);
		bdSetBit(p, nbits - 2, 1);
		bdSetBit(p, 0, 1);

		/* To improve trial division, compute table R[q] = n0 mod q
		   for each odd prime q <= B
		*/
		for (i = 0; i < N_SMALL_PRIMES; i++)
		{
			r[i] = bdShortMod(u, p, SMALL_PRIMES[i]);
		}

		done = overflow = 0;
		/* Try every odd number n0, n0+2, n0+4,... until we succeed */
		for (j = 0; j < maxodd; j++, overflow = bdShortAdd(p, p, 2))
		{
			/* Check for overflow */
			if (overflow)
				break;

			///give_a_sign('.');
			count++;

			/* Each time 2 is added to the current candidate
			   update table R[q] = (R[q] + 2) mod q */
			if (j > 0)
			{
				for (i = 0; i < N_SMALL_PRIMES; i++)
				{
					r[i] = (r[i] + 2) % SMALL_PRIMES[i];
				}
			}

			/* Candidate passes the trial division stage if and only if
			   NONE of the R[q] values equal zero */
			for (failedtrial = 0, i = 0; i < N_SMALL_PRIMES; i++)
			{
				if (r[i] == 0)
				{
					failedtrial = 1;
					break;
				}
			}
			if (failedtrial)
				continue;

			/* If p mod e = 1 then gcd(p, e) > 1, so try again */
			bdShortMod(u, p, e);
			if (bdShortCmp(u, 1) == 0)
				continue;

			/* Do expensive primality test */
			///give_a_sign('*');
			if (bdRabinMiller(p, ntests))
			{	/* Success! - we have a prime */
				done = 1;
				break;
			}

		}
	}


	/* Clear up */
	bdFree(&u);
	///printf("\n");

	return (done ? count : -1);
}

static int GenerateRSAKey(BIGD n, BIGD e, BIGD d, BIGD p, BIGD q, BIGD dP, BIGD dQ, BIGD qInv,size_t nbits, bdigit_t ee, size_t ntests, unsigned char *seed, size_t seedlen,BD_RANDFUNC randFunc)
{
	size_t np, nq;
	unsigned char *myseed = NULL;
	long ptests;
	int res;

	/* Initialise */
	BIGD g=bdNew(),
         p1=bdNew(),
         q1=bdNew(),
         phi=bdNew();

	/* We add an extra byte to the user-supplied seed */
	myseed = (unsigned char * )malloc(seedlen + 1);
	if (!myseed) return -1;
	memcpy(myseed, seed, seedlen);

	/* Do (p, q) in two halves, approx equal */
	nq = nbits / 2 ;
	np = nbits - nq;

	/* Make sure seeds are slightly different for p and q */
	myseed[seedlen] = 0x01;
	res = GenerateRSAPrime(p, np, ee, ntests, myseed, seedlen+1, randFunc);
	ptests = res;

	myseed[seedlen] = 0xff;
	res = GenerateRSAPrime(q, nq, ee, ntests, myseed, seedlen+1, randFunc);
	ptests += res;
	bdSetShort(e, ee);

	/* If q > p swap p and q so p > q */
	if (bdCompare(p, q) < 1)
	{
		bdSetEqual(g, p);
		bdSetEqual(p, q);
		bdSetEqual(q, g);
	}

	/* Calc p-1 and q-1 */
	bdSetEqual(p1, p);
	bdDecrement(p1);

	bdSetEqual(q1, q);
	bdDecrement(q1);

	/* Check gcd(p-1, e) = 1 */
	bdGcd(g, p1, e);
	bdGcd(g, q1, e);

	/* Compute n = pq */
	bdMultiply(n, p, q);

	/* Compute d = e^-1 mod (p-1)(q-1) */
	bdMultiply(phi, p1, q1);
	res = bdModInv(d, e, phi);

	/* Check ed = 1 mod phi */
	bdModMult(g, e, d, phi);

	/* Calculate CRT key values */
	bdModInv(dP, e, p1);
	bdModInv(dQ, e, q1);
	bdModInv(qInv, q, p);

	/* Clean up */
	if (myseed) free(myseed);
	bdFree(&g);
	bdFree(&p1);
	bdFree(&q1);
	bdFree(&phi);

	return 0;
}

SYSLIBFUNC(BOOL) RSA_KeyGen(DWORD dwBitsCount,RSA_KEY *lppPrivKey,RSA_KEY *lppPubKey)
{
    if (!SYSLIB_SAFE::CheckParamWrite(lppPrivKey,sizeof(*lppPrivKey)))
        return false;

    if (!SYSLIB_SAFE::CheckParamWrite(lppPubKey,sizeof(*lppPubKey)))
        return false;

    BOOL bRet=false;
	unsigned ee = 65537;
	size_t ntests = 50;

	/* Initialise */
	BIGD p=bdNew(),
         q=bdNew(),
         n=bdNew(),
         e=bdNew(),
         d=bdNew(),
         dP=bdNew(),
         dQ=bdNew(),
         qInv=bdNew(),
         m=bdNew(),
         c=bdNew(),
         s=bdNew(),
         m1=bdNew(),
         m2=bdNew(),
         h=bdNew(),
         hq=bdNew();

	GenerateRSAKey(n,e,d,p,q,dP,dQ,qInv,dwBitsCount,ee,ntests,NULL,0,(BD_RANDFUNC)MyRand);

    /* Set a random message m < n */
    bdRandomSeeded(m, bdBitLength(n)-1, NULL, 0, (BD_RANDFUNC)MyRand);

    /* Encrypt c = m^e mod n */
    bdModExp(c, m, e, n);

    /* Check decrypt m1 = c^d mod n */
    bdModExp(m1, c, d, n);
    if (!bdCompare(m1, m))
    {
        _RSA_SECRET_KEY *lpSecKey=(_RSA_SECRET_KEY*)MemAlloc(sizeof(_RSA_SECRET_KEY));
        if (lpSecKey)
        {
            lpSecKey->bType=RSA_SEC_KEY;

            lpSecKey->n=bdNew();
            bdSetEqual(lpSecKey->n,n);

            lpSecKey->e=bdNew();
            bdSetEqual(lpSecKey->e,e);

            lpSecKey->d=bdNew();
            bdSetEqual(lpSecKey->d,d);

            *lppPrivKey=(RSA_KEY)lpSecKey;
        }
        _RSA_PUBLIC_KEY *lpPubKey=(_RSA_PUBLIC_KEY*)MemAlloc(sizeof(_RSA_PUBLIC_KEY));
        if (lpPubKey)
        {
            lpPubKey->bType=RSA_PUB_KEY;

            lpPubKey->n=bdNew();
            bdSetEqual(lpPubKey->n,n);

            lpPubKey->e=bdNew();
            bdSetEqual(lpPubKey->e,e);

            *lppPubKey=(RSA_KEY)lpPubKey;
        }

        bRet=true;
    }

	bdFree(&n);
	bdFree(&e);
	bdFree(&d);
	bdFree(&p);
	bdFree(&q);
	bdFree(&dP);
	bdFree(&dQ);
	bdFree(&qInv);
	bdFree(&m);
	bdFree(&c);
	bdFree(&s);
	bdFree(&m1);
	bdFree(&m2);
	bdFree(&h);
	bdFree(&hq);

	return bRet;
}

static void RSA_CryptInt(BIGD m,BIGD c,BIGD d,BIGD n,LPBYTE lpIn,DWORD dwInSize,LPBYTE lpOut)
{
    bdConvFromOctets(m,lpIn,dwInSize);
    bdModExp(c,m,d,n);
    if (lpOut)
        bdConvToOctets(c,lpOut,(bdBitLength(n)+7)/8);
    return;
}

static bool RSA_CheckKey(RSA_KEY rsaKey)
{
    bool bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckParamRead(rsaKey,sizeof(_RSA_PUBLIC_KEY)))
            break;

        _RSA_PUBLIC_KEY *lpPub=(_RSA_PUBLIC_KEY*)rsaKey;
        if (lpPub->bType == RSA_PUB_KEY)
        {
            bRet=true;
            break;
        }

        if (lpPub->bType != RSA_SEC_KEY)
            break;

        if (!SYSLIB_SAFE::CheckParamRead(rsaKey,sizeof(_RSA_SECRET_KEY)))
            break;

        bRet=true;
    }
    while (false);
    return bRet;
}

static bool RSA_CheckSignBuffRead(RSA_KEY rsaKey,LPBYTE lpSign)
{
    bool bRet=false;
    do
    {
        if (!RSA_CheckKey(rsaKey))
            break;

        _RSA_PUBLIC_KEY *lpPub=(_RSA_PUBLIC_KEY*)rsaKey;
        if (lpPub->bType != RSA_PUB_KEY)
            break;

        if (!SYSLIB_SAFE::CheckParamRead(lpSign,((bdBitLength(lpPub->n)+7)/8)))
            break;

        bRet=true;
    }
    while (false);
    return bRet;
}

static bool RSA_CheckSignBuffWrite(RSA_KEY rsaKey,LPBYTE lpSign)
{
    bool bRet=false;
    do
    {
        if (!RSA_CheckKey(rsaKey))
            break;

        _RSA_SECRET_KEY *lpSecretKey=(_RSA_SECRET_KEY*)rsaKey;
        if (lpSecretKey->bType != RSA_SEC_KEY)
            break;

        if (!SYSLIB_SAFE::CheckParamWrite(lpSign,((bdBitLength(lpSecretKey->n)+7)/8)))
            break;

        bRet=true;
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) RSA_SignBuffer(RSA_KEY rsaPrivKey,LPBYTE lpBufIn,DWORD dwBufSize,LPBYTE lpSign)
{
    BOOL bRet=false;

    do
    {
        if (!SYSLIB_SAFE::CheckParamRead(lpBufIn,dwBufSize))
            break;

        if (!RSA_CheckSignBuffWrite(rsaPrivKey,lpSign))
            break;

        byte bMD6[64];
        if (!hash_CalcMD6(lpBufIn,dwBufSize,bMD6))
            break;

        BIGD m=bdNew();
        if (!m)
            break;

        BIGD s=bdNew();
        if (!s)
        {
            bdFree(&m);
            break;
        }

        _RSA_SECRET_KEY *lpSecretKey=(_RSA_SECRET_KEY*)rsaPrivKey;
        RSA_CryptInt(m,s,lpSecretKey->d,lpSecretKey->n,bMD6,sizeof(bMD6),lpSign);

        bdFree(&m);
        bdFree(&s);

        bRet=true;
    }
    while (false);

    return bRet;
}

SYSLIBFUNC(BOOL) RSA_SignFileW(RSA_KEY rsaPrivKey,LPCWSTR lpFile,LPBYTE lpSign)
{
    BOOL bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
            break;

        if (!RSA_CheckSignBuffWrite(rsaPrivKey,lpSign))
            break;

        HANDLE hFile=CreateFileW(lpFile,GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            HANDLE hMap=CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,NULL);
            if (hMap)
            {
                LPBYTE lpMap=(byte*)MapViewOfFile(hMap,FILE_MAP_READ,0,0,0);
                if (lpMap)
                {
                    bRet=RSA_SignBuffer(rsaPrivKey,lpMap,GetFileSize(hFile,NULL),lpSign);
                    UnmapViewOfFile(lpMap);
                }
                SysCloseHandle(hMap);
            }
            SysCloseHandle(hFile);
        }
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) RSA_SignFileA(RSA_KEY rsaPrivKey,LPCSTR lpFile,LPBYTE lpSign)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=RSA_SignFileW(rsaPrivKey,lpFileNameW,lpSign);

    MemFree(lpFileNameW);
    return bRet;
}

static void GenerateRandomRc4Key(DWORD *lpKey)
{
    for (int i=0; i < (256/4)-1; i++)
        StrFormatA((char*)&lpKey[i],"%x",GetRndDWORD());
    return;
}

SYSLIBFUNC(DWORD) RSA_CryptBufferFull(RSA_KEY rsaKey,LPBYTE lpBufIn,DWORD dwBufSize,LPBYTE *lppBufOut)
{
    if (!RSA_CheckKey(rsaKey))
        return 0;

    if (!SYSLIB_SAFE::CheckParamRead(lpBufIn,dwBufSize))
        return 0;

    if (!SYSLIB_SAFE::CheckParamWrite(lppBufOut,sizeof(*lppBufOut)))
        return 0;

    DWORD dwSize=0;

    BIGD d,n;

    if (((_RSA_SECRET_KEY*)rsaKey)->bType == RSA_SEC_KEY)
    {
        _RSA_SECRET_KEY *lpPriv=(_RSA_SECRET_KEY*)rsaKey;
        d=lpPriv->d;
        n=lpPriv->n;
    }
    else
    {
        _RSA_PUBLIC_KEY *lpPub=(_RSA_PUBLIC_KEY*)rsaKey;
        d=lpPub->e;
        n=lpPub->n;
    }

    DWORD dwKeyLenInBytes=(bdBitLength(n)+7)/8,
          dwNewBufSize=ALIGN(max(dwKeyLenInBytes,dwBufSize),dwKeyLenInBytes);
    LPBYTE lpOutBuf=(byte*)MemQuickAlloc(dwNewBufSize);
    if (lpOutBuf)
    {
        BIGD m=bdNew(),
             c=bdNew();

        LPBYTE lpOut=lpOutBuf,
               lpIn=lpBufIn;

        while (dwBufSize >= dwKeyLenInBytes)
        {
            RSA_CryptInt(m,c,d,n,lpIn,dwKeyLenInBytes,lpOut);

            lpIn+=dwKeyLenInBytes;
            lpOut+=dwKeyLenInBytes;
            dwBufSize-=dwKeyLenInBytes;
        }

        if (dwBufSize)
        {
            LPBYTE lpTmp=(byte*)MemQuickAlloc(dwKeyLenInBytes);
            if (lpTmp)
            {
                memcpy(lpTmp,lpIn,dwBufSize);

                DWORD dwPadSize=dwKeyLenInBytes-dwBufSize;
                LPBYTE lpPad=lpTmp+dwBufSize;
                for (DWORD i=0; i < dwPadSize; i++)
                {
                    DWORD dwRndByte=0;
                    while (!dwRndByte)
                        dwRndByte=xor128(0xFF);
                    lpPad[i]=(byte)dwRndByte;
                }

                RSA_CryptInt(m,c,d,n,lpTmp,dwKeyLenInBytes,lpOut);

                dwSize=dwNewBufSize;
                MemFree(lpTmp);
            }
        }

        *lppBufOut=lpOutBuf;

        bdFree(&m);
        bdFree(&c);
    }
    return dwSize;
}

SYSLIBFUNC(DWORD) RSA_CryptBuffer(RSA_KEY rsaKey,LPBYTE lpBufIn,DWORD dwBufSize,LPBYTE *lppBufOut)
{
    if (!RSA_CheckKey(rsaKey))
        return 0;

    if (!SYSLIB_SAFE::CheckParamRead(lpBufIn,dwBufSize))
        return 0;

    if (!SYSLIB_SAFE::CheckParamWrite(lppBufOut,sizeof(*lppBufOut)))
        return 0;

    DWORD dwSize=0;
    ENCRYPTED_HDR ehHdr={0};
    ehHdr.dwMagic=RSA_CRYPT_MAGIC;
    ehHdr.dwSize=dwBufSize;
    ehHdr.dwChksum=MurmurHash3(lpBufIn,dwBufSize);
    ehHdr.dwRandomShit=GetRndDWORD();
    GenerateRandomRc4Key((DWORD*)&ehHdr.rc4key);
    LPBYTE lpEnc;
    DWORD dwRSASize=RSA_CryptBufferFull(rsaKey,(byte*)&ehHdr,sizeof(ehHdr),&lpEnc);
    if (dwRSASize)
    {
        dwSize=dwRSASize+dwBufSize;
        LPBYTE lpEnc1=(byte*)MemRealloc(lpEnc,dwSize);
        if (lpEnc1)
        {
            LPBYTE lpOut=lpEnc1+dwRSASize;
            rc4Full(ehHdr.rc4key,sizeof(ehHdr.rc4key),lpBufIn,dwBufSize,lpOut);
            *lppBufOut=lpEnc1;
        }
        else
            MemFree(lpEnc);
    }
    return dwSize;
}

SYSLIBFUNC(BOOL) RSA_CryptFileW(RSA_KEY rsaKey,LPCWSTR lpFileIn,LPCWSTR lpFileOut)
{
    BOOL bRet=false;
    do
    {
        if (!RSA_CheckKey(rsaKey))
            break;

        if (!SYSLIB_SAFE::CheckStrParamW(lpFileIn,MAX_PATH))
            break;

        if (!SYSLIB_SAFE::CheckStrParamW(lpFileOut,MAX_PATH))
            break;

        HANDLE hFileIn=CreateFileW(lpFileIn,GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL);
        if (hFileIn != INVALID_HANDLE_VALUE)
        {
            HANDLE hMapIn=CreateFileMapping(hFileIn,NULL,PAGE_READONLY,0,0,NULL);
            if (hMapIn)
            {
                LPBYTE lpMapIn=(byte*)MapViewOfFile(hMapIn,FILE_MAP_READ,0,0,0);
                if (lpMapIn)
                {
                    LPBYTE lpBuf;
                    DWORD dwSize=RSA_CryptBuffer(rsaKey,lpMapIn,GetFileSize(hFileIn,NULL),&lpBuf);
                    if (dwSize)
                    {
                        HANDLE hFileOut=CreateFileW(lpFileOut,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
                        if (hFileOut != INVALID_HANDLE_VALUE)
                        {
                            DWORD tmp;
                            WriteFile(hFileOut,lpBuf,dwSize,&tmp,NULL);
                            FlushFileBuffers(hFileOut);
                            bRet=true;
                            SysCloseHandle(hFileOut);
                        }
                        MemFree(lpBuf);
                    }
                    UnmapViewOfFile(lpMapIn);
                }
                SysCloseHandle(hMapIn);
            }
            SysCloseHandle(hFileIn);
        }
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) RSA_CryptFileA(RSA_KEY rsaKey,LPCSTR lpFileIn,LPCSTR lpFileOut)
{
    LPWSTR lpFileInW=StrAnsiToUnicodeEx(lpFileIn,0,NULL),
           lpFileOutW=StrAnsiToUnicodeEx(lpFileOut,0,NULL);

    BOOL bRet=RSA_CryptFileW(rsaKey,lpFileInW,lpFileOutW);

    MemFree(lpFileInW);
    MemFree(lpFileOutW);
    return bRet;
}

static void RSA_DecryptInt(BIGD m,BIGD c,BIGD d,BIGD n,LPBYTE lpIn,DWORD dwInSize,LPBYTE lpOut)
{
    bdConvFromOctets(c,lpIn,dwInSize);
    bdModExp(m,c,d,n);
    if (lpOut)
        bdConvToOctets(m,lpOut,(bdBitLength(n)+7)/8);
    return;
}

SYSLIBFUNC(DWORD) RSA_DecryptBufferFull(RSA_KEY rsaKey,LPBYTE lpBufIn,DWORD dwBufSize,LPBYTE *lppBufOut)
{
    if (!RSA_CheckKey(rsaKey))
        return 0;

    if (!SYSLIB_SAFE::CheckParamRead(lpBufIn,dwBufSize))
        return 0;

    if (!SYSLIB_SAFE::CheckParamWrite(lppBufOut,sizeof(*lppBufOut)))
        return 0;

    DWORD dwHdrSize=0;

    BIGD d,n;

    if (((_RSA_SECRET_KEY*)rsaKey)->bType == RSA_SEC_KEY)
    {
        _RSA_SECRET_KEY *lpPriv=(_RSA_SECRET_KEY*)rsaKey;
        d=lpPriv->d;
        n=lpPriv->n;
    }
    else
    {
        _RSA_PUBLIC_KEY *lpPub=(_RSA_PUBLIC_KEY*)rsaKey;
        d=lpPub->e;
        n=lpPub->n;
    }

    DWORD dwKeyLenInBytes=(bdBitLength(n)+7)/8,
          dwBytesToDecrypt=ALIGN(max(dwKeyLenInBytes,dwBufSize),dwKeyLenInBytes);
    LPBYTE lpOutBuf=(LPBYTE )MemQuickAlloc(dwBytesToDecrypt);
    if (lpOutBuf)
    {
        BIGD m=bdNew(),
             c=bdNew();

        LPBYTE lpIn=lpBufIn,
               lpOut=lpOutBuf;
        while (dwBytesToDecrypt >= dwKeyLenInBytes)
        {
            RSA_DecryptInt(m,c,d,n,lpIn,dwKeyLenInBytes,lpOut);

            lpIn+=dwKeyLenInBytes;
            lpOut+=dwKeyLenInBytes;
            dwBytesToDecrypt-=dwKeyLenInBytes;
        }

        *lppBufOut=lpOutBuf;
        dwHdrSize=ALIGN(max(dwKeyLenInBytes,dwBufSize),dwKeyLenInBytes);

        bdFree(&m);
        bdFree(&c);
    }

    return dwHdrSize;
}

SYSLIBFUNC(DWORD) RSA_DecryptBuffer(RSA_KEY rsaKey,LPBYTE lpBufIn,DWORD dwBufSize,LPBYTE *lppBufOut)
{
    if (!RSA_CheckKey(rsaKey))
        return 0;

    if (!SYSLIB_SAFE::CheckParamRead(lpBufIn,dwBufSize))
        return 0;

    if (!SYSLIB_SAFE::CheckParamWrite(lppBufOut,sizeof(*lppBufOut)))
        return 0;

    DWORD dwSize=0;
    ENCRYPTED_HDR *lpHdr;
    DWORD dwBytesToSkip=RSA_DecryptBufferFull(rsaKey,lpBufIn,sizeof(ENCRYPTED_HDR),(byte**)&lpHdr);
    if (dwBytesToSkip)
    {
        if (lpHdr->dwMagic == RSA_CRYPT_MAGIC)
        {
            DWORD dwDataSize=lpHdr->dwSize;
            LPBYTE lpOut=(byte*)MemQuickAlloc(dwDataSize);
            if (lpOut)
            {
                rc4Full(lpHdr->rc4key,sizeof(lpHdr->rc4key),lpBufIn+dwBytesToSkip,dwDataSize,lpOut);
                if (MurmurHash3(lpOut,dwDataSize) == lpHdr->dwChksum)
                {
                    *lppBufOut=lpOut;
                    dwSize=dwDataSize;
                }
                else
                    MemFree(lpOut);
            }
        }
        MemFree(lpHdr);
    }
    return dwSize;
}

SYSLIBFUNC(BOOL) RSA_DecryptFileW(RSA_KEY rsaKey,LPCWSTR lpFileIn,LPCWSTR lpFileOut)
{
    BOOL bRet=false;
    do
    {
        if (!RSA_CheckKey(rsaKey))
            break;

        if (!SYSLIB_SAFE::CheckStrParamW(lpFileIn,MAX_PATH))
            break;

        if (!SYSLIB_SAFE::CheckStrParamW(lpFileOut,MAX_PATH))
            break;

        HANDLE hFileIn=CreateFileW(lpFileIn,GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL);
        if (hFileIn != INVALID_HANDLE_VALUE)
        {
            HANDLE hMapIn=CreateFileMapping(hFileIn,NULL,PAGE_READONLY,0,0,NULL);
            if (hMapIn)
            {
                LPBYTE lpMapIn=(byte*)MapViewOfFile(hMapIn,FILE_MAP_READ,0,0,0);
                if (lpMapIn)
                {
                    LPBYTE lpBuf;
                    DWORD dwSize=RSA_DecryptBuffer(rsaKey,lpMapIn,GetFileSize(hFileIn,NULL),&lpBuf);
                    if (dwSize)
                    {
                        HANDLE hFileOut=CreateFileW(lpFileOut,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
                        if (hFileOut != INVALID_HANDLE_VALUE)
                        {
                            DWORD tmp;
                            WriteFile(hFileOut,lpBuf,dwSize,&tmp,NULL);
                            FlushFileBuffers(hFileOut);
                            bRet=true;
                            SysCloseHandle(hFileOut);
                        }
                        MemFree(lpBuf);
                    }
                    UnmapViewOfFile(lpMapIn);
                }
                SysCloseHandle(hMapIn);
            }
            SysCloseHandle(hFileIn);
        }
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) RSA_DecryptFileA(RSA_KEY rsaKey,LPCSTR lpFileIn,LPCSTR lpFileOut)
{
    LPWSTR lpFileInW=StrAnsiToUnicodeEx(lpFileIn,0,NULL),
           lpFileOutW=StrAnsiToUnicodeEx(lpFileOut,0,NULL);

    BOOL bRet=RSA_DecryptFileW(rsaKey,lpFileInW,lpFileOutW);

    MemFree(lpFileInW);
    MemFree(lpFileOutW);
    return bRet;
}

SYSLIBFUNC(BOOL) RSA_CheckBufferSign(RSA_KEY rsaPubKey,LPBYTE lpBufIn,DWORD dwBufSize,LPBYTE lpSign)
{
    BOOL bRet=false;
    do
    {
        if (!RSA_CheckSignBuffRead(rsaPubKey,lpSign))
            break;

        if (!SYSLIB_SAFE::CheckParamRead(lpBufIn,dwBufSize))
            break;

        _RSA_PUBLIC_KEY *lpPublicKey=(_RSA_PUBLIC_KEY*)rsaPubKey;

        byte bMD6[64];
        if (!hash_CalcMD6(lpBufIn,dwBufSize,bMD6))
            break;

        BIGD m0=bdNew();
        if (!m0)
            break;

        BIGD m1=bdNew();
        if (!m1)
        {
            bdFree(&m0);
            break;
        }

        BIGD s=bdNew();
        if (!s)
        {
            bdFree(&m0);
            bdFree(&m1);
            break;
        }

        DWORD dwKeySizeInBytes=(bdBitLength(((_RSA_PUBLIC_KEY*)rsaPubKey)->n)+7)/8;
        RSA_DecryptInt(m0,s,lpPublicKey->e,lpPublicKey->n,lpSign,dwKeySizeInBytes,NULL);

        bdConvFromOctets(m1,bMD6,sizeof(bMD6));

        bRet=(bdCompare(m0,m1) == 0);

        bdFree(&m0);
        bdFree(&m1);
        bdFree(&s);
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) RSA_CheckFileSignW(RSA_KEY rsaPubKey,LPCWSTR lpFile,LPBYTE lpSign)
{
    BOOL bRet=false;
    do
    {
        if (!SYSLIB_SAFE::CheckStrParamW(lpFile,MAX_PATH))
            break;

        if (!RSA_CheckSignBuffRead(rsaPubKey,lpSign))
            break;

        HANDLE hFile=CreateFileW(lpFile,GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            HANDLE hMap=CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,NULL);
            if (hMap)
            {
                LPBYTE lpMap=(byte*)MapViewOfFile(hMap,FILE_MAP_READ,0,0,0);
                if (lpMap)
                {
                    bRet=RSA_CheckBufferSign(rsaPubKey,lpMap,GetFileSize(hFile,NULL),lpSign);
                    UnmapViewOfFile(lpMap);
                }
                SysCloseHandle(hMap);
            }
            SysCloseHandle(hFile);
        }
    }
    while (false);
    return bRet;
}

SYSLIBFUNC(BOOL) RSA_CheckFileSignA(RSA_KEY rsaPubKey,LPCSTR lpFile,LPBYTE lpSign)
{
    LPWSTR lpFileNameW=StrAnsiToUnicodeEx(lpFile,0,NULL);

    BOOL bRet=RSA_CheckFileSignW(rsaPubKey,lpFileNameW,lpSign);

    MemFree(lpFileNameW);
    return bRet;
}

SYSLIBFUNC(void) RSA_DestroyKey(RSA_KEY rsaKey)
{
    if (RSA_CheckKey(rsaKey))
    {
        if (((_RSA_SECRET_KEY*)rsaKey)->bType == RSA_SEC_KEY)
        {
            _RSA_SECRET_KEY *lpSecKey=(_RSA_SECRET_KEY*)rsaKey;
            bdFree(&lpSecKey->n);
            bdFree(&lpSecKey->e);
            bdFree(&lpSecKey->d);
        }
        else if (((_RSA_PUBLIC_KEY*)rsaKey)->bType == RSA_PUB_KEY)
        {
            _RSA_PUBLIC_KEY *lpPubKey=(_RSA_PUBLIC_KEY*)rsaKey;
            bdFree(&lpPubKey->n);
            bdFree(&lpPubKey->e);
        }
        MemFree(rsaKey);
    }
    return;
}

SYSLIBFUNC(DWORD) RSA_DumpKey(RSA_KEY rsaKey,LPBYTE lpBuf)
{
    if (!RSA_CheckKey(rsaKey))
        return 0;

    DWORD dwKeySize=0;

    if (((_RSA_SECRET_KEY*)rsaKey)->bType == RSA_SEC_KEY)
    {
        _RSA_SECRET_KEY *lpSecKey=(_RSA_SECRET_KEY*)rsaKey;
        _RSA_SECRET_KEY_DUMP *lpSecDmp=(_RSA_SECRET_KEY_DUMP*)lpBuf;

        if (!SYSLIB_SAFE::CheckParamWrite(lpSecDmp,sizeof(*lpSecDmp)))
            return 0;

        lpSecDmp->hdr.dwMagic=RSA_KEY_MAGIC;
        lpSecDmp->hdr.bType=RSA_SEC_KEY;

        lpSecDmp->hdr.dwKeyLen=bdBitLength(lpSecKey->n);
        DWORD dwSizeInBytes=(lpSecDmp->hdr.dwKeyLen+7)/8;

        LPBYTE lpN=lpSecDmp->bN;
        bdConvToOctets(lpSecKey->n,lpN,dwSizeInBytes);

        LPBYTE lpE=lpN+dwSizeInBytes;
        bdConvToOctets(lpSecKey->e,lpE,dwSizeInBytes);

        lpSecDmp->hdr.dwKeyID=MurmurHash3(lpN,dwSizeInBytes*2);

        LPBYTE lpD=lpE+dwSizeInBytes;
        bdConvToOctets(lpSecKey->d,lpD,dwSizeInBytes);

        dwKeySize=sizeof(_RSA_KEY_DUMP_COMMON_HDR)+dwSizeInBytes*3;
    }
    else if (((_RSA_PUBLIC_KEY*)rsaKey)->bType == RSA_PUB_KEY)
    {
        _RSA_PUBLIC_KEY *lpPubKey=(_RSA_PUBLIC_KEY*)rsaKey;
        _RSA_PUBLIC_KEY_DUMP *lpPubDmp=(_RSA_PUBLIC_KEY_DUMP*)lpBuf;

        if (!SYSLIB_SAFE::CheckParamWrite(lpPubDmp,sizeof(*lpPubDmp)))
            return 0;

        lpPubDmp->hdr.dwMagic=RSA_KEY_MAGIC;
        lpPubDmp->hdr.bType=RSA_PUB_KEY;

        lpPubDmp->hdr.dwKeyLen=bdBitLength(lpPubKey->n);
        DWORD dwSizeInBytes=(lpPubDmp->hdr.dwKeyLen+7)/8;

        LPBYTE lpN=lpPubDmp->bN;
        bdConvToOctets(lpPubKey->n,lpN,dwSizeInBytes);

        LPBYTE lpE=lpN+dwSizeInBytes;
        bdConvToOctets(lpPubKey->e,lpE,dwSizeInBytes);

        lpPubDmp->hdr.dwKeyID=MurmurHash3(lpN,dwSizeInBytes*2);

        dwKeySize=sizeof(_RSA_KEY_DUMP_COMMON_HDR)+dwSizeInBytes*2;
    }
    return dwKeySize;
}

SYSLIBFUNC(RSA_KEY) RSA_LoadKeyFromDump(LPBYTE lpBuf,DWORD dwSize)
{
    RSA_KEY rsaKey=NULL;
    if (SYSLIB_SAFE::CheckParamRead(lpBuf,dwSize))
    {
        _RSA_KEY_DUMP_COMMON_HDR *lpHdr=(_RSA_KEY_DUMP_COMMON_HDR *)lpBuf;
        if (lpHdr->dwMagic == RSA_KEY_MAGIC)
        {
            DWORD dwKeyLenInBytes=(lpHdr->dwKeyLen+7)/8;
            if (lpHdr->bType == RSA_PUB_KEY)
            {
                if (dwSize == sizeof(_RSA_KEY_DUMP_COMMON_HDR)+dwKeyLenInBytes*2)
                {
                    rsaKey=(RSA_KEY)MemAlloc(sizeof(_RSA_PUBLIC_KEY));
                    if (rsaKey)
                    {
                        _RSA_PUBLIC_KEY *lpPubKey=(_RSA_PUBLIC_KEY*)rsaKey;
                        lpPubKey->bType=RSA_PUB_KEY;

                        LPBYTE lpN=((_RSA_PUBLIC_KEY_DUMP*)lpHdr)->bN;
                        lpPubKey->n=bdNew();
                        bdConvFromOctets(lpPubKey->n,lpN,dwKeyLenInBytes);

                        LPBYTE lpE=lpN+dwKeyLenInBytes;
                        lpPubKey->e=bdNew();
                        bdConvFromOctets(lpPubKey->e,lpE,dwKeyLenInBytes);
                    }
                }
            }
            else if (lpHdr->bType == RSA_SEC_KEY)
            {
                if (dwSize == sizeof(_RSA_KEY_DUMP_COMMON_HDR)+dwKeyLenInBytes*3)
                {
                    rsaKey=(RSA_KEY)MemAlloc(sizeof(_RSA_SECRET_KEY));
                    if (rsaKey)
                    {
                        _RSA_SECRET_KEY *lpSecKey=(_RSA_SECRET_KEY*)rsaKey;
                        lpSecKey->bType=RSA_SEC_KEY;

                        LPBYTE lpN=((_RSA_PUBLIC_KEY_DUMP*)lpHdr)->bN;
                        lpSecKey->n=bdNew();
                        bdConvFromOctets(lpSecKey->n,lpN,dwKeyLenInBytes);

                        LPBYTE lpE=lpN+dwKeyLenInBytes;
                        lpSecKey->e=bdNew();
                        bdConvFromOctets(lpSecKey->e,lpE,dwKeyLenInBytes);

                        LPBYTE lpD=lpE+dwKeyLenInBytes;
                        lpSecKey->d=bdNew();
                        bdConvFromOctets(lpSecKey->d,lpD,dwKeyLenInBytes);
                    }
                }
            }
        }
    }
    return rsaKey;
}

SYSLIBFUNC(RSA_KEY) RSA_GetPublicKeyFromPrivate(RSA_KEY rsaPriv)
{
    if (!RSA_CheckKey(rsaPriv))
        return NULL;

    RSA_KEY rsaPub=NULL;
    if (((_RSA_SECRET_KEY*)rsaPriv)->bType == RSA_SEC_KEY)
    {
        rsaPub=(RSA_KEY)MemAlloc(sizeof(_RSA_PUBLIC_KEY));
        if (rsaPub)
        {
            _RSA_PUBLIC_KEY *lpPubKey=(_RSA_PUBLIC_KEY*)rsaPub;
            lpPubKey->bType=RSA_PUB_KEY;

            lpPubKey->n=bdNew();
            bdSetEqual(lpPubKey->n,((_RSA_SECRET_KEY*)rsaPriv)->n);

            lpPubKey->e=bdNew();
            bdSetEqual(lpPubKey->e,((_RSA_SECRET_KEY*)rsaPriv)->e);
        }
    }
    return rsaPub;
}

SYSLIBFUNC(DWORD) RSA_GetKeyLen(RSA_KEY rsaKey)
{
    if (!RSA_CheckKey(rsaKey))
        return 0;

    return bdBitLength(((_RSA_PUBLIC_KEY*)rsaKey)->n);
}

SYSLIBFUNC(BOOL) RSA_IsSecretKey(RSA_KEY rsaKey)
{
    if (!RSA_CheckKey(rsaKey))
        return false;

    return (((_RSA_PUBLIC_KEY*)rsaKey)->bType == RSA_SEC_KEY);
}

