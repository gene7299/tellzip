#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include "zlib.h"
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#define _LARGEFILE64_SOURCE     /* See feature_test_macros(7) */
//#define TELLZIP_DBG(fmt, args...)   do{if(1){  printf("[] "fmt, ## args); fflush(stdout);}}while(0)
#define TELLZIP_DBG(fmt, args...)   do{}while(0)


#define CHUNK 16384

/* PKZIP header definitions */
#define ZIPMAG 0x4b50           /* two-byte zip lead-in */
#define LOCREM 0x0403           /* remaining two bytes in zip signature */
/*
 *  * Header signatures
 *   */
#define LOCSIG 0x04034b50L          /* "PK\003\004" */
#define EXTSIG 0x08074b50L          /* "PK\007\008" */
#define CENSIG 0x02014b50L          /* "PK\001\002" */
#define ENDSIG 0x06054b50L          /* "PK\005\006" */
#define LOCFLG 4                /* offset of bit flag */
#define  CRPFLG 1               /*  bit for encrypted entry */
#define  EXTFLG 8               /*  bit for extended local header */
#define LOCHOW 6                /* offset of compression method */
#define LOCTIM 8                /* file mod time (for decryption) */
#define LOCCRC 12               /* offset of crc */
#define LOCSIZ 16               /* offset of compressed size */
#define LOCLEN 20               /* offset of uncompressed length */
#define LOCFIL 24               /* offset of file name field length */
#define LOCEXT 26               /* offset of extra field length */
#define LOCHDR 28               /* size of local header, including LOCREM */
#define EXTHDR 16               /* size of extended local header, inc sig */
#define CENHDR 46
#define ENDHDR 22

#define CH(b, n) (((unsigned char *)(b))[n])
#define SH(b, n) (CH(b, n) | (CH(b, n+1) << 8))
#define LG(b, n) (SH(b, n) | (SH(b, n+2) << 16))
#define GETSIG(b) LG(b, 0)

/*
 *  * Macros for getting end of central directory header (END) fields
 *   */
#define ENDSUB(b) SH(b, 8)          /* number of entries on this disk */
#define ENDTOT(b) SH(b, 10)         /* total number of entries */
#define ENDSIZ(b) LG(b, 12)         /* central directory size */
#define ENDOFF(b) LG(b, 16)         /* central directory offset */
#define ENDCOM(b) SH(b, 20)         /* size of zip file comment */

/*
 *  * Macros for getting central directory header (CEN) fields
 *   */
#define CENVEM(b) SH(b, 4)          /* version made by */
#define CENVER(b) SH(b, 6)          /* version needed to extract */
#define CENFLG(b) SH(b, 8)          /* general purpose bit flags */
#define CENHOW(b) SH(b, 10)         /* compression method */
#define CENTIM(b) LG(b, 12)         /* modification time */
#define CENCRC(b) LG(b, 16)         /* crc of uncompressed data */
#define CENSIZ(b) LG(b, 20)         /* compressed size */
#define CENLEN(b) LG(b, 24)         /* uncompressed size */
#define CENNAM(b) SH(b, 28)         /* length of filename */
#define CENEXT(b) SH(b, 30)         /* length of extra field */
#define CENCOM(b) SH(b, 32)         /* file comment length */
#define CENDSK(b) SH(b, 34)         /* disk number start */
#define CENATT(b) SH(b, 36)         /* internal file attributes */
#define CENATX(b) LG(b, 38)         /* external file attributes */
#define CENOFF(b) LG(b, 42)         /* offset of local header */

char *entries[1024];
unsigned int totalentry;
/* report a zlib or i/o error */
#if 0
void zerr(int ret)
{
    fputs("ziptest: ", stderr);
    switch (ret) {
    case Z_ERRNO:
        if (ferror(stdin))
            fputs("error reading stdin\n", stderr);
        if (ferror(stdout))
            fputs("error writing stdout\n", stderr);
        break;
    case Z_STREAM_ERROR:
        fputs("invalid compression level\n", stderr);
        break;
    case Z_DATA_ERROR:
        fputs("invalid or incomplete deflate data\n", stderr);
        break;
    case Z_MEM_ERROR:
        fputs("out of memory\n", stderr);
        break;
    case Z_VERSION_ERROR:
        fputs("zlib version mismatch!\n", stderr);
    }
}
#endif
unsigned int readFully(FILE* fd, void *buf, long long int len)
{
	unsigned char *bp = (unsigned char *)buf;
	while (len > 0) {
		long long int n = (long long int)fread((char*)bp, 1, len,fd);
		if (n <=0) {
			return -1;
		}
		bp += n;
		len -= n;
	}
	return 0;
}

unsigned int findEND(FILE* fd, void *endbuf , char *filepath)
{
	unsigned char buf[ENDHDR *2];
	off64_t len,pos;
#if 0
    struct stat stat_buf;
    int rc = stat(filepath , &stat_buf);
	if(rc == 0)
	{
		len = pos = stat_buf.st_size;
		TELLZIP_DBG("pos %u %d\n", pos,pos);
	}else
	{
		len = 0;
	}
#endif
	fseeko64(fd, 0, SEEK_END);
	pos = ftello64(fd);
	len = pos;
	TELLZIP_DBG("zip length %u %d\n", pos,pos);

	/*
     * Search backwards ENDHDR bytes at a time from end of file stopping
     * when the END header has been found.
     */
	memset(buf, 0, sizeof(buf));
	while (len - pos < 0xFFFF) {
		unsigned char *bp;
		long long int count = 0xFFFF - (len - pos);
		if (count > ENDHDR) {
            count = ENDHDR;
        }
        /* Shift previous block */
        memcpy(buf + count, buf, count);
		/* Update position and read next block */
        pos -= count;
		fseeko64(fd, pos, SEEK_SET);
		readFully(fd, buf, count);
		/* Now scan the block for END header signature */
        for (bp = buf; bp < buf + count; bp++) {
            if (GETSIG(bp) == ENDSIG) {
                /* Check for possible END header */
                long long int endpos = pos + (long int)(bp - buf);
                long long int clen = ENDCOM(bp);
                if (endpos + ENDHDR + clen == len) {
                    /* Found END header */
                    memcpy(endbuf, bp, ENDHDR);
					fseeko64(fd, (unsigned int)endpos+ENDHDR, SEEK_SET);
					if (clen > 0) {
						char *comment = (char*)malloc(clen+1);
						readFully(fd, comment, clen);
						comment[clen] = '\0';
					}
					return (unsigned int)endpos;
				} else { // added for '0' padding
					memcpy(endbuf, bp, ENDHDR);
					return (unsigned int)endpos;
				}
			}
		}
	}
	return 0; //END header not found
}

unsigned int readCEN(FILE* fd, char *filepath)
{
	unsigned char endbuf[ENDHDR];
	char *cenbuf, *cp;
	long long int locpos, cenpos, cenoff, cenlen, total, count, i;
	long long int endpos = findEND(fd, endbuf, filepath);
	long long int namelen = 512 + 1;
	char namebuf[512 + 1];
	char *name = namebuf;

	TELLZIP_DBG("END header is at %d\n", endpos);
	/* Get position and length of central directory */
	cenlen = ENDSIZ(endbuf);
	cenpos = endpos - cenlen;

	TELLZIP_DBG("postion & length of central directory is %x & %d\n", cenlen, cenpos);
	cenoff = ENDOFF(endbuf);
	locpos = cenpos - cenoff;
	totalentry = ENDTOT(endbuf);
	TELLZIP_DBG("total number of central directory entries %d\n", totalentry);

	fseeko64(fd, cenpos, SEEK_SET);
	cenbuf = (char *)malloc(cenlen);
	readFully(fd, cenbuf, cenlen);
	long long int sum = 0;
	//entries = (char*)malloc(total);
	for (count = 0, cp = cenbuf; count < totalentry; count++) {
		long long int method, nlen, clen, elen, size, csize, crc;
		nlen = CENNAM(cp);
		elen = CENEXT(cp);
		clen = CENCOM(cp);
		size = CENLEN(cp);
		csize = CENSIZ(cp);
		crc = CENCRC(cp);
		if (namelen < nlen + 1) { /* grow temp buffer */
            do
                namelen = namelen * 2;
            while (namelen < nlen + 1);
            if (name != namebuf)
                free(name);
            name = (char *)malloc(namelen);
	        if (name == 0) {
    		    free(cenbuf);
		        return -1;
        	}
        }
	    memcpy(name, cp+CENHDR, nlen);
        name[nlen] = 0;
	entries[count] = (char*)malloc(nlen);
		memcpy(entries[count], name, nlen);

		cp += (CENHDR + nlen + elen + clen);
		sum += size;
	}
	TELLZIP_DBG("sum=%u\n",sum);
	return sum;//cenpos;
}

int main(int argc, char **argv)
{
	if(argc!=2)
	{
		printf("fail1\n");
		//printf("uc=0\n");
		return 0;
	}
	if(argv[1]==NULL)
	{
		printf("fail2\n");
		//printf("uc=0\n");
		return 0;
	}

	unsigned int uc = 0; //uncompressed size
	char str[512] = "data.zip";
	char *loc;
	char *zipfile;
	int errnum;
	unsigned short n;
	unsigned char h[LOCHDR];
	int ret;
	int i;
	int isFail = 0;

	memset(str,0,512);
	strcpy(str,argv[1]);

	errno = 0;
	FILE* file = fopen64(str, "r");
	//int file = open(str,O_RDONLY|O_LARGEFILE)
	if (file < 0)
	{
		printf("fail9\n");
		isFail = 1;
		//printf("uc=0\n");//printf("cannot open zipfile. errno %d\n",errno);
		return 0;
	}
	else
	{
		//printf("file %p\n", file);
	}
#if 0
	unsigned int size = 0;
    struct stat stat_buf;
    int rc = stat(str , &stat_buf);
	if(rc == 0)
	{
		size = stat_buf.st_size;
		TELLZIP_DBG("File size =  %u %d\n", size,size);
	}else
	{

		printf("fail3\n");

		//printf("uc=0\n");//printf("cannot open zipfile. errno %d\n",errno);
		//return 0;
	}
#endif

	n = getc(file);
	n |= getc(file) << 8;
	if (n == ZIPMAG)
	{
		if (fread((char *)h, 1, LOCHDR, file) != LOCHDR || SH(h,0) != LOCREM) {
			TELLZIP_DBG("invalid zipfile");
			printf("fail4\n");
			isFail = 1;
		}
		else{
			TELLZIP_DBG("valid zip or jar file\n");
			isFail = 0;
		}
	} else
	{
		TELLZIP_DBG("input not a zip file\n");
		printf("fail6\n");
		isFail = 1;
	}

	if(isFail == 1)
	{
		//printf("uc=0\n");
		return 0;
	}else
	{
		uc = readCEN(file,str);
		if(uc == 0)
		{
			printf("fail7\n");
		}else
		{
			printf("uc=%u\n",uc);
		}

	}

}
