#ifndef __INCLUDE_FUNC_MY__
#define __INCLUDE_FUNC_MY__

typedef struct
{
    unsigned char destMAC[6];
    unsigned char srcMAC[6];
    unsigned char type[2];
} ETHERDATA;

typedef struct
{
    unsigned char headerLength : 4;
    unsigned char version : 4;
    unsigned char service;
    unsigned short ntotalLength;
    unsigned short nid;
    unsigned char offset1 : 6;
    unsigned char dfFlag : 1;
    unsigned char mfFlag : 1;
    unsigned char offset2;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned char srcIP[4];
    unsigned char destIP[4];
} IPDATA;

typedef struct
{
    unsigned short nsrcPort;
    unsigned short ndestPort;
    unsigned int nseq;
    unsigned int nack;
    unsigned char offset1 : 4;
    unsigned char headerLength : 4;
    unsigned char finFlag : 1;
    unsigned char synFlag : 1;
    unsigned char rstFlag : 1;
    unsigned char pshFlag : 1;
    unsigned char ackFlag : 1;
    unsigned char urgFlag : 1;
    unsigned char offset2 : 2;
    unsigned short nwinSize;
    unsigned short checksum;
    unsigned short nurgent;
} TCPDATA;

typedef union
{
    unsigned char raw[14];
    ETHERDATA data;
} MYETHER;

typedef union
{
    unsigned char raw[20];
    IPDATA data;
} MYIP;

typedef union
{
    unsigned char raw[20];
    TCPDATA data;
} MYTCP;

typedef struct
{
    unsigned char mac[6];
    unsigned char ip[4];
    unsigned short port;
    unsigned int num;
} INFO;

int addrcheck(const unsigned char ip[], const unsigned char addr[][4], int size);

char *dummyhtml();

int getiplist(unsigned char addr[][4], int size, const char *fname);

unsigned short mkchecksum(const unsigned char data[], int size);

unsigned short mktcpchecksum(const unsigned char data[]);

int sockfin(const char *ifname, int sock);

int sockinit(const char *ifname);

#endif