#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "common.h"


int sockWan, sockLan;
char ifWan[32] = "";
char ifLan[32] = "";

void systemfin(int n);                
int TCPpacketCtrl(const char data[]); 

int sendDummyPacket(INFO dest, INFO src, const char *data, int syn, int fin);
int dspcheck(const char data[], int sock);

int main(int argc, char *argv[])
{

    fd_set fdset;
    int n, recv, send, byte, size;
    char buf[1024 * 128];
    char *fname;
    unsigned char deny[128][4];

    if (argc >= 4)
    {
        strcpy(ifWan, argv[1]);
        strcpy(ifLan, argv[2]);
        fname = argv[3];
    }
    else
    {
        printf("./a.out WAN-NIC名 LAN-NIC名 リスト\n");
        printf("./a.out eth0 eth1 listfile\n");
        return 0;
    }

    size = getiplist(deny, 128, fname);

    signal(SIGINT, systemfin);

    sockWan = sockinit(ifWan);
    sockLan = sockinit(ifLan);

    while (1)
    {
        FD_ZERO(&fdset);
        FD_SET(sockWan, &fdset);
        FD_SET(sockLan, &fdset);
        n = select(8, &fdset, NULL, NULL, NULL);
        if (n < 0)
        {
            perror("select");
            break;
        }
        else if (n > 0)
        {
            if (FD_ISSET(sockWan, &fdset) == 1)
            {
                recv = sockWan;
                send = sockLan;
            }
            else if (FD_ISSET(sockLan, &fdset) == 1)
            {
                recv = sockLan;
                send = sockWan;
            }
            else
            {
                perror("select");
                break;
            }

            if ((byte = read(recv, buf, sizeof(buf))) <= 0)
            {
                perror("read");
                break;
            }

            if (recv == sockLan && buf[13] == 0x00 && buf[23] == 6)
            {
                if (addrcheck(buf + 14 + 16, deny, size))
                {
                    TCPpacketCtrl(buf);
                }
                else
                {
                    write(sockWan, buf, byte);
                }
            }
            else
            {
                write(send, buf, byte);
            }
        }
    }

    sockfin(ifLan, sockWan);
    sockfin(ifWan, sockLan);

    return 0;
}

void systemfin(int n)
{

    printf("\nCtrl + C\n");

    sockfin(ifWan, sockWan);
    sockfin(ifLan, sockLan);

    exit(0);
}


int TCPpacketCtrl(const char data[])
{

    MYETHER ether;
    MYIP ip;
    MYTCP tcp;
    unsigned int iplen, tcplen, len;
    INFO dest, src;

    char tmp[1460];

#ifdef DEBUG
    dspcheck(data, sockLan);
#endif

    memcpy(ether.raw, data, 14);
    memcpy(ip.raw, data + 14, 20);
    iplen = ip.data.headerLength * 4; 
    memcpy(tcp.raw, data + 14 + iplen, 20);
    tcplen = tcp.data.headerLength * 4;                
    len = ntohs(ip.data.ntotalLength) - iplen - tcplen; 

    memcpy(dest.mac, ether.data.srcMAC, 6);
    memcpy(dest.ip, ip.data.srcIP, 4);
    dest.port = ntohs(tcp.data.nsrcPort);
    memcpy(src.mac, ether.data.destMAC, 6);
    memcpy(src.ip, ip.data.destIP, 4);
    src.port = ntohs(tcp.data.ndestPort);

    if (tcp.data.synFlag)
    {
        dest.num = ntohl(0);
        src.num = ntohl(tcp.data.nseq) + 1;
        sendDummyPacket(dest, src, "", 1, 0);
    }
    else if (tcp.data.finFlag)
    {
        dest.num = ntohl(tcp.data.nack);
        src.num = ntohl(tcp.data.nseq) + 1;
        sendDummyPacket(dest, src, "", 0, 1);
    }
    else if (len > 0)
    {
        dest.num = ntohl(tcp.data.nack);
        src.num = ntohl(tcp.data.nseq) + len;
        sendDummyPacket(dest, src, dummyhtml(), 0, 0);
    }

    return 0;
}

int sendDummyPacket(INFO dest, INFO src, const char *data, int syn, int fin)
{

    int len;
    unsigned char *raw;
    MYIP ip;
    MYTCP tcp;
    unsigned short tmp;
    static unsigned short id = 1;

    len = strlen(data);

    raw = (unsigned char *)malloc(16 + 20 + 20 + len); 
    if (raw == NULL)
    {
        printf("malloc error.\n");
        systemfin(0);
    }

    memcpy(raw, dest.mac, 6);
    memcpy(raw + 6, src.mac, 6);
    raw[12] = 0x08;
    raw[13] = 0x00;

    memset(ip.raw, 0x00, 20);
    ip.data.version = 4;                         
    ip.data.headerLength = 5;                    
    ip.data.ntotalLength = htons(20 + 20 + len); 
    ip.data.nid = htons(id++);                  
    ip.data.mfFlag = 0;                          
    ip.data.dfFlag = 1;                          
    ip.data.ttl = 64;                           
    ip.data.protocol = 6;                      
    memcpy(ip.data.srcIP, src.ip, 4);            
    memcpy(ip.data.destIP, dest.ip, 4);      
    tmp = mkchecksum(ip.raw, 20);
    ip.data.checksum = htons(tmp); 
    memcpy(raw + 14, ip.raw, 20); 


    memset(tcp.raw, 0x00, 20);
    tcp.data.nsrcPort = htons(src.port);   
    tcp.data.ndestPort = htons(dest.port); 
    tcp.data.nseq = htonl(dest.num);       
    tcp.data.nack = htonl(src.num);        
    tcp.data.headerLength = 5;            
    tcp.data.finFlag = fin;
    tcp.data.synFlag = syn;
    tcp.data.ackFlag = 1;
    tcp.data.nwinSize = htons(1460); 
    memcpy(raw + 14 + 20, tcp.raw, 20);


    if (len > 0)
    {
        memcpy(raw + 14 + 20 + 20, data, len);
    }

    tmp = mktcpchecksum(raw + 14);
    raw[14 + 20 + 16] = tmp >> 8;
    raw[14 + 20 + 17] = tmp & 0xff;

    write(sockLan, raw, 14 + 20 + 20 + len);

#ifdef DEBUG
    dspcheck(raw, sockWan);
#endif

    free(raw);

    return 0;
}

int strlength(char *s)
{
    int i = 0;
    while ((*(s + i)) != '\0')
    {
        i++;
    }

    return i;
}
