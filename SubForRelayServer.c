#include <arpa/inet.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include "common.h"

int addrcheck(const unsigned char ip[], const unsigned char addr[][4], int size)
{

    int i;

    for (i = 0; i < size; i++)
    {
        if (!memcmp(ip, &addr[i][0], 4))
        {
            return 1;
        }
    }

    return 0;
}


char *dummyhtml()
{

    int size = 1024;
    char *str;
    char dummy[size];

    str = (char *)malloc(size);
    if (str == NULL)
    {
        return NULL;
    }
    memset(str, '\0', size);
    memset(dummy, '\0', size);

    sprintf(dummy, "<html><body><h2>access denied</h2></html>");

    sprintf(str, "HTTP/1.1 200 OK\r\n");
    sprintf(str, "%sContent-Length: %ld\r\n", str, strlen(dummy));
    sprintf(str, "%sConnection: close\r\n", str);
    sprintf(str, "%sContent-Type: text/html\r\n\r\n", str);
    sprintf(str, "%s%s", str, dummy);

    return str;
}


int getiplist(unsigned char addr[][4], int size, const char *fname)
{

    FILE *fp;
    char buf[128];
    int ip[4];
    int s = 0, res, i;

    fp = fopen(fname, "r");
    if (fp == NULL)
    {
        return 0;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL)
    {
        res = sscanf(buf, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);

        if (res == 4)
        {
            for (i = 0; i < 4; ++i)
            {
                addr[s][i] = (unsigned char)ip[i];
            }
            s++;
            if (s >= size)
            {
                break;
            }
        }
    }
    fclose(fp);

    return s;
}


unsigned short mkchecksum(const unsigned char data[], int size)
{

    unsigned int sum = 0;
    int i;

    for (i = 0; i < size; i += 2)
    {
        
        sum += (data[i] << 8);
        if (i + 1 < size)
        {
            
            sum += data[i + 1];
        }

        if (sum > 0xffff)
            sum = (sum >> 16) + (sum & 0xffff);
        if (sum > 0xffff)
            sum = (sum >> 16) + (sum & 0xffff);
    }

    return 0xffff - sum;
}


unsigned short mktcpchecksum(const unsigned char data[])
{

    unsigned int iplen, tcplen, len;
    unsigned short tmp;
    unsigned char *buf;

    iplen = (data[0] & 0x0F) * 4;
    tcplen = (data[iplen + 12] >> 4) * 4;
    len = (data[2] << 8) + data[3] - iplen - tcplen;

    buf = (unsigned char *)malloc(iplen + tcplen + len);
    if (buf == NULL)
    {
        printf("malloc error.\n");
        exit(1);
    }

    
    memcpy(buf, data + 12, 8);
    buf[8] = 0;
    buf[9] = 6;
    tmp = tcplen + len;
    buf[10] = tmp >> 8;
    buf[11] = tmp & 0xff;

    
    memcpy(buf + 12, data + iplen, tcplen + len);

    buf[12 + 16] = 0;
    buf[12 + 17] = 0;
    tmp = mkchecksum(buf, 12 + tcplen + len);

    free(buf);

    return tmp;
}


int sockfin(const char *ifname, int sock)
{

    struct ifreq ifr;
    struct packet_mreq mreq;
  
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl SIOCGIFINDEX");
        exit(1);
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_ifindex = ifr.ifr_ifindex;
    if ((setsockopt(sock, SOL_PACKET, PACKET_DROP_MEMBERSHIP, (void *)&mreq, sizeof(mreq))) < 0)
    {
        perror("setsockopt");
        exit(1);
    }
    printf("%s @ normal mode\n", ifname);

    return 0;
}


int sockinit(const char *ifname)
{

    int sock;
    struct ifreq ifr;
    struct packet_mreq mreq;
    struct sockaddr_ll sll;

    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl SIOCGIFINDEX");
        exit(1);
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_ifindex = ifr.ifr_ifindex;
    if ((setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq))) < 0)
    {
        perror("setsockopt");
        exit(1);
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    {
        perror("bind");
        exit(1);
    }

    printf("%s @ promiscuous mode\n", ifname);

    return sock;
}
