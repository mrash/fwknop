#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#ifdef  _BPF_
#include <sys/param.h>
#endif

#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <sys/uio.h>

#ifdef _LINUX_

#include <stdio.h>

#ifdef  _GLIBC_

#include <net/if_packet.h>
#include <netinet/if_ether.h>
#include <net/if.h>

#else 

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>

#endif /*_GLIBC_*/

#else 

#define MAX_IFS     32

#include <sys/time.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include "ip.h"

#ifdef _BSDRAW_

unsigned short in_cksum (unsigned short*,int);

#endif
#endif /*_LINUX_*/

#ifdef _BPF_

static int
get_ether_addr(u_long ipaddr, u_char *hwaddr)
{
    struct ifreq *ifr, *ifend, *ifp;
    u_long ina, mask;
    struct sockaddr_dl *dla;
    struct ifreq ifreq;
    struct ifconf ifc;
    struct ifreq ifs[MAX_IFS];
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        perror("socket");

    ifc.ifc_len = sizeof(ifs);
    ifc.ifc_req = ifs;
    if (ioctl(s, SIOCGIFCONF, &ifc) < 0) {
        close(s);
        return 0;
    }
    ifend = (struct ifreq *) (ifc.ifc_buf + ifc.ifc_len);
    for (ifr = ifc.ifc_req; ifr < ifend; ) {
        if (ifr->ifr_addr.sa_family == AF_INET) {
            ina = ((struct sockaddr_in *) 
                &ifr->ifr_addr)->sin_addr.s_addr;
            strncpy(ifreq.ifr_name, ifr->ifr_name, 
                sizeof(ifreq.ifr_name));
            if (ioctl(s, SIOCGIFFLAGS, &ifreq) < 0)
                continue;
            if ((ifreq.ifr_flags &
                 (IFF_UP|IFF_BROADCAST|IFF_POINTOPOINT|
                    IFF_LOOPBACK|IFF_NOARP))
                 != (IFF_UP|IFF_BROADCAST))
                goto nextif;
            if (ioctl(s, SIOCGIFNETMASK, &ifreq) < 0)
                continue;
            mask = ((struct sockaddr_in *)
                &ifreq.ifr_addr)->sin_addr.s_addr;
            if ((ipaddr & mask) != (ina & mask))
                goto nextif;
            break;
        }
nextif:
        ifr = (struct ifreq *) 
            ((char *)&ifr->ifr_addr + ifr->ifr_addr.sa_len);
    }

    if (ifr >= ifend) {
        close(s);
        return 0;
    }
    ifp = ifr;
    for (ifr = ifc.ifc_req; ifr < ifend; ) {
        if (strcmp(ifp->ifr_name, ifr->ifr_name) == 0
            && ifr->ifr_addr.sa_family == AF_LINK) {
            dla = (struct sockaddr_dl *) &ifr->ifr_addr;
            memcpy(hwaddr,LLADDR(dla),dla->sdl_alen);
            close (s);
            return dla->sdl_alen;
        }
        ifr = (struct ifreq *) 
            ((char *)&ifr->ifr_addr + ifr->ifr_addr.sa_len);
    }
    return 0;
}

#endif /*_BPF_*/
                                            
void send_eth_packet(int fd, char* eth_device, u_char *pkt, int len, int flag)
{
    int retval;

#ifndef _BPF_

    struct msghdr msg;
    struct sockaddr_pkt spkt;
    struct iovec iov;
    strcpy((char *)spkt.spkt_device, eth_device);
    spkt.spkt_protocol = htons(ETH_P_IP);
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &spkt;
    msg.msg_namelen = sizeof(spkt);
    msg.msg_iovlen = 1;
    msg.msg_iov = &iov;
    iov.iov_base = pkt;
    iov.iov_len = len;

    retval = sendmsg(fd, &msg, 0);
#else   

#ifdef _BSDRAW_
    if (flag) {
        ((struct iphdr *)(pkt + 14))->tot_len
            = htons(((struct iphdr *)(pkt + 14))->tot_len);        
        ((struct iphdr *)(pkt + 14))->frag_off
            = htons(((struct iphdr *)(pkt + 14))->frag_off);        
        ((struct iphdr *)(pkt + 14))->check = 0;        
        ((struct iphdr *)(pkt + 14))->check 
            = in_cksum((unsigned short*)(pkt + 14), 
                    4*((struct iphdr *)(pkt + 14))->ihl);
    }
#endif
    retval = write(fd,pkt,len);
#endif
    if (retval < 0) {
        croak("send_eth_packet");
    }
}


int mac_disc(unsigned int addr,unsigned char * eth_mac) {

#ifndef _BPF_

    struct arpreq
    {
        struct sockaddr arp_pa;     
        struct sockaddr arp_ha;     
        int arp_flags;          
        struct sockaddr arp_netmask;
        char arp_dev[16];
    } req;
    int fd;
    fd = socket(AF_INET,SOCK_DGRAM,0);
    memset((char*)&req,0,sizeof(req));
    req.arp_pa.sa_family = AF_INET;
    *(unsigned int*)(req.arp_pa.sa_data+2) = htonl(addr);
    if (ioctl(fd,SIOCGARP,&req) < 0) {
        close(fd);
        return 0;
    }
    memcpy(eth_mac, req.arp_ha.sa_data, ETH_ALEN);
    close(fd);
    return 1;

#else
        
    int mib[6],found;
    size_t needed;
    char *lim, *buf, *next;
    struct rt_msghdr *rtm;
    struct sockaddr_inarp *sin;
    struct sockaddr_dl *sdl;
    extern int h_errno;
    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_INET;
    mib[4] = NET_RT_FLAGS;
    mib[5] = RTF_LLINFO;
    found = 0;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
        perror("route-sysctl-estimate");
    if ((buf = (char*)malloc(needed)) == NULL)
        perror("malloc");
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
        perror("actual retrieval of routing table");
    lim = buf + needed;
    for (next = buf; next < lim; next += rtm->rtm_msglen) {
        rtm = (struct rt_msghdr *)next;
        sin = (struct sockaddr_inarp *)(rtm + 1);
        sdl = (struct sockaddr_dl *)(sin + 1);
        if (addr != ntohl(sin->sin_addr.s_addr))
            continue;
        found = 1;
    }
    free(buf);
    if (!found) {
        return 0;
    } else {
        memcpy(eth_mac,LLADDR(sdl),sdl->sdl_alen);
    return 1;  
    }
#endif
}


int
tap(char *dev,unsigned int *my_eth_ip,unsigned char *my_eth_mac)
{
 
    int fd,v,s;
    struct ifreq ifr;
    (void)strcpy(ifr.ifr_name, dev);
#ifndef _BPF_

    if ((fd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0) {
        croak("(tap) SOCK_PACKET allocation problems [fatal]");
    }
#else
    if ((fd = bpf_open()) < 0)
        croak("(tap) fd < 0");
    v = 32768;
    (void) ioctl(fd, BIOCSBLEN, (caddr_t)&v);
    if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) < 0) {
        croak("(tap) BIOCSETIF problems [fatal]");
    }
    s = socket(AF_INET, SOCK_DGRAM, 0);
#endif

#ifndef _BPF_
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        croak("(tap) Can't get interface IP address");
    }
#else
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        close(s);
        croak("(tap) Can't get interface IP address");
    }
#endif
 
    *my_eth_ip = ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr);

#ifndef _BPF_
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        croak("(tap) Can't get interface HW address");
    }
    memcpy(my_eth_mac, ifr.ifr_hwaddr.sa_data,ETH_ALEN);
#else
    close(s);
    if (!get_ether_addr(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr,
        my_eth_mac)) {
        croak("(tap) Can't get interface HW address");
    }
#endif
    return fd;
}

