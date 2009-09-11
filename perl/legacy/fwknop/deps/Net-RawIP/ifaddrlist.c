#ifdef   _LINUX_
#define  _BSD_SOURCE 1
#define  __FAVOR_BSD 1
#endif

#include <sys/param.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>			

#if __STDC__
struct mbuf;
struct rtentry;
#endif

#include <net/if.h>
#include <netinet/in.h>
#include <ctype.h>
#include <errno.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _SOLARIS_
#include <stropts.h>
#include <sys/sockio.h>
#include "solaris.h"
#endif   /* _SOLARIS_ */

#define MAX_IPADDR 32

#include "ifaddrlist.h"	

int
ifaddrlist(register struct ifaddrlist **ipaddrp, register char *errbuf)
{
    register int fd, nipaddr;
#ifdef HAVE_SOCKADDR_SA_LEN
    register int n;
#endif
    register struct ifreq *ifrp, *ifend, *ifnext, *mp;
    register struct sockaddr_in *sin;
    register struct ifaddrlist *al;
    struct ifconf ifc;
    struct ifreq ibuf[MAX_IPADDR], ifr;
    char device[sizeof(ifr.ifr_name) + 1];
    static struct ifaddrlist ifaddrlist[MAX_IPADDR];
    (void)memset(device,0,sizeof(device));   
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        (void)sprintf(errbuf, "socket: %s", strerror(errno));
        return (-1);
    }
    ifc.ifc_len = sizeof(ibuf);
    ifc.ifc_buf = (caddr_t)ibuf;

    if (ioctl(fd,
            SIOCGIFCONF,
            (char *)&ifc) < 0 || ifc.ifc_len < sizeof(struct ifreq))
    {
        (void)sprintf(errbuf, "SIOCGIFCONF: %s", strerror(errno));
        (void)close(fd);
        return (-1);
    }
    ifrp = ibuf;
    ifend = (struct ifreq *)((char *)ibuf + ifc.ifc_len);

    al = ifaddrlist;
    mp = NULL;
    nipaddr = 0;
    for (; ifrp < ifend; ifrp = ifnext)
    {
#ifdef HAVE_SOCKADDR_SA_LEN
        n = ifrp->ifr_addr.sa_len + sizeof(ifrp->ifr_name);
        if (n < sizeof(*ifrp))
        {
            ifnext = ifrp + 1;
        }
        else
        {
            ifnext = (struct ifreq *)((char *)ifrp + n);
        }
        if (ifrp->ifr_addr.sa_family != AF_INET) continue;
#else
        ifnext = ifrp + 1;
#endif
        strncpy(ifr.ifr_name, ifrp->ifr_name, sizeof(ifr.ifr_name));
        if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifr) < 0)
        {
            if (errno == ENXIO) continue;
            (void)sprintf(errbuf,
                        "SIOCGIFFLAGS: %.*s: %s",
                        (int)sizeof(ifr.ifr_name),
                        ifr.ifr_name,
                        strerror(errno));
            (void)close(fd);
            return (-1);
        }

        if ((ifr.ifr_flags & IFF_UP) == 0) continue;
        
        (void)strncpy(device, ifr.ifr_name, sizeof(ifr.ifr_name));
        device[sizeof(device) - 1] = '\0';
        if (ioctl(fd, SIOCGIFADDR, (char *)&ifr) < 0)
        {
            sprintf(errbuf, "SIOCGIFADDR: %s: %s", device, strerror(errno));
            close(fd);
            return (-1);
        }
    
        sin = (struct sockaddr_in *)&ifr.ifr_addr;
        al->addr = ntohl(sin->sin_addr.s_addr);
        al->device = strdup(device);
        al->len = strlen(device);
	++al;
        ++nipaddr;
    }
    (void)close(fd);

    *ipaddrp = ifaddrlist;
    return (nipaddr);
}
