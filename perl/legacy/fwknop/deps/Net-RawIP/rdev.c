#include "EXTERN.h"
#include "perl.h"

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))
#define MAX_IFS 32

static int
dev_name(u_int32_t ipaddr, u_char *name)
{
	struct ifreq *ifr, *ifend;
#ifdef HAVE_SOCKADDR_SA_LEN
        register int n;
#endif
	u_long ina,mask,pdst;
	struct sockaddr_dl *dla;
	struct ifreq ifreq;
	struct ifconf ifc;
	struct ifreq ifs[MAX_IFS];
	int s,len,ppp;
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
			ppp = 0;
		        ina = ((struct sockaddr_in *) 
				&ifr->ifr_addr)->sin_addr.s_addr;
			strncpy(ifreq.ifr_name, ifr->ifr_name, 
				sizeof(ifreq.ifr_name));
			if (ioctl(s, SIOCGIFFLAGS, &ifreq) < 0)
				continue;
			if (!(ifreq.ifr_flags & IFF_UP))
				goto nextif;
			if (ifreq.ifr_flags & IFF_POINTOPOINT) ppp = 1; 
			if (ioctl(s, SIOCGIFNETMASK, &ifreq) < 0)
				continue;
			mask = ((struct sockaddr_in *)
				&ifreq.ifr_addr)->sin_addr.s_addr;
			if ((ipaddr & mask) ^ (ina & mask))  {
			   if(!ppp) {
			         goto nextif;
			   }
			   else {
			         if (ioctl(s, SIOCGIFDSTADDR, &ifreq) < 0)
				     continue;
			         pdst = ((struct sockaddr_in *)
				          &ifreq.ifr_addr)->sin_addr.s_addr;
			         if (pdst ^ ipaddr) goto nextif;
			   }
			}
			break;
		}
nextif:
#ifdef HAVE_SOCKADDR_SA_LEN
		 n = ifr->ifr_addr.sa_len + sizeof(ifr->ifr_name);
                 if (n < sizeof(*ifr))
                 {
                  ifr = ifr + 1;
                 }
                 else
                 {
                  ifr = (struct ifreq *)((char *)ifr + n);
                 }
#else
                ifr = ifr + 1; 
#endif
	}

	if (ifr >= ifend) {
		close(s);
		return 0;
	}
        close(s);
        len = strlen(ifr->ifr_name);
        memcpy(name,ifr->ifr_name,len);
        return len;
}
 

int
ip_rt_dev(u_int32_t addr,u_char *name)
{
	size_t needed;
	int mib[6], rlen, seqno;
	char *buf, *next, *lim,i;
	register struct rt_msghdr *rtm;
	struct sockaddr *sa ;
        struct sockaddr_in *sin; 
        u_int32_t devip = 0,dest,mask,gate,local;
        char *cp;
        local = htonl(0x7f000001);
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;		
	mib[3] = 0;	
	mib[4] = NET_RT_DUMP;
	mib[5] = 0;		
	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0){
		croak("route-sysctl-estimate");
        }
	if ((buf = malloc(needed)) == NULL){
		croak("malloc");
        } 
	if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0){
		croak("route-sysctl-get");
        }
	lim = buf + needed;
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		
			sa = (struct sockaddr *)(rtm + 1);
                        cp = (char*)sa;
			if (sa->sa_family != AF_INET)
		continue;
        dest = mask = gate = 0;
           for (i = 1; i; i <<= 1)
                        if (i & rtm->rtm_addrs) {
                                sa = (struct sockaddr *)cp;
                                switch (i) {
                                case RTA_DST:
                                 sin = (struct sockaddr_in*)sa;
                                 dest = sin->sin_addr.s_addr;
                                        break;
                                case RTA_GATEWAY:
                             if(rtm->rtm_flags & RTF_GATEWAY){   
                               sin = (struct sockaddr_in*)sa;
                               gate = sin->sin_addr.s_addr;
                              }
                                         break;
                                case RTA_NETMASK:
                                 sin = (struct sockaddr_in*)sa;
                                 mask = sin->sin_addr.s_addr;
                                       break;
                                }
                                ADVANCE(cp, sa);
                        }
   if(!(rtm->rtm_flags & RTF_LLINFO) && (rtm->rtm_flags & RTF_HOST)) 
     mask = 0xffffffff;   
     if(!mask && dest && (dest != local)) continue;
     if(!dest) mask = 0;
     if(dest == local) {
                        dest = htonl(0x7f000000); mask = htonl(0xff000000);
                       }			     
     if(!((mask & addr) ^ dest)){
                                switch (gate) {
                                case 0:
                                devip = addr;
                                break;
                                default:
                                devip = gate;
                                }
    }
   }
   free(buf);
  return  dev_name(devip,name);
}

