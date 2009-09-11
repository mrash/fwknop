#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#ifdef _SOLARIS_
#include "solaris.h"
#else
#include <sys/cdefs.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pcap.h>

#ifdef _BPF_
#include <errno.h>
#include <fcntl.h>
#endif

#ifndef DLT_RAW
#define DLT_RAW  12
#endif

#ifndef DLT_SLIP_BSDOS 
#define DLT_SLIP_BSDOS  13
#endif

#ifndef DLT_PPP_BSDOS
#define DLT_PPP_BSDOS   14 
#endif

#include "ip.h"



unsigned short ip_in_cksum(struct iphdr *iph, unsigned short *ptr, int nbytes)
{

	register long sum = 0;	/* assumes long == 32 bits */
	u_short oddbyte;
	register u_short answer;	/* assumes u_short == 16 bits */
	int pheader_len;
	unsigned short *pheader_ptr;
	
	struct pseudo_header {
		unsigned long saddr;
		unsigned long daddr;
		unsigned char null;
		unsigned char proto;
		unsigned short tlen;
	} pheader;
	
	pheader.saddr = iph->saddr;
	pheader.daddr = iph->daddr;
	pheader.null = 0;
	pheader.proto = iph->protocol;
	pheader.tlen = htons(nbytes);

	pheader_ptr = (unsigned short *)&pheader;
	for (pheader_len = sizeof(pheader); pheader_len; pheader_len -= 2) {
		sum += *pheader_ptr++;
	}
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {	/* mop up an odd byte, if necessary */
		oddbyte = 0;	/* make sure top half is zero */
		*((u_char *) & oddbyte) = *(u_char *) ptr;	/* one byte only */
		sum += oddbyte;
	}
	sum += (sum >> 16);	/* add carry */
	answer = ~sum;		/* ones-complement, then truncate to 16 bits */
	return (answer);
}

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register long sum=0;        /* assumes long == 32 bits */
	u_short oddbyte;
	register u_short answer;    /* assumes u_short == 16 bits */
        
	while(nbytes>1){
        	sum+=*ptr++;
	        nbytes-=2;    
	}
	if(nbytes==1){              /* mop up an odd byte, if necessary */
        	oddbyte=0;              /* make sure top half is zero */
	        *((u_char *)&oddbyte)=*(u_char *)ptr;   /* one byte only */
        	sum+=oddbyte;
	}               
	sum+=(sum>>16);             /* add carry */
	answer=~sum;                /* ones-complement, then truncate to 16 bits */
	return(answer);
}


int rawsock(void)
{
	int fd,val=1;

    
	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        croak("(rawsock) socket problems [fatal]");
	}  

	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0) {  
        croak("Cannot set IP_HDRINCL socket option");
	}
	return fd;
}	

u_long
host_to_ip (char *host_name)
{
  struct hostent *target;
  u_long *resolved_ip;
  u_long host_resolved_ip;
  resolved_ip = (u_long *) malloc (sizeof (u_long));

  if ((target = gethostbyname (host_name)) == NULL)
    {
      croak("host_to_ip: failed");
    }
  else
    {
      bcopy (target->h_addr, resolved_ip, sizeof (struct in_addr));
      host_resolved_ip = ntohl ((u_long) * resolved_ip);
      free(resolved_ip);
      return host_resolved_ip;
    }
}

void
pkt_send (int fd, unsigned char * sock,u_char *pkt,int size)
{

  if (sendto (fd, (const void *)pkt,size, 0, (const struct sockaddr *) sock, sizeof (struct sockaddr)) < 0)
    {
      close (fd);
      croak("sendto()");
    }
}

int
linkoffset(int type)

{
	switch (type) {

	case DLT_EN10MB:
		return 14;
	case DLT_SLIP:
		return 16;
	case DLT_SLIP_BSDOS:
		return 24;
	case DLT_NULL:
		return 4;
	case DLT_PPP:
		return 4;
	case DLT_PPP_BSDOS:
		return 24;
	case DLT_FDDI:
		return 21;
	case DLT_IEEE802:
		return 22;
	case DLT_ATM_RFC1483:
		return 8;
	case DLT_RAW:
		return 0;
	}
}

#ifdef _BPF_

int
bpf_open(void)
{
	int fd;
	int n = 0;
	char device[sizeof "/dev/bpf000"];
	do {
		(void)sprintf(device, "/dev/bpf%d", n++);
		fd = open(device, O_WRONLY);
	} while (fd < 0 && errno == EBUSY);
	if (fd < 0)
		printf("%s: %s", device, pcap_strerror(errno));
	return (fd);
}

#endif
