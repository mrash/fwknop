#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
}
#endif

#include "patchlevel.h"

#if PATCHLEVEL < 5
#  ifndef PL_sv_undef
#    define PL_sv_undef sv_undef
#  endif
#  ifndef PL_na
#    define PL_na   na
#  endif
#endif

#ifdef _BSDRAW_
#define BSDFIX(a) (a)
#else
#define BSDFIX(a) htons(a)
#endif

#ifdef _SOLARIS_
#include "solaris.h"
#else
#include <sys/cdefs.h>
#endif
#include "ifaddrlist.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/time.h>


#ifdef _ETH_

#define ETH_ALEN 6

struct ether_header
{
    u_int8_t  ether_dhost[ETH_ALEN];  /* destination eth addr */
    u_int8_t  ether_shost[ETH_ALEN];  /* source ether addr    */
    u_int16_t ether_type;             /* packet type ID field */
};

#endif

struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t ihl:4;
    u_int8_t version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t    version:4;
    u_int8_t ihl:4;
#else
#error  "Please fix <bytesex.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
};

struct tcphdr
{
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
#else
#error  "Adjust your <bits/endian.h> defines"
#endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};

struct icmphdr
{
    u_int8_t type;        /* message type */
    u_int8_t code;        /* type sub-code */
    u_int16_t checksum;
    union
    {
        struct
        {
            u_int16_t id;
            u_int16_t sequence;
        } echo;         /* echo datagram */
        u_int32_t   gateway;    /* gateway address */
        struct
        {
            u_int16_t unused;
            u_int16_t mtu;
        } frag;         /* path mtu discovery */
    } un;
};

struct udphdr {
    u_int16_t source;
    u_int16_t dest;
    u_int16_t len;
    u_int16_t check;
};



#define TCPHDR 20

#pragma pack(1)

typedef struct itpkt {
    struct iphdr ih;
    struct tcphdr th;
} ITPKT;

typedef struct iipkt {
    struct iphdr ih;
    struct icmphdr ich;
} IIPKT;

typedef struct iupkt {
    struct iphdr ih;
    struct udphdr uh;
} IUPKT;


unsigned short ip_in_cksum(struct iphdr *iph, unsigned short *ptr, int nbytes);
unsigned short in_cksum(unsigned short *ptr, int nbytes);
int rawsock(void);
u_long host_to_ip (char *host_name);
void pkt_send(int fd, unsigned char *sock, u_char *pkt, int size);
int linkoffset(int);
 
static int
not_here(s)
    char *s;
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

static double
constant(name, arg)
    char *name;
    int arg;
{
    errno = 0;
    switch (*name) {
        case 'A':
        break;
        case 'B':
        break;
        case 'C':
        break;
        case 'D':
        break;
        case 'E':
        break;
        case 'F':
        break;
        case 'G':
        break;
        case 'H':
        break;
        case 'I':
        break;
        case 'J':
        break;
        case 'K':
        break;
        case 'L':
        break;
        case 'M':
        break;
        case 'N':
        break;
        case 'O':
        break;
        case 'P':
        if (strEQ(name, "PCAP_ERRBUF_SIZE"))
#ifdef PCAP_ERRBUF_SIZE
            return PCAP_ERRBUF_SIZE;
#else
        goto not_there;
#endif
        if (strEQ(name, "PCAP_VERSION_MAJOR"))
#ifdef PCAP_VERSION_MAJOR
            return PCAP_VERSION_MAJOR;
#else
        goto not_there;
#endif
        if (strEQ(name, "PCAP_VERSION_MINOR"))
#ifdef PCAP_VERSION_MINOR
            return PCAP_VERSION_MINOR;
#else
        goto not_there;
#endif
        break;
        case 'Q':
        break;
        case 'R':
        break;
        case 'S':
        break;
        case 'T':
        break;
        case 'U':
        break;
        case 'V':
        break;
        case 'W':
        break;
        case 'X':
        break;
        case 'Y':
        break;
        case 'Z':
        break;
        case 'a':
        break;
        case 'b':
        break;
        case 'c':
        break;
        case 'd':
        break;
        case 'e':
        break;
        case 'f':
        break;
        case 'g':
        break;
        case 'h':
        break;
        case 'i':
        break;
        case 'j':
        break;
        case 'k':
        break;
        case 'l':
        if (strEQ(name, "lib_pcap_h"))
#ifdef lib_pcap_h
            return lib_pcap_h;
#else
        goto not_there;
#endif
        break;
        case 'm':
        break;
        case 'n':
        break;
        case 'o':
        break;
        case 'p':
        break;
        case 'q':
        break;
        case 'r':
        break;
        case 's':
        break;
        case 't':
        break;
        case 'u':
        break;
        case 'v':
        break;
        case 'w':
        break;
        case 'x':
        break;
        case 'y':
        break;
        case 'z':
        break;
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

SV * (*ptr)(u_char*);

pcap_handler printer;

static SV * retref (ref)
    u_char * ref;
{
    return (SV*)ref;
}

static SV * handler (file)
    u_char * file;
{
    SV * handle;
    GV * gv;
    handle = sv_newmortal();
    gv = newGVgen("Net::RawIP");
    do_open(gv, "+<&", 3, FALSE, 0, 0, PerlIO_importFILE((FILE*)file, NULL));
    sv_setsv(handle, sv_bless(newRV_noinc((SV*)gv), gv_stashpv("Net::RawIP",1)));
    return handle;
}

SV * first;
SV * second;
SV * third;

static  void
    call_printer (file,pkt,user)
    u_char * file;
    struct pcap_pkthdr * pkt;
    u_char * user;
{
    dSP ;
    PUSHMARK(sp) ;
    sv_setsv(first,(*ptr)(file));
    sv_setpvn(second, (char *)pkt, sizeof(struct pcap_pkthdr));
    sv_setpvn(third, (char *)user, pkt->caplen);
    XPUSHs(first);
    XPUSHs(second);
    XPUSHs(third);
    PUTBACK ;
    perl_call_sv((SV*)printer,G_VOID);
}

static SV * ip_opts_parse(pkt)
    SV * pkt;
{
    int byte,i;
    STRLEN size;
    u_char * ptr;
    AV * RETVAL; 
    byte = 0;
    size = SvCUR(pkt);
    ptr = (u_char *)SvPV(pkt, size);
    RETVAL = newAV();
    for (i=0; byte<size; i=i+3) {
        switch (*ptr) {
            case 0:
            case 1:
                av_store(RETVAL,i,newSViv(*ptr));
                av_store(RETVAL,i+1,newSViv(1));
                av_store(RETVAL,i+2,newSViv(0));
                ptr++;
                byte++;
                break;
            case 7:
            case 68:
            case 130:
            case 131:
            case 136:
            case 137:
                av_store(RETVAL,i,newSViv(*ptr));
                av_store(RETVAL,i+1,newSViv(*(ptr+1)));
                av_store(RETVAL,i+2,newSVpv((char*)(ptr+2),*(ptr+1)-2));
                if (!*(ptr + 1)) {
                    ptr++;
                    byte++;
                }
                else {
                    byte = byte + *(ptr + 1);
                    ptr = ptr + *(ptr + 1);
                }
                break;
            default:
                ptr++;
                byte++;
        }
    }
    return newRV_noinc((SV*)RETVAL);
}

static SV * ip_opts_creat(ref)
    SV * ref;
{
    int len,i;
    AV * opts;
    SV * ip_opts;
    char c;
    STRLEN l;

    if (SvTYPE(SvRV(ref)) == SVt_PVAV)
        opts = (AV *)SvRV(ref);
    else
        croak("Not array reference\n");

    ip_opts = newSVpv(SvPV((SV*)&PL_sv_undef,l),0);
    len = av_len(opts);
    for (i=0; i<=(len-2); i=i+3) {
        switch (SvIV(*av_fetch(opts,i,0))) {
            case 0:
            case 1:
                c = (char)SvIV(*av_fetch(opts,i,0));
                sv_catpvn(ip_opts,&c,1);
                break;
            case 7:
            case 68:
            case 130:
            case 131:
            case 136:
            case 137:
                c = (char)SvIV(*av_fetch(opts,i,0));
                sv_catpvn(ip_opts, &c, 1);
                c = (char)SvIV(*av_fetch(opts,i+1,0));
                sv_catpvn(ip_opts, &c,1);
                sv_catpvn(ip_opts, 
                            SvPV(*av_fetch(opts,i+2,0),l),
                            SvCUR(*av_fetch(opts,i+2,0)));
            break;
        }
    }
    c = 0;
    for (i=0; i<SvCUR(ip_opts)%4; i++) {
        sv_catpvn(ip_opts,&c,1);
    }
    if (SvCUR(ip_opts) > 40)
        SvCUR_set(ip_opts,40);  
    return ip_opts;
}


static SV * tcp_opts_parse(pkt)
    SV * pkt;
{
    int byte,i;
    STRLEN size;
    u_char * ptr;
    AV * RETVAL; 
    byte = 0;
    size = SvCUR(pkt);
    ptr = (u_char *)SvPV(pkt,size);
    RETVAL = newAV();
    for (i=0; byte<size; i=i+3) {
        switch (*ptr) {
            case 0:
            case 1:
                av_store(RETVAL, i, newSViv(*ptr));
                av_store(RETVAL, i+1, newSViv(1));
                av_store(RETVAL, i+2, newSViv(0));
                ptr++;
                byte++;
                break;
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 11:
            case 12:
            case 13:
                av_store(RETVAL, i, newSViv(*ptr));
                av_store(RETVAL, i+1, newSViv(*(ptr+1)));
                av_store(RETVAL, i+2, newSVpv((char*)(ptr+2),*(ptr+1)-2));
                if (!*(ptr + 1)) {
                    ptr++;
                    byte++;
                }
                else {
                    byte = byte + *(ptr + 1);
                    ptr = ptr + *(ptr + 1);
                }
                break;
            default:
                ptr++;
                byte++;
        }
    }
    return newRV_noinc((SV*)RETVAL);
}                                                                                     

static SV * tcp_opts_creat(ref)
    SV * ref;
{
    int len,i;
    AV * opts;
    SV * ip_opts;
    char c;
    STRLEN l;
    
    if (SvTYPE(SvRV(ref)) == SVt_PVAV)
        opts = (AV *)SvRV(ref);
    else
        croak("Not array reference\n");
    
    ip_opts = newSVpv(SvPV((SV*)&PL_sv_undef,l),0);
    len = av_len(opts);
    for (i=0; i<=(len-2); i=i+3) {
        switch (SvIV(*av_fetch(opts,i,0))) {
            case 0:
            case 1:
                c = (char)SvIV(*av_fetch(opts,i,0));
                sv_catpvn(ip_opts,&c,1);
                break;
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 11:
            case 12:
            case 13:
                c = (char)SvIV(*av_fetch(opts, i, 0));
                sv_catpvn(ip_opts, &c, 1);
                c = (char)SvIV(*av_fetch(opts, i+1, 0));
                sv_catpvn(ip_opts, &c, 1);
                sv_catpvn(ip_opts,
                            SvPV(*av_fetch(opts,i+2,0),l),
                            SvCUR(*av_fetch(opts,i+2,0)));
                break;
        }
    }
    c = 0;
    for (i=0; i<SvCUR(ip_opts)%4; i++) {
        sv_catpvn(ip_opts, &c, 1);
    }
    if (SvCUR(ip_opts) > 40)
        SvCUR_set(ip_opts,40);
    return ip_opts;
}                                                                                     


MODULE = Net::RawIP     PACKAGE = Net::RawIP      PREFIX = pcap_

PROTOTYPES: ENABLE

double
constant(name,arg)
    char *        name
    int           arg

void 
closefd(fd)
    int fd
CODE:
    close(fd);


SV * 
ip_rt_dev(addr)
    u_int32_t addr
CODE:
#ifdef _LINUX_
    char dev[] = "proc";
    RETVAL = newSVpv(dev,4);
#endif
#ifdef _BPF_
    char dev[16];
    int len;
    memset(dev,0,16);
    len = ip_rt_dev(addr,dev);
    RETVAL = newSVpv(dev,len); 
#endif
#if !defined(_LINUX_) && !defined(_BPF_)
    croak("rdev() is not implemented on this system");
#endif
OUTPUT:
    RETVAL


SV *
timem ()
CODE:
    struct timeval tv;
    struct timezone tz;
    tz.tz_minuteswest = 0;
    tz.tz_dsttime = 0;
    if ((gettimeofday(&tv,&tz) < 0)) { 
        RETVAL = newSViv(0);
        croak("gettimeofday()");
    }
    else {
        RETVAL = newSVpvf("%u.%06u",tv.tv_sec,tv.tv_usec);
    }
OUTPUT:
    RETVAL

unsigned int  
rawsock()

#ifdef _IFLIST_

HV *
ifaddrlist()
CODE:
    int c,i;
    char buf[132];
    struct ifaddrlist *al;
    RETVAL = newHV();
    sv_2mortal((SV*)RETVAL);    
    c = ifaddrlist(&al,buf);
    for (i=0; i<c; i++) {
        hv_store(RETVAL, al->device, al->len,
            newSVpvf("%u.%u.%u.%u",
                (al->addr & 0xff000000) >> 24,
                (al->addr & 0x00ff0000) >> 16,
                (al->addr & 0x0000ff00) >> 8,
                (al->addr & 0x000000ff)
            ),0);
                
        al++;
    }
OUTPUT:
    RETVAL

#endif


#ifdef _ETH_

int
tap(device,ip,mac)
    char *device
    SV *ip
    SV *mac
CODE:
    unsigned int i;
    unsigned char m[6];
    RETVAL = tap(device,&i,m);
    if (RETVAL) {
        sv_setiv(ip,i);
        sv_setpvn(mac,(char *)m,6);
    } 
OUTPUT:
    ip
    mac 
    RETVAL

int 
mac_disc(addr,mac)
    unsigned int addr
    SV *mac
CODE:
    unsigned char m[6];
    RETVAL = mac_disc(addr,m);
    if (RETVAL) {
        sv_setpvn(mac,(char *)m,6);
    }
OUTPUT:
    mac
    RETVAL

void 
send_eth_packet(fd,eth_device,pkt,flag)
    int fd
    char* eth_device
    SV* pkt
    int flag
CODE:
    send_eth_packet(fd, eth_device, (char*)SvPV(pkt,PL_na), SvCUR(pkt),flag);

AV * 
eth_parse(pkt)
    SV * pkt
CODE:
    u_char * c;
    struct ether_header *epkt;
    epkt = (struct ether_header *)SvPV(pkt,PL_na);
    RETVAL = newAV();
    sv_2mortal((SV*)RETVAL);
    av_unshift(RETVAL,3);
    c = (u_char*)epkt->ether_dhost;
    av_store(RETVAL,0,
        newSVpvf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", c[0],c[1],c[2],c[3],c[4],c[5]));
    c = (u_char*)epkt->ether_shost;
    av_store(RETVAL, 1,
        newSVpvf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", c[0],c[1],c[2],c[3],c[4],c[5]));
    av_store(RETVAL, 2,
        newSViv(ntohs(epkt->ether_type))); 
OUTPUT:
    RETVAL


#endif
 
SV *
set_sockaddr (daddr,port)
    unsigned int daddr
    unsigned short port
CODE:
    int size;
    struct sockaddr_in dest_sockaddr;
    size = sizeof(struct sockaddr_in);
    memset(&dest_sockaddr,0,size);
    dest_sockaddr.sin_family = AF_INET;
    dest_sockaddr.sin_port = htons(port);
    dest_sockaddr.sin_addr.s_addr = htonl(daddr);
    RETVAL = newSVpv((char*)&dest_sockaddr,size);
OUTPUT:
    RETVAL  
  

unsigned long
host_to_ip (host_name)
    char *host_name

void 
pkt_send (fd, sock, pkt)
    int fd
    SV *sock
    SV *pkt
CODE:
    pkt_send (fd, (u_char *)SvPV(sock,PL_na), (u_char *)SvPV(pkt,PL_na), SvCUR(pkt));


AV * 
tcp_pkt_parse(pkt)
    SV * pkt
CODE:
    u_int ipo,doff,ihl,tot_len;
    ITPKT *pktr;
    ipo = 0;
    pktr = (ITPKT *)SvPV(pkt,PL_na);
    ihl = pktr->ih.ihl;
    tot_len = ntohs(pktr->ih.tot_len);
    RETVAL = newAV();
    sv_2mortal((SV*)RETVAL);
    av_unshift(RETVAL,29);
    av_store(RETVAL, 0, newSViv(pktr->ih.version));
    av_store(RETVAL, 1, newSViv(pktr->ih.ihl));
    av_store(RETVAL, 2, newSViv(pktr->ih.tos));
    av_store(RETVAL, 3, newSViv(ntohs(pktr->ih.tot_len)));
    av_store(RETVAL, 4, newSViv(ntohs(pktr->ih.id)));
    av_store(RETVAL, 5, newSViv(ntohs(pktr->ih.frag_off)));
    av_store(RETVAL, 6, newSViv(pktr->ih.ttl));
    av_store(RETVAL, 7, newSViv(pktr->ih.protocol));
    av_store(RETVAL, 8, newSViv(ntohs(pktr->ih.check)));
    av_store(RETVAL, 9, newSViv(ntohl(pktr->ih.saddr)));
    av_store(RETVAL, 10, newSViv(ntohl(pktr->ih.daddr)));
    if (ihl > 5) {
        av_store(RETVAL,28,
            ip_opts_parse(sv_2mortal(newSVpv((char*)pktr + 20,ihl*4 - 20))));
        pktr = (ITPKT *)pktr + (ihl*4 - 20);  
        ipo = 1;
    }
    doff = pktr->th.doff;
    av_store(RETVAL, 11, newSViv(ntohs(pktr->th.source)));
    av_store(RETVAL, 12, newSViv(ntohs(pktr->th.dest)));
    av_store(RETVAL, 13, newSViv(ntohl(pktr->th.seq)));
    av_store(RETVAL, 14, newSViv(ntohl(pktr->th.ack_seq)));
    av_store(RETVAL, 15, newSViv(pktr->th.doff));
    av_store(RETVAL, 16, newSViv(pktr->th.res1));
    av_store(RETVAL, 17, newSViv(pktr->th.res2));
    av_store(RETVAL, 18, newSViv(pktr->th.urg));
    av_store(RETVAL, 19, newSViv(pktr->th.ack));
    av_store(RETVAL, 20, newSViv(pktr->th.psh));
    av_store(RETVAL, 21, newSViv(pktr->th.rst));
    av_store(RETVAL, 22, newSViv(pktr->th.syn));
    av_store(RETVAL, 23, newSViv(pktr->th.fin));
    av_store(RETVAL, 24, newSViv(ntohs(pktr->th.window)));
    av_store(RETVAL, 25, newSViv(ntohs(pktr->th.check)));
    av_store(RETVAL, 26, newSViv(ntohs(pktr->th.urg_ptr)));
    if (doff > 5) {
        if (!ipo) {
            av_store(RETVAL, 28, newSViv(0));
        }
        av_store(RETVAL, 29,
            tcp_opts_parse(sv_2mortal(newSVpv((char*)pktr+40,doff*4-20))));
        pktr = (ITPKT *)pktr + (doff*4 - 20);
    } 
    av_store(RETVAL, 27, newSVpv(((char*)&pktr->th.urg_ptr+2),
    tot_len - (4*ihl + doff*4))); 
OUTPUT:
    RETVAL

AV * 
icmp_pkt_parse(pkt)
    SV * pkt
CODE:
    u_int ihl,tot_len;
    IIPKT *pktr;
    pktr = (IIPKT *)SvPV(pkt,PL_na);
    ihl = pktr->ih.ihl;
    tot_len = ntohs(pktr->ih.tot_len);
    RETVAL = newAV();
    sv_2mortal((SV*)RETVAL);
    av_unshift(RETVAL,20);
    av_store(RETVAL, 0, newSViv(pktr->ih.version));
    av_store(RETVAL, 1, newSViv(pktr->ih.ihl));
    av_store(RETVAL, 2, newSViv(pktr->ih.tos));
    av_store(RETVAL, 3, newSViv(ntohs(pktr->ih.tot_len)));
    av_store(RETVAL, 4, newSViv(ntohs(pktr->ih.id)));
    av_store(RETVAL, 5, newSViv(ntohs(pktr->ih.frag_off)));
    av_store(RETVAL, 6, newSViv(pktr->ih.ttl));
    av_store(RETVAL, 7, newSViv(pktr->ih.protocol));
    av_store(RETVAL, 8, newSViv(ntohs(pktr->ih.check)));
    av_store(RETVAL, 9, newSViv(ntohl(pktr->ih.saddr)));
    av_store(RETVAL, 10, newSViv(ntohl(pktr->ih.daddr)));
    if (ihl > 5) {
        av_store(RETVAL, 20,
            ip_opts_parse(sv_2mortal(newSVpv((char*)pktr + 20,ihl*4 - 20))));  
        pktr = (IIPKT *)pktr + (ihl*4 - 20);  
    }
    av_store(RETVAL, 11, newSViv(pktr->ich.type));
    av_store(RETVAL, 12, newSViv(pktr->ich.code));
    av_store(RETVAL, 13, newSViv(ntohs(pktr->ich.checksum)));
    av_store(RETVAL, 14, newSViv(pktr->ich.un.gateway));
    av_store(RETVAL, 15, newSViv(pktr->ich.un.echo.id));
    av_store(RETVAL, 16, newSViv(pktr->ich.un.echo.sequence));
    av_store(RETVAL, 17, newSViv(pktr->ich.un.frag.unused));
    av_store(RETVAL, 18, newSViv(pktr->ich.un.frag.mtu));
    av_store(RETVAL, 19, newSVpv(((char*)&pktr->ich.un.frag.mtu+2),
    tot_len - (4*ihl + 8)));
OUTPUT:
    RETVAL

AV * 
generic_pkt_parse(pkt)
    SV * pkt
CODE:
    u_int ihl,tot_len;
    struct iphdr *pktr;
    pktr = (struct iphdr *)SvPV(pkt,PL_na);
    ihl = pktr->ihl;
    tot_len = ntohs(pktr->tot_len);
    RETVAL = newAV();
    sv_2mortal((SV*)RETVAL);
    av_store(RETVAL, 0, newSViv(pktr->version));
    av_store(RETVAL, 1, newSViv(pktr->ihl));
    av_store(RETVAL, 2, newSViv(pktr->tos));
    av_store(RETVAL, 3, newSViv(ntohs(pktr->tot_len)));
    av_store(RETVAL, 4, newSViv(ntohs(pktr->id)));
    av_store(RETVAL, 5, newSViv(ntohs(pktr->frag_off)));
    av_store(RETVAL, 6, newSViv(pktr->ttl));
    av_store(RETVAL, 7, newSViv(pktr->protocol));
    av_store(RETVAL, 8, newSViv(ntohs(pktr->check)));
    av_store(RETVAL, 9, newSViv(ntohl(pktr->saddr)));
    av_store(RETVAL, 10, newSViv(ntohl(pktr->daddr)));
    if (ihl > 5) {
        av_store(RETVAL,12,
        ip_opts_parse(sv_2mortal(newSVpv((char*)pktr + 20,ihl*4 - 20))));  
        pktr = pktr + (ihl*4 - 20);  
    }
    av_store(RETVAL, 11, newSVpv(((char*)pktr+20), tot_len - 4*ihl));
OUTPUT:
    RETVAL


AV * 
udp_pkt_parse(pkt)
    SV * pkt
CODE:
    u_int ihl,tot_len;
    IUPKT *pktr;
    pktr = (IUPKT *)SvPV(pkt,PL_na);
    ihl = pktr->ih.ihl;
    tot_len = ntohs(pktr->ih.tot_len);
    RETVAL = newAV();
    sv_2mortal((SV*)RETVAL);
    av_unshift(RETVAL, 16);
    av_store(RETVAL, 0, newSViv(pktr->ih.version));
    av_store(RETVAL, 1, newSViv(pktr->ih.ihl));
    av_store(RETVAL, 2, newSViv(pktr->ih.tos));
    av_store(RETVAL, 3, newSViv(ntohs(pktr->ih.tot_len)));
    av_store(RETVAL, 4, newSViv(ntohs(pktr->ih.id)));
    av_store(RETVAL, 5, newSViv(ntohs(pktr->ih.frag_off)));
    av_store(RETVAL, 6, newSViv(pktr->ih.ttl));
    av_store(RETVAL, 7, newSViv(pktr->ih.protocol));
    av_store(RETVAL, 8, newSViv(ntohs(pktr->ih.check)));
    av_store(RETVAL, 9, newSViv(ntohl(pktr->ih.saddr)));
    av_store(RETVAL, 10, newSViv(ntohl(pktr->ih.daddr)));
    if (ihl > 5) {
        av_store(RETVAL, 16,
            ip_opts_parse(sv_2mortal(newSVpv((char*)pktr + 20,ihl*4 - 20))));  
        pktr = pktr + (ihl*4 - 20);  
    }
    av_store(RETVAL, 11, newSViv(ntohs(pktr->uh.source)));
    av_store(RETVAL, 12, newSViv(ntohs(pktr->uh.dest)));
    av_store(RETVAL, 13, newSViv(ntohs(pktr->uh.len)));
    av_store(RETVAL, 14, newSViv(ntohs(pktr->uh.check)));
    av_store(RETVAL, 15, newSVpv(((char*)&pktr->uh.check+2),
        tot_len - (4*ihl + 8)));
OUTPUT:
    RETVAL

SV *
udp_pkt_creat(p)
    SV * p
CODE:
    int opt,iplen;
    SV * ip_opts;
    u_char * ptr;
    AV * pkt;
    IUPKT piu;
    u_char *piur;
    opt = 0;
    iplen = 20;
    if (SvTYPE(SvRV(p)) == SVt_PVAV)
        pkt = (AV *)SvRV(p);
    else
        croak("Not array reference\n");
        piu.ih.version = SvIV(*av_fetch(pkt,0,0));
        piu.ih.ihl = SvIV(*av_fetch(pkt,1,0));
        piu.ih.tos = SvIV(*av_fetch(pkt,2,0));
        piu.ih.tot_len = BSDFIX(SvIV(*av_fetch(pkt,3,0)));
    if (!piu.ih.tot_len) 
        piu.ih.tot_len = BSDFIX(iplen + 8 + SvCUR(*av_fetch(pkt,15,0))); 
    piu.ih.id = htons(SvIV(*av_fetch(pkt,4,0)));
    piu.ih.frag_off = BSDFIX(SvIV(*av_fetch(pkt,5,0)));
    piu.ih.ttl = SvIV(*av_fetch(pkt,6,0));
    piu.ih.protocol = SvIV(*av_fetch(pkt,7,0));
    piu.ih.check = htons(SvIV(*av_fetch(pkt,8,0)));
    piu.ih.saddr = htonl(SvIV(*av_fetch(pkt,9,0)));
    piu.ih.daddr = htonl(SvIV(*av_fetch(pkt,10,0)));
    if (!piu.ih.check)
        piu.ih.check = in_cksum((unsigned short *)&piu,iplen); 
    piu.uh.source = htons(SvIV(*av_fetch(pkt,11,0)));
    piu.uh.dest = htons(SvIV(*av_fetch(pkt,12,0)));
    piu.uh.len = htons(SvIV(*av_fetch(pkt,13,0)));
    if (!piu.uh.len)
        piu.uh.len = htons(8 + SvCUR(*av_fetch(pkt,15,0))); 
    piu.uh.check = htons(SvIV(*av_fetch(pkt,14,0)));
    if (av_fetch(pkt,16,0)) {
        if (SvROK(*av_fetch(pkt,16,0))) {
            opt++;
            ip_opts = ip_opts_creat(*av_fetch(pkt,16,0));
            piu.ih.ihl = 5 + SvCUR(ip_opts)/4;
            piu.ih.tot_len = BSDFIX(4*piu.ih.ihl + 8 + SvCUR(*av_fetch(pkt,15,0)));
            iplen = 4*piu.ih.ihl;
            piu.ih.check = 0;
            ptr = (u_char*)safemalloc(iplen + 8);
            memcpy(ptr,(u_char*)&piu,20);
            memcpy(ptr+20,SvPV(ip_opts,PL_na),SvCUR(ip_opts));
            memcpy(ptr+20+SvCUR(ip_opts),(u_char*)&piu + 20,8);
            ((struct iphdr*)ptr)->check = in_cksum((unsigned short *)ptr,iplen);
            RETVAL = newSVpv((char*)ptr, sizeof(IUPKT)+SvCUR(ip_opts));
            sv_catsv(RETVAL, *av_fetch(pkt,15,0));
            Safefree(ptr);
            sv_2mortal(ip_opts);
        }
    }
    if (!opt) {
        RETVAL = newSVpv((char*)&piu,sizeof(IUPKT));
        sv_catsv(RETVAL,*av_fetch(pkt,15,0));
    }
    if (!piu.uh.check) {
        piur = (u_char*) SvPV(RETVAL, PL_na);
        ((struct udphdr*)(piur + iplen))->check = 
            ip_in_cksum((struct iphdr *)piur,
                        (unsigned short *)(piur + iplen),
                        8 + SvCUR(*av_fetch(pkt,15,0)));
        sv_setpvn(RETVAL, (char*)piur, iplen + 8 + SvCUR(*av_fetch(pkt,15,0)));
    }
OUTPUT:
    RETVAL  

 # This assembles an ICMP packet based on the data passed in as an
 # array reference from the Perl module.  Populating this are with
 # comments as I try to understand the code better so I'll remember
 # what I thought each bit did.
 # Steve Bonds

SV *
icmp_pkt_creat(p)
    SV * p
CODE:
    int opt,iplen;
    SV * ip_opts;
    u_char * ptr;
    AV * pkt;
    IIPKT pii;
    u_char *piir;
    opt = 0;
    iplen = 20;
    if (SvTYPE(SvRV(p)) == SVt_PVAV)
	/* pkt allows for easy access in C to the original parameter, p.  
           Steve Bonds */
        pkt = (AV *)SvRV(p);
    else
        croak("Not array reference\n");

    /* Populate the C pii ICMP packet structure with information from "pkt", which
       is the C char pointer to the array reference passed in.  The perlguts
       man page recommends checking that this returns non-null before calling
       SvIV on it, probably to follow the Second Commandment of C:

         Thou shalt not follow the NULL pointer, for chaos and madness await thee at its end.

       (http://web.archive.org/web/19961109205914/http://www.lysator.liu.se/c/ten-commandments.html)

       however, it would appear that the original author didn't and I don't want to
       make too many changes yet, so I'll pretend I didn't see it for now...

       Steve Bonds */
    pii.ih.version = SvIV(*av_fetch(pkt,0,0));
    pii.ih.ihl = SvIV(*av_fetch(pkt,1,0));
    pii.ih.tos = SvIV(*av_fetch(pkt,2,0));
    pii.ih.tot_len = BSDFIX(SvIV(*av_fetch(pkt,3,0)));
    if (!pii.ih.tot_len)
        pii.ih.tot_len = BSDFIX(iplen + 8 + SvCUR(*av_fetch(pkt,19,0))); 
    pii.ih.id = htons(SvIV(*av_fetch(pkt,4,0)));
    pii.ih.frag_off = BSDFIX(SvIV(*av_fetch(pkt,5,0)));
    pii.ih.ttl = SvIV(*av_fetch(pkt,6,0));
    pii.ih.protocol = SvIV(*av_fetch(pkt,7,0));
    pii.ih.check = htons(SvIV(*av_fetch(pkt,8,0)));
    pii.ih.saddr = htonl(SvIV(*av_fetch(pkt,9,0)));
    pii.ih.daddr = htonl(SvIV(*av_fetch(pkt,10,0)));
    if (!pii.ih.check)
        pii.ih.check = in_cksum((unsigned short *)&pii,iplen);

    /* We're done with the basic IP header assembly into the pii
    structure.  Move on to the ICMP header specifics.  Steve Bonds */

    pii.ich.type = SvIV(*av_fetch(pkt,11,0));
    pii.ich.code = SvIV(*av_fetch(pkt,12,0));
    pii.ich.checksum = htons(SvIV(*av_fetch(pkt,13,0)));
    pii.ich.un.gateway = SvIV(*av_fetch(pkt,14,0));

    /* Array index 20 is the "data" area of the ICMP packet.  av_fetch only
    returns a scalar so the data area must be one, which explains why it
    didn't work so great when I used an array reference here based on my
    incorrect understanding of the POD docs.  Steve Bonds */
    if (av_fetch(pkt,20,0)) {
        if (SvROK(*av_fetch(pkt,20,0))) {
            opt++;

	    /* I don't understand why this module calls an internal parsing function
	       on a raw data field supplied by the user.  This may or may not
	       associate with an actual IP structure, depending on what the
	       user of this module decides.  It appears that this is done to
               get the proper packet length for the IP header, but this could
               also be done based on the scalar length of the raw data area
               itself (SvCUR).  

	       Why wouldn't the sum of these work for the total IP packet length:
	         + IP header (20)
		 + ICMP header (8)
		   - type (1)
		   - code (1)
		   - checksum (2)
		   - id or unused (2)
		   - sequence or mtu (2)
		 + ICMP data (variable length)

	       Finding the total length shouldn't require any decoding of the ICMP
	       data area.  Doing so just gives this module additional places to
	       either break/crash or mangle the intended data on its way out.

	       In the interest of not breaking the module until I understand it better,
	       leave it alone for now.

	       Steve Bonds */
            ip_opts = ip_opts_creat(*av_fetch(pkt,20,0));
            pii.ih.ihl = 5 + SvCUR(ip_opts)/4;
            iplen = 4*pii.ih.ihl;

            /* Array index 19 is the MTU or Sequence.  SvCUR returns the length of that scalar.
               Steve Bonds */
            pii.ih.tot_len = BSDFIX(iplen + 8 + SvCUR(*av_fetch(pkt,19,0)));
            pii.ih.check = 0;

	    /* Create a place to copy the pii structure for rebuilding the checksum.
               Steve Bonds */
            ptr = (u_char*)safemalloc(iplen + 8);
	    /* Copy the 20 byte IP header in */
            memcpy(ptr,(u_char*)&pii,20);

	    /* Either this is a bug or I don't understand something going on here.
	       ip_opts is derived above from field 20 of "pkt" which is the
	       user-supplied data area of the ICMP packet they want to send.
	       This data area is supposed to be an IP packet, but since they
	       can set it to any arbitrary string of bytes, it doesn't necessarily
	       have to be.  So it looks to me like we just joined the 20 byte IP
	       header with the 8 bytes ip_opts creates from the user data area.
	       I would instead have expected this to be the 8 bytes of ICMP
	       packet header we created above.  Steve Bonds */
            memcpy(ptr+20,SvPV(ip_opts,PL_na),SvCUR(ip_opts));

	    /* Here's the 8 bytes we created above getting copied in.  I would have
	       expected this line to be before the above line. */
            memcpy(ptr+20+SvCUR(ip_opts),(u_char*)&pii + 20,8);

	    /* Re-build a valid IP checksum for our packet. */
            ((struct iphdr*)ptr)->check = in_cksum((unsigned short *)ptr,iplen);

	    /* Create a new scalar that will contain the string value contained
	       in our temporary spot *ptr.  This in essence becomes a packed
	       string value in perl when it gets sent back.  Steve Bonds */
            RETVAL = newSVpv((char*)ptr, sizeof(IIPKT)+SvCUR(ip_opts));

	    /* Toss field 19 from the original array (MTU/Sequence) onto 
	       the end of the RETVAL scalar created above.  Alas, these are
	       2-byte values so these need to be converted to proper network 
	       byte order before they will be valid.  This looks like the 
	       bug I came here to find.

	       I think it may be simpler to convert this to network byte order
	       via Perl before it gets passed in to this code so as to minimize 
	       the changes needed inside this harder-to-follow .xs file.

	       Steve Bonds */
            sv_catsv(RETVAL, *av_fetch(pkt, 19, 0));
            Safefree(ptr);
            sv_2mortal(ip_opts);
        }
    }
    if (!opt) {
        RETVAL = newSVpv((char*)&pii,sizeof(IIPKT));
        sv_catsv(RETVAL,*av_fetch(pkt,19,0));
    }
    if (!pii.ich.checksum) {
        piir = (u_char*) SvPV(RETVAL,PL_na);
        ((struct icmphdr*)(piir + iplen))->checksum = 
            in_cksum((unsigned short *)(piir + iplen),8 + SvCUR(*av_fetch(pkt,19,0)));
        sv_setpvn(RETVAL,(char*)piir,iplen + 8 + SvCUR(*av_fetch(pkt,19,0)));
    }
OUTPUT:
    RETVAL  

SV *
generic_pkt_creat(p)
    SV * p
CODE:
    int opt,iplen;
    SV * ip_opts;
    AV * pkt;
    struct iphdr ih;
    u_char *pigr;
    opt = 0;
    iplen = 20;
    
    if (SvTYPE(SvRV(p)) == SVt_PVAV)
        pkt = (AV *)SvRV(p);
    else
        croak("Not array reference\n");

    ih.version = SvIV(*av_fetch(pkt,0,0));
    ih.ihl = SvIV(*av_fetch(pkt,1,0));
    ih.tos = SvIV(*av_fetch(pkt,2,0));
    ih.tot_len = BSDFIX(SvIV(*av_fetch(pkt,3,0)));
    if (!ih.tot_len)
        ih.tot_len = BSDFIX(iplen + SvCUR(*av_fetch(pkt,11,0))); 
    ih.id = htons(SvIV(*av_fetch(pkt,4,0)));
    ih.frag_off = BSDFIX(SvIV(*av_fetch(pkt,5,0)));
    ih.ttl = SvIV(*av_fetch(pkt,6,0));
    ih.protocol = SvIV(*av_fetch(pkt,7,0));
    ih.check = htons(SvIV(*av_fetch(pkt,8,0)));
    ih.saddr = htonl(SvIV(*av_fetch(pkt,9,0)));
    ih.daddr = htonl(SvIV(*av_fetch(pkt,10,0)));
    if (!ih.check)
        ih.check = in_cksum((unsigned short *)&ih,iplen); 
    if (av_fetch(pkt,12,0)) {
        if (SvROK(*av_fetch(pkt,12,0))) {
            opt++;
            ip_opts = ip_opts_creat(*av_fetch(pkt,12,0));
            if (ih.ihl <= 5)
                ih.ihl = 5 + SvCUR(ip_opts)/4;
            iplen = 20 + SvCUR(ip_opts);
            if (!ih.tot_len)
                ih.tot_len = BSDFIX(20 + SvCUR(ip_opts) + SvCUR(*av_fetch(pkt,11,0)));
            ih.check = 0;
            RETVAL = newSVpv((char*)&ih,20);
            sv_catsv(RETVAL,ip_opts);
            pigr = (u_char*) SvPV(RETVAL,PL_na);
            ((struct iphdr*)pigr)->check = in_cksum((unsigned short *)pigr,iplen);
            sv_setpvn(RETVAL,(char*)pigr,iplen);
            sv_catsv(RETVAL,*av_fetch(pkt,11,0));
            sv_2mortal(ip_opts);
        }
    }
    if (!opt) {
        RETVAL = newSVpv((char*)&ih,iplen);
        sv_catsv(RETVAL,*av_fetch(pkt,11,0));
    }
OUTPUT:
RETVAL
   
SV *
tcp_pkt_creat(p)
    SV * p
CODE:
    int  ipo,opt,iplen;
    AV * pkt;
    SV * ip_opts;
    SV * tcp_opts;
    u_char * ptr;
    u_char * tptr;
    ITPKT pit;
    u_char *pitr;
    ipo = 0;
    opt = 0;
    iplen = 20;
    if (SvTYPE(SvRV(p)) == SVt_PVAV)
        pkt = (AV *)SvRV(p);
    else
        croak("Not array reference\n");
    pit.ih.version = SvIV(*av_fetch(pkt,0,0));
    pit.ih.ihl = SvIV(*av_fetch(pkt,1,0));
    pit.ih.tos = SvIV(*av_fetch(pkt,2,0));
    pit.ih.tot_len = BSDFIX(SvIV(*av_fetch(pkt,3,0)));
    if (!pit.ih.tot_len)
        pit.ih.tot_len = BSDFIX(iplen + TCPHDR + SvCUR(*av_fetch(pkt,27,0))); 
    pit.ih.id = htons(SvIV(*av_fetch(pkt,4,0)));
    pit.ih.frag_off = BSDFIX(SvIV(*av_fetch(pkt,5,0)));
    pit.ih.ttl = SvIV(*av_fetch(pkt,6,0));
    pit.ih.protocol = SvIV(*av_fetch(pkt,7,0));
    pit.ih.check = htons(SvIV(*av_fetch(pkt,8,0)));
    pit.ih.saddr = htonl(SvIV(*av_fetch(pkt,9,0)));
    pit.ih.daddr = htonl(SvIV(*av_fetch(pkt,10,0)));
    if (!pit.ih.check)
        pit.ih.check = in_cksum((unsigned short *)&pit,iplen); 
    pit.th.source = htons(SvIV(*av_fetch(pkt,11,0)));
    pit.th.dest = htons(SvIV(*av_fetch(pkt,12,0)));
    pit.th.seq = htonl(SvIV(*av_fetch(pkt,13,0)));
    pit.th.ack_seq = htonl(SvIV(*av_fetch(pkt,14,0)));
    pit.th.doff = SvIV(*av_fetch(pkt,15,0));
    pit.th.res1 = SvIV(*av_fetch(pkt,16,0));
    pit.th.res2 = SvIV(*av_fetch(pkt,17,0));
    pit.th.urg = SvIV(*av_fetch(pkt,18,0));
    pit.th.ack = SvIV(*av_fetch(pkt,19,0));
    pit.th.psh = SvIV(*av_fetch(pkt,20,0));
    pit.th.rst = SvIV(*av_fetch(pkt,21,0));
    pit.th.syn = SvIV(*av_fetch(pkt,22,0));
    pit.th.fin = SvIV(*av_fetch(pkt,23,0));
    pit.th.window = htons(SvIV(*av_fetch(pkt,24,0)));
    pit.th.check = htons(SvIV(*av_fetch(pkt,25,0)));
    pit.th.urg_ptr = htons(SvIV(*av_fetch(pkt,26,0)));
    if (av_fetch(pkt,28,0)) {
        if(SvROK(*av_fetch(pkt,28,0))) {
            opt++;
            ip_opts = ip_opts_creat(*av_fetch(pkt,28,0));
            pit.ih.ihl = 5 + SvCUR(ip_opts)/4;
            pit.ih.tot_len = BSDFIX(4*pit.ih.ihl + TCPHDR + SvCUR(*av_fetch(pkt,27,0)));
            iplen = 4*pit.ih.ihl;
            pit.ih.check = 0;
            ptr = (u_char*)safemalloc(4*pit.ih.ihl + TCPHDR);
            memcpy(ptr,(u_char*)&pit,20);
            memcpy(ptr+20,SvPV(ip_opts,PL_na),SvCUR(ip_opts));
            memcpy(ptr+20+SvCUR(ip_opts),(u_char*)&pit + 20,TCPHDR);
            ((struct iphdr*)ptr)->check = in_cksum((unsigned short *)ptr,4*pit.ih.ihl);
            RETVAL = newSVpv((char*)ptr, sizeof(ITPKT)+SvCUR(ip_opts));
            sv_catsv(RETVAL,*av_fetch(pkt,27,0));
            Safefree(ptr);
            sv_2mortal(ip_opts);
            ipo = 1;
        }
        if (av_fetch(pkt,29,0)) {
            if (SvROK(*av_fetch(pkt,29,0))) {
                opt++;
                tcp_opts = tcp_opts_creat(*av_fetch(pkt,29,0));
                if (ipo) {
                    ptr = (u_char *)SvPV(RETVAL,PL_na);
                    tptr = (u_char*)safemalloc(SvCUR(RETVAL) + SvCUR(tcp_opts) -
                                                SvCUR(*av_fetch(pkt,27,0)));
                    ((struct iphdr*)ptr)->tot_len = BSDFIX(SvCUR(RETVAL) + SvCUR(tcp_opts)); 
                    ((struct iphdr*)ptr)->check = 0;
                    ((struct iphdr*)ptr)->check = in_cksum((unsigned short *)ptr,iplen);
                    ((struct tcphdr*)(ptr + iplen))->doff = 5 + SvCUR(tcp_opts)/4; 
                    memcpy(tptr,ptr,SvCUR(RETVAL)-SvCUR(*av_fetch(pkt,27,0)));
                    memcpy(tptr+(SvCUR(RETVAL)-SvCUR(*av_fetch(pkt,27,0))),
                            SvPV(tcp_opts,PL_na),SvCUR(tcp_opts));
                    sv_setpvn(RETVAL, (char *)tptr, SvCUR(RETVAL) + SvCUR(tcp_opts) -
                                                  SvCUR(*av_fetch(pkt,27,0)));
                    sv_catsv(RETVAL, *av_fetch(pkt,27,0));
                }
                else {
                    pit.ih.tot_len = BSDFIX(40+SvCUR(tcp_opts)+SvCUR(*av_fetch(pkt,27,0)));
                    pit.ih.check = 0;
                    pit.ih.check = in_cksum((unsigned short *)&pit,iplen);
                    pit.th.doff = 5 + SvCUR(tcp_opts)/4;
                    tptr = (u_char*)safemalloc(40+SvCUR(tcp_opts));
                    memcpy(tptr,&pit,40);
                    memcpy(tptr+40,SvPV(tcp_opts,PL_na),SvCUR(tcp_opts));
                    RETVAL = newSVpv((char*)tptr, 40+SvCUR(tcp_opts));
                    sv_catsv(RETVAL, *av_fetch(pkt,27,0));
                }           
                Safefree(tptr);
                sv_2mortal(tcp_opts);
            }
        }
    }
    if (!opt) {
        RETVAL = newSVpv((char*)&pit,sizeof(ITPKT));
        sv_catsv(RETVAL,*av_fetch(pkt,27,0));
    }
    if (!pit.th.check) {
        pitr = (u_char *)SvPV(RETVAL,PL_na);
        ((struct tcphdr*)(pitr + iplen))->check = 
        ip_in_cksum((struct iphdr *)pitr,(unsigned short *)(pitr + iplen),
                          4*((struct tcphdr*)(pitr + iplen))->doff + 
                                                SvCUR(*av_fetch(pkt,27,0)));
        sv_setpvn(RETVAL,(char*)pitr,iplen+
            4*((struct tcphdr*)(pitr + iplen))->doff + SvCUR(*av_fetch(pkt,27,0)));
    }
OUTPUT:
    RETVAL  

pcap_t *
open_live(device,snaplen,promisc,to_ms,ebuf)
    char *device
    int snaplen
    int promisc
    int to_ms
    char * ebuf
CODE:
    ebuf = (char*)safemalloc(PCAP_ERRBUF_SIZE);
    RETVAL = pcap_open_live(device, snaplen, promisc, to_ms, ebuf);     
    Safefree(ebuf);
OUTPUT:
    ebuf
    RETVAL

pcap_t *
open_offline(fname,ebuf)
    char *fname
    char *ebuf
CODE:
    ebuf = (char*)safemalloc(PCAP_ERRBUF_SIZE);
    RETVAL = pcap_open_offline(fname,ebuf);
    Safefree(ebuf);
OUTPUT:
    ebuf
    RETVAL

SV *
pcap_dump_open(p,fname)
    pcap_t *p
    char *fname
CODE:
    RETVAL = newSViv((unsigned long)pcap_dump_open(p,fname));
OUTPUT:
    RETVAL

char *
lookupdev(ebuf)
    char *ebuf
CODE:
    ebuf = (char*)safemalloc(PCAP_ERRBUF_SIZE);
    RETVAL = pcap_lookupdev(ebuf);
    Safefree(ebuf);
OUTPUT:
    ebuf
    RETVAL
        
int 
lookupnet(device,netp,maskp,ebuf)
    char *device
    bpf_u_int32 netp
    bpf_u_int32 maskp
    char *ebuf
CODE:
    ebuf = (char*)safemalloc(PCAP_ERRBUF_SIZE);
    RETVAL = pcap_lookupnet(device,&netp,&maskp,ebuf);
    Safefree(ebuf);
OUTPUT:
    netp
    maskp
    ebuf
    RETVAL

void
dump(ptr,pkt,user)
    SV * ptr
    SV * pkt
    SV * user
CODE:
    pcap_dump((u_char*)PerlIO_findFILE(IoOFP(sv_2io(ptr))),
          (struct pcap_pkthdr*)(SvPV(pkt,PL_na)),
          (u_char*)(SvPV(user,PL_na)));      

int 
dispatch(p,cnt,print,user)
    pcap_t *p
    int cnt
    pcap_handler print
    SV * user
CODE:
    printer = print;
    if (!SvROK(user) && SvOK(user)) {
        user = (SV *) SvIV(user);
        ptr = &handler;
    }
    else {
        ptr = &retref;
    }
    first = newSViv(0);
    second = newSViv(0);
    third = newSViv(0);
    RETVAL = pcap_dispatch(p,cnt,(pcap_handler)&call_printer,(u_char*)user);
OUTPUT:
    RETVAL

int 
loop(p,cnt,print,user)
    pcap_t *p
    int cnt
    pcap_handler print
    SV *user
CODE:
    printer = print;
    if (!SvROK(user) && SvOK(user)) {
        user = (SV *)SvIV(user); 
        ptr = &handler;
    }
    else {
        ptr = &retref;
    }
    first = newSViv(0);
    second = newSViv(0);
    third = newSViv(0);
    RETVAL = pcap_loop(p,cnt,(pcap_handler)&call_printer,(u_char*)user);
OUTPUT:
    RETVAL


int 
compile(p,fp,str,optimize,netmask)
    pcap_t * p
    struct bpf_program *fp
    char *str
    int optimize
    unsigned int netmask
CODE:
    fp = (struct bpf_program *)safemalloc(sizeof(struct bpf_program));
    RETVAL = pcap_compile(p,fp,str,optimize,netmask);
    Safefree(fp);
OUTPUT: 
    fp
    RETVAL

int
linkoffset(p)
    pcap_t * p
CODE:
    RETVAL = linkoffset(pcap_datalink(p));
OUTPUT:
    RETVAL
        
int 
pcap_setfilter(p,fp)
    pcap_t *p
    struct bpf_program *fp
OUTPUT:
    RETVAL

SV *
next(p,h)
    pcap_t *p      
    SV *h
CODE:
    STRLEN len;
    u_char * hdr;
    const u_char * next;
    len = sizeof(struct pcap_pkthdr);
    if (!SvOK(h)) {
        sv_setpv(h,"new");
        SvGROW(h,len) ;
    }
    hdr = (u_char *)SvPV(h,len) ;
    next = pcap_next(p,(struct pcap_pkthdr*)hdr);
    if (next)
        RETVAL = newSVpv((char *)next,((struct pcap_pkthdr*)hdr)->caplen);
    else
        RETVAL = newSViv(0);
    sv_setpvn(h,(char *)hdr,len);
OUTPUT:
    h
    RETVAL



int 
pcap_datalink(p)  
    pcap_t *p 
OUTPUT:
    RETVAL

int 
pcap_snapshot(p)  
    pcap_t *p 
OUTPUT:
    RETVAL

int 
pcap_is_swapped(p)  
    pcap_t *p 
OUTPUT:
RETVAL

int 
pcap_major_version(p)  
    pcap_t *p 
OUTPUT:
    RETVAL

int 
pcap_minor_version(p)  
    pcap_t *p 
OUTPUT:
    RETVAL

int 
stat(p,ps)  
    pcap_t *p
    u_char *ps 
CODE:
    ps = safemalloc(sizeof(struct pcap_stat));
    RETVAL = pcap_stats(p,(struct pcap_stat*)ps);
    Safefree(ps);
OUTPUT:
    ps
    RETVAL
        

int 
pcap_fileno(p)
    pcap_t *p
OUTPUT:
    RETVAL


void 
pcap_perror(p,prefix) 
    pcap_t *p
    char *prefix 

SV *
pcap_geterr(p)
    pcap_t *p
CODE:
    RETVAL = newSVpv(pcap_geterr(p),0);   
OUTPUT:
    RETVAL


SV *
pcap_strerror(error) 
    int error    
CODE:
    RETVAL = newSVpv(pcap_strerror(error),0);   
OUTPUT:
    RETVAL

void 
pcap_close(p) 
    pcap_t *p
  
  
void 
pcap_dump_close(p) 
    pcap_dumper_t *p 



FILE *
pcap_file(p)
    pcap_t *p
OUTPUT:
    RETVAL

