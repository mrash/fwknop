#include <stdio.h>
#include <stdlib.h>

/* This is part of the fwknop project, and just returns the source IP of web
 * request made through a webserver.  The fwknop client uses this to resolve
 * the external IP of a system that is behind a NAT.  The myip executable is
 * accessed here:  http://www.cipherdyne.org/cgi-bin/myip
 *
 * Compile with: gcc -Wall -o myip myip.c
*/

int main(void)
{
    char *ip_str = NULL;

    if ((ip_str = getenv("REMOTE_ADDR")) != NULL)
        fprintf(stdout,
            "Pragma: no-cache\r\n"
            "Content-Type: text/plain\r\n\r\n%s\r\n",
            ip_str
        );
    else
        fprintf(stdout,
            "Pragma: no-cache\r\n"
            "Content-Type: text/plain\r\n\r\nNULL\r\n"
        );

    return 0;
}
