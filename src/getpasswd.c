/* $Id$
 *****************************************************************************
 *
 * File:    getpasswd.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Routines for obtaining a password from a user.
 *
 * Copyright (C) 2009 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU Public License):
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program; if not, write to the Free Software
 *     Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *     USA
 *
 *****************************************************************************
*/
#include <stdio.h>
#include <signal.h>
#include <termios.h>

#include "fwknop_common.h"
#include "getpasswd.h"

#define MAX_PASS_LEN    128

/* Function for accepting password input from users
*/
char*
getpasswd(const char *prompt)
{
    static char     pwbuf[MAX_PASS_LEN + 1] = {0};
    char           *ptr;    
    sigset_t        sig, old_sig;
    struct termios  ts, old_ts;
    FILE           *fp;
    int             c;

    if((fp = fopen(ctermid(NULL), "r+")) == NULL)
        return(NULL);

    setbuf(fp, NULL);

    /* Setup blocks for SIGINT and SIGTSTP and save the original signal
     * mask.
    */
    sigemptyset(&sig);
    sigaddset(&sig, SIGINT);
    sigaddset(&sig, SIGTSTP);
    sigprocmask(SIG_BLOCK, &sig, &old_sig);

    /* Save current tty state for later restoration after we disable echo
     * of characters to the tty.
    */
    tcgetattr(fileno(fp), &ts);
    old_ts = ts;
    ts.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    tcsetattr(fileno(fp), TCSAFLUSH, &ts);

    fputs(prompt, fp);

    /* Read in the password.
    */
    ptr = pwbuf;
    while((c = getc(fp)) != EOF && c != '\n')
        if(ptr < &pwbuf[MAX_PASS_LEN])
            *ptr++ = c;

    /* Null terminate the password.
    */
    *ptr = 0;

    /* we can go ahead and echo out a newline.
    */
    putc('\n', fp);

    /* Restore our tty state and signal handlers.
    */
    tcsetattr(fileno(fp), TCSAFLUSH, &old_ts);
    sigprocmask(SIG_BLOCK, &old_sig, NULL);

    fclose(fp);

    return(pwbuf);
}

/* Function for accepting password input from users
*/
char*
getpasswd_file(const char *pw_file, const char *dst_ip_str)
{
    FILE           *pwfile_ptr;
    unsigned int    numLines = 0, i = 0, found_dst_ip;

    static char     pwbuf[MAX_PASS_LEN + 1]     = {0};
    char            conf_line_buf[MAX_LINE_LEN] = {0};
    char            tmp_char_buf[MAX_LINE_LEN]  = {0};
    char           *lptr;

    if ((pwfile_ptr = fopen(pw_file, "r")) == NULL)
    {
        fprintf(stderr, "[*] Could not open config file: %s\n", pw_file);
        exit(EXIT_FAILURE);
    }

    while ((fgets(conf_line_buf, MAX_LINE_LEN, pwfile_ptr)) != NULL)
    {
        numLines++;
        conf_line_buf[MAX_LINE_LEN-1] = '\0';
        lptr = conf_line_buf;

        memset(tmp_char_buf, 0x0, MAX_LINE_LEN);

        while (*lptr == ' ' || *lptr == '\t' || *lptr == '=')
            lptr++;

        /* Get past comments and empty lines.
        */
        if (*lptr == '#' || *lptr == '\n' || *lptr == '\r' || *lptr == '\0' || *lptr == ';')
            continue;

        /* Look for a line like "<SPA destination IP>: <password>" - this allows
        * multiple keys to be placed within the same file, and the client will
        * reference the matching one for the SPA server we are contacting
        */
        found_dst_ip = 1;
        for (i=0; i < strlen(dst_ip_str); i++)
            if (*lptr++ != dst_ip_str[i])
                found_dst_ip = 0;

        if (! found_dst_ip)
            continue;

        if (*lptr == ':')
            lptr++;
        else
            continue;

        /* Skip whitespace until we get to the password
        */
        while (*lptr == ' ' || *lptr == '\t' || *lptr == '=')
            lptr++;

        i = 0;
        while (*lptr != '\0') {
            pwbuf[i] = *lptr;
            lptr++;
            i++;
        }
        pwbuf[i] = '\0';
    }

    fclose(pwfile_ptr);

    if (pwbuf[0] == '\0') {
        fprintf(stderr, "[*] Could not get password for IP: %s from: %s\n",
            dst_ip_str, pw_file);
        exit(EXIT_FAILURE);
    }

    return pwbuf;
}

/***EOF***/
