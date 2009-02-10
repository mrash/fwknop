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

#include "getpasswd.h"

#define MAX_PASS_LEN    128

/* Generic hex dump function.
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

/***EOF***/
