/*
 *****************************************************************************
 *
 * File:    log_msg.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: General logging routine that can write to syslog and/or stderr
 *          and can take varibale number of args.
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
#include "fwknopd_common.h"
#include "log_msg.h"

void log_msg(int level, char* msg, ...)
{
    va_list ap, apse;

    va_start(ap, msg);

    /* Print msg to stderr if the level was or'ed with LOG_STDERR
    */
    if(LOG_STDERR & level)
    {
        /* Need to make a copy of our va_list so we don't screw
         * up the message going to syslog after we print it to stderr.
        */
        va_copy(apse, ap);

        vfprintf(stderr, msg, apse);
        fprintf(stderr, "\n");

        va_end(apse);

        if(LOG_STDERR_ONLY & level)
            return;

        /* Remove the log to stderr flag from the log level value.
        */
        level &= LOG_STDERR_MASK;
    }

    /* Send the message to syslog.
    */
    openlog(MY_NAME, LOG_PID, LOG_DAEMON);

    vsyslog(level, msg, ap);

    va_end(ap);
}

/***EOF***/
