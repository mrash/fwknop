/*
 *****************************************************************************
 *
 * File:    sig_handler.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Signal handling dta and routines for fwknopd.
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
#include "sig_handler.h"

sig_atomic_t got_signal     = 0;    /* General signal flag (break capture) */

sig_atomic_t got_sighup     = 0;    /* SIGHUP flag  */
sig_atomic_t got_sigint     = 0;    /* SIGINT flag  */
sig_atomic_t got_sigterm    = 0;    /* SIGTERM flag */
sig_atomic_t got_sigusr1    = 0;    /* SIGUSR1 flag */
sig_atomic_t got_sigusr2    = 0;    /* SIGUSR2 flag */

/* SIGHUP Handler
*/
void
sig_handler(int sig)
{
    got_signal = sig;

    switch(sig) {
        case SIGHUP:
            got_sighup = 1;
            return;
        case SIGINT:
            got_sigint = 1;
            return;
        case SIGTERM:
            got_sigterm = 1;
            return;
        case SIGUSR1:
            got_sigusr1 = 1;
            return;
        case SIGUSR2:
            got_sigusr2 = 1;
            return;
    }
}

/* Setup signal handlers
*/
int
set_sig_handlers(void)
{
    int err = 0;

    /* Clear the signal flags.
    */
    got_signal     = 0;
    got_sighup     = 0;
    got_sigint     = 0;
    got_sigterm    = 0;
    got_sigusr1    = 0;
    got_sigusr2    = 0;

    /* Setup the handlers */

    if(signal(SIGHUP, sig_handler) == SIG_ERR)
    {
        log_msg(LOG_ERR|LOG_STDERR, "* Error setting SIGHUP handler");
        err++;
    }

    if(signal(SIGINT, sig_handler) == SIG_ERR)
    {
        log_msg(LOG_ERR|LOG_STDERR, "* Error setting SIGINT handler");
        err++;
    }

    if(signal(SIGTERM, sig_handler) == SIG_ERR)
    {
        log_msg(LOG_ERR|LOG_STDERR, "* Error setting SIGTERM handler");
        err++;
    }

    if(signal(SIGUSR1, sig_handler) == SIG_ERR)
    {
        log_msg(LOG_ERR|LOG_STDERR, "* Error setting SIGUSR1 handler");
        err++;
    }

    if(signal(SIGUSR2, sig_handler) == SIG_ERR)
    {
        log_msg(LOG_ERR|LOG_STDERR, "* Error setting SIGUSR2 handler");
        err++;
    }

    return(err);
}

/***EOF***/
