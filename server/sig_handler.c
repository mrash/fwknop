/*
 *****************************************************************************
 *
 * File:    sig_handler.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Signal handling dta and routines for fwknopd.
 *
 * Copyright 2010-2013 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *****************************************************************************
*/
#include "fwknopd_common.h"
#include "log_msg.h"
#include "sig_handler.h"

#if HAVE_SYS_WAIT_H
  #include <sys/wait.h>
#endif

sig_atomic_t got_signal     = 0;    /* General signal flag (break capture) */

sig_atomic_t got_sighup     = 0;    /* SIGHUP flag  */
sig_atomic_t got_sigint     = 0;    /* SIGINT flag  */
sig_atomic_t got_sigterm    = 0;    /* SIGTERM flag */
sig_atomic_t got_sigusr1    = 0;    /* SIGUSR1 flag */
sig_atomic_t got_sigusr2    = 0;    /* SIGUSR2 flag */
sig_atomic_t got_sigchld    = 0;    /* SIGCHLD flag */

sigset_t    *csmask;

/* SIGHUP Handler
*/
void
sig_handler(int sig)
{
    int o_errno;
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
        case SIGCHLD:
            o_errno = errno; /* Save errno */
            got_sigchld = 1;
            waitpid(-1, NULL, WNOHANG);
            errno = o_errno; /* restore errno (in case reset by waitpid) */
            return;
    }
}

/* Setup signal handlers
*/
int
set_sig_handlers(void)
{
    int                 err = 0;
    struct sigaction    act;

    /* Clear the signal flags.
    */
    got_signal     = 0;
    got_sighup     = 0;
    got_sigint     = 0;
    got_sigterm    = 0;
    got_sigusr1    = 0;
    got_sigusr2    = 0;

    /* Setup the handlers
    */
    act.sa_handler = sig_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;

    if(sigaction(SIGHUP, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* Error setting SIGHUP handler: %s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGINT, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* Error setting SIGINT handler: %s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGTERM, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* Error setting SIGTERM handler: %s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGUSR1, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* Error setting SIGUSR1 handler: %s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGUSR2, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* Error setting SIGUSR2 handler: %s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGCHLD, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* Error setting SIGCHLD handler: %s",
            strerror(errno));
        err++;
    }

    return(err);
}

/***EOF***/
