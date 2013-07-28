/*
 *****************************************************************************
 *
 * File:    sig_handler.h
 *
 * Author:  Damien Stuart (dstuart@dstuart.org)
 *
 * Purpose: Header file for sig_handler functions and data.
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
#ifndef SIG_HANDLER_H
#define SIG_HANDLER_H

#include <signal.h>

extern sig_atomic_t got_signal;

extern sig_atomic_t got_sighup;
extern sig_atomic_t got_sigint;
extern sig_atomic_t got_sigterm;
extern sig_atomic_t got_sigusr1;
extern sig_atomic_t got_sigusr2;
extern sig_atomic_t got_sigchld;

void sig_handler(int sig);
int set_sig_handlers(void);

#endif /* SIG_HANDLER_H */

/***EOF***/
