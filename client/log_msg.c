/**
 * @file    log_msg.c
 *
 * @author  Damien S. Stuart
 *
 * @brief   General logging routine that can write to stderr
 *          and can take variable number of args.
 *
 * Copyright 2009-2010 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU Public License):
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
 */

/* TODO : Normal/info/debug message should go to stdout */

#include "fwknop_common.h"
#include "log_msg.h"
#include <stdarg.h>

#define LOG_STREAM              stderr                  /*!< All of the messages log by the module are sent to the sderr stream */

typedef struct
{
    int verbosity;
} log_ctx_t;

static log_ctx_t log_ctx;

/**
 * Set up the context for the log module.
 *
 * This function only initialize the verbosity level
 */
void
log_new(void)
{
    log_ctx.verbosity = LOG_DEFAULT_VERBOSITY;
}

/**
 * Destroy the context for the log module.
 *
 * This function is not used at the moment since the module does not open file
 * which would require to be closed;
 */
void
log_free(void)
{
}

/**
 * Set the verbosity level
 *
 * The function set the verbosity level for the current context of the log
 * module. New messages with a higher priority will not be printed afterwards.
 * For example setting the verbosity to LOG_VERBOSITY_WARNING will not
 * print a message with a priority set to LOG_VERBOSITY_NORMAL to the stream
 * LOG_STREAM.
 * 
 * @param level verbosity level to set
 */
void
log_set_verbosity(int level)
{
    log_ctx.verbosity = level;
}

/**
 * Send a message to LOG_STREAM
 *
 * Print a message to LOG_STREAM according to the context verbosity.
 * 
 * @param level Verbosity level to used for the message.
 * @param msg   Message to print
 */
void
log_msg(int level, char* msg, ...)
{
    va_list ap;

    /* Send the message only to the stream for messages with a verbosity
     * equal or lower than the verbosity context. */
    if (level <= log_ctx.verbosity)
    {
        va_start(ap, msg);
        vfprintf(LOG_STREAM, msg, ap);
        fprintf(LOG_STREAM, "\n");
        va_end(ap);
    }
    else;
}

/***EOF***/
