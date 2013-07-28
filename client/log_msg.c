/**
 * @file    log_msg.c
 *
 * @author  Damien S. Stuart
 *
 * @brief   General logging routine that can write to stderr
 *          and can take variable number of args.
 *
 * Copyright 2009-2013 Damien Stuart (dstuart@dstuart.org)
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
 */

#include "fwknop_common.h"
#include "log_msg.h"
#include <stdarg.h>

#define LOG_STREAM_STDERR   stderr                  /*!< Error and warning messages are redirected to stderr */
#define LOG_STREAM_STDOUT   stdout                  /*!< Normal, info and debug messages are redirected to stdout */

typedef struct
{
    int verbosity;                                  /*!< Verbosity level (LOG_VERBOSITY_DEBUG...*/
} log_ctx_t;

static log_ctx_t log_ctx;                           /*!< Structure to store the context of the module */

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
 * Set the verbosity level for the current context of the log module.
 * 
 * @param level verbosity level to set
 */
void
log_set_verbosity(int level)
{
    log_ctx.verbosity = level;
}

/**
 * Log a message
 *
 * This function sends a message to the stream dedicated to the priority
 * set. If the verbosity for the context is higher than the one used for
 * the message, then the message is discarded.
 * 
 * @param level Verbosity level to used for the message.
 * @param msg   Message to print
 */
void
log_msg(int level, char* msg, ...)
{
    va_list ap;

    if (level <= log_ctx.verbosity)
    {
        va_start(ap, msg);
        
        switch (level)
        {
            case LOG_VERBOSITY_ERROR:
            case LOG_VERBOSITY_WARNING:
                vfprintf(LOG_STREAM_STDERR, msg, ap);
                fprintf(LOG_STREAM_STDERR, "\n");
                break;
            case LOG_VERBOSITY_NORMAL:
            case LOG_VERBOSITY_INFO:
            case LOG_VERBOSITY_DEBUG:
            default : 
                vfprintf(LOG_STREAM_STDOUT, msg, ap);
                fprintf(LOG_STREAM_STDOUT, "\n");
                break;
        }

        va_end(ap);
    }
    else;
}

/***EOF***/
