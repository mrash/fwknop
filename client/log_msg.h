/**
 * \file    client/log_msg.h
 *
 * \brief   Header file for log_msg.c
 */

/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
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

#ifndef LOG_MSG_H
#define LOG_MSG_H

typedef enum
{
    LOG_FIRST_VERBOSITY = 0,
    LOG_VERBOSITY_ERROR = 0,    /*!< Constant to define a ERROR message */
    LOG_VERBOSITY_WARNING,      /*!< Constant to define a WARNING message */
    LOG_VERBOSITY_NORMAL,       /*!< Constant to define a NORMAL message */
    LOG_VERBOSITY_INFO,         /*!< Constant to define a INFO message */
    LOG_VERBOSITY_DEBUG,        /*!< Constant to define a DEBUG message */
    LOG_LAST_VERBOSITY
} log_level_t;

#define LOG_DEFAULT_VERBOSITY   LOG_VERBOSITY_NORMAL    /*!< Default verbosity to use */

void log_new(void);
void log_free(void);
void log_set_verbosity(int level);
void log_msg(int verbosity_level, char *msg, ...);

#endif /* LOG_MSG_H */

/***EOF***/
