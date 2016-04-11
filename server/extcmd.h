/**
 * \file server/extcmd.h
 *
 * \brief Header file for extcmd.c.
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
 *
 *****************************************************************************
*/
#ifndef EXTCMD_H
#define EXTCMD_H

#define IO_READ_BUF_LEN     256
#define EXTCMD_DEF_TIMEOUT  15
#define NO_TIMEOUT          0
#define WANT_STDERR         0x01
#define WANT_STDOUT_GETLINE 0x02
#define ALLOW_PARTIAL_LINES 0x04
#define NO_STDERR           0
#define ROOT_UID            0
#define ROOT_GID            0

/* The various return status states in which an external command result
 * may end up in.
*/
enum {
    EXTCMD_WRITE_ERROR              =   -9,
    EXTCMD_CHDIR_ERROR              =   -8,
    EXTCMD_OPEN_ERROR               =   -7,
    EXTCMD_ARGV_ERROR               =   -6,
    EXTCMD_SETGID_ERROR             =   -5,
    EXTCMD_SETUID_ERROR             =   -4,
    EXTCMD_SELECT_ERROR             =   -3,
    EXTCMD_PIPE_ERROR               =   -2,
    EXTCMD_FORK_ERROR               =   -1,
    EXTCMD_SUCCESS_ALL_OUTPUT       = 0x00,
    EXTCMD_SUCCESS_PARTIAL_STDOUT   = 0x01,
    EXTCMD_SUCCESS_PARTIAL_STDERR   = 0x02,
    EXTCMD_STDOUT_READ_ERROR        = 0x04,
    EXTCMD_STDERR_READ_ERROR        = 0x08,
    EXTCMD_EXECUTION_ERROR          = 0x10,
    EXTCMD_EXECUTION_TIMEOUT        = 0x20
};

/* Some convenience macros for testing the extcmd return status.
*/
#define EXTCMD_IS_SUCCESS(x) (x == EXTCMD_SUCCESS_ALL_OUTPUT)
#define EXTCMD_IS_SUCCESS_PARTIAL_STDOUT(x) (x && EXTCMD_SUCCESS_PARTIAL_STDOUT)
#define EXTCMD_IS_SUCCESS_PARTIAL_STDERR(x) (x && EXTCMD_SUCCESS_PARTIAL_STDERR)
#define EXTCMD_IS_SUCCESS_PARTIAL_OUTPUT(x) \
    ((x && EXTCMD_SUCCESS_PARTIAL_STDOUT) \
        || x && EXTCMD_SUCCESS_PARTIAL_STDERR)
#define EXTCMD_STDOUT_READ_ERROR(x) (x && EXTCMD_STDOUT_READ_ERROR)
#define EXTCMD_STDERR_READ_ERROR(x) (x && EXTCMD_STDERR_READ_ERROR)
#define EXTCMD_READ_ERROR(x) \
    ((x && EXTCMD_STDOUT_READ_ERROR) \
        || x && EXTCMD_STDERR_READ_ERROR)
#define EXTCMD_EXECUTION_ERROR(x) (x && EXTCMD_EXECUTION_ERROR)

#define EXTCMD_NOERROR(x,y) ((y == 0) \
    && (EXTCMD_IS_SUCCESS(x) || EXTCMD_IS_SUCCESS_PARTIAL_OUTPUT(x))

/* Function prototypes
*/



/**
 * \brief Runs an external command
 *
 * This function is actually a wrapper for _run_extcmd().
 * Run an external command returning exit status, and optionally filling
 * provided buffer with STDOUT output up to the size provided.
 *
 * \param cmd Command to run
 * \param so_buf Buffer for command output, or null pointer to discard output
 * \param so_buf_sz length of so_buf
 * \param want_stderr Flag indicating stderr is to be saved
 * \param timeout Placeholder, the timeout is not used
 * \param pid_status Pointer where the command status is stored
 * \param opts Program options struct
 *
 */
int run_extcmd(const char *cmd, char *so_buf, const size_t so_buf_sz,
        const int want_stderr, const int timeout, int *pid_status,
        const fko_srv_options_t * const opts);

/**
 * \brief Runs an external command as a given user and group
 *
 * This function is actually a wrapper for _run_extcmd().
 * Run an external command returning exit status, and optionally filling
 * provided buffer with STDOUT output up to the size provided.
 * This function takes a user ID and Group ID to use when running the command.
 *
 * \param uid User to run as
 * \param gid Group to run as
 * \param cmd Command to run
 * \param so_buf Buffer for command output
 * \param so_buf_sz length of so_buf
 * \param want_stderr Flag indicating stderr is to be saved
 * \param timeout Placeholder, the timeout is not used
 * \param pid_status Pointer where the command status is stored
 * \param opts Program options struct
 *
 */
int run_extcmd_as(uid_t uid, gid_t gid, const char *cmd, char *so_buf,
        const size_t so_buf_sz, const int want_stderr, const int timeout,
        int *pid_status, const fko_srv_options_t * const opts);

/**
 * \brief Runs an external command, searching for a substring
 *
 * This function is actually a wrapper for _run_extcmd().
 * Run an external command returning exit status, and optionally filling
 * provided buffer with STDOUT output up to the size provided.
 *
 * \param cmd Command to run
 * \param want_stderr Flag indicating stderr is to be saved
 * \param timeout Placeholder, the timeout is not used
 * \param substr_search The substring to search for
 * \param pid_status Pointer where the command status is stored
 * \param opts Program options struct
 *
 * \return Returns line number where the substring was matched, or 0 for no match
 */
int search_extcmd(const char *cmd, const int want_stderr,
        const int timeout, const char *substr_search,
        int *pid_status, const fko_srv_options_t * const opts);

/**
 * \brief Runs an external command, returning a line of output
 *
 * This function is actually a wrapper for _run_extcmd().
 * Run an external command returning exit status, and optionally filling
 * provided buffer with STDOUT output up to the size provided.
 * This function searches the command output for the first match against
 * The provided substring, returns the line number that matched,
 * and populates so_buf with that line of output.
 *
 * \param cmd Command to run
 * \param so_buf Buffer for command output
 * \param so_buf_sz length of so_buf
 * \param timeout Placeholder, the timeout is not used
 * \param substr_search The substring to search for
 * \param pid_status Pointer where the command status is stored
 * \param opts Program options struct
 *
 * \return Returns the line number that matched, or 0 for no match
 */
int search_extcmd_getline(const char *cmd, char *so_buf, const size_t so_buf_sz,
        const int timeout, const char *substr_search, int *pid_status,
        const fko_srv_options_t * const opts);

/**
 * \brief Runs an external command, and feeds it stdin
 *
 * This function is actually a wrapper for _run_extcmd_write().
 * Run an external command that expects stdin.
 *
 * \param cmd Command to run
 * \param cmd_write The text to send as stdin
 * \param pid_status Pointer where the command status is stored
 * \param opts Program options struct
 *
 */
int run_extcmd_write(const char *cmd, const char *cmd_write, int *pid_status,
        const fko_srv_options_t * const opts);
#endif /* EXTCMD_H */

/***EOF***/
