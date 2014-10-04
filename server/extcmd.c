/*
 *****************************************************************************
 *
 * File:    extcmd.c
 *
 * Purpose: Routines for executing and processing external commands.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
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
#include "fwknopd_common.h"
#include "extcmd.h"
#include "log_msg.h"
#include "utils.h"

#include <errno.h>
#include <signal.h>

#if HAVE_SYS_WAIT_H
  #include <sys/wait.h>
#endif

/*
static sig_atomic_t got_sigalrm; 
*/

/* Takes a file descriptor and makes it non-blocking.
static int
set_nonblock(int fd)
{
    int val;

    if((val = fcntl(fd, F_GETFL, 0)) < 0)
    {
        perror("fcntl F_GETFL error:");
        return(-1);
    }

    val |= O_NONBLOCK;

    if(fcntl(fd, F_SETFL, val) < 0)
    {
        perror("fcntl F_SETFL error setting O_NONBLOCK");
        return(-1);
    }

    return(0);
}

static void 
alarm_handler(int sig)
{
    got_sigalrm = 1;
}
*/

/* Run an external command returning exit status, and optionally filling
 * provided  buffer with STDOUT output up to the size provided.
 *
 * Note: XXX: We are not using the timeout parameter at present. We still need
 *       to implement a reliable timeout mechanism.
*/
static int
_run_extcmd(uid_t user_uid, const char *cmd, char *so_buf, const size_t so_buf_sz,
        const int timeout, const fko_srv_options_t * const opts)
{
    FILE   *ipt;
    int     retval = 0;
    char    so_read_buf[IO_READ_BUF_LEN] = {0};
    int     res;

    char   *argv_new[MAX_CMDLINE_ARGS]; /* for execvpe() */
    int     argc_new=0;
    int     pipe_fd[2];
    pid_t   pid=0;
    FILE   *output;
    int     status;

    memset(argv_new, 0x0, sizeof(argv_new));

    if(strtoargv(cmd, argv_new, &argc_new, opts) != 1)
    {
        log_msg(LOG_ERR, "Error converting cmd str to argv");
        return(-1);
    }

    if(so_buf != NULL)
    {
        if(pipe(pipe_fd) < 0)
        {
            log_msg(LOG_ERR, "[*] pipe() error");
            free_argv(argv_new, &argc_new);
            return -1;
        }
    }

    pid = fork();
    if (pid == 0)
    {
        if(so_buf != NULL)
        {
            close(pipe_fd[0]);
            dup2(pipe_fd[1], STDOUT_FILENO);
            dup2(pipe_fd[1], STDERR_FILENO);
        }

        /* don't use env
        */
        execvpe(argv_new[0], argv_new, (char * const *)NULL);
    }
    else if(pid == -1)
    {
        log_msg(LOG_ERR, "[*] Could not fork() for cmd.");
        free_argv(argv_new, &argc_new);
        return -1;
    }

    /* Only the parent process makes it here
    */
    if(so_buf != NULL)
    {
        close(pipe_fd[1]);
        if ((output = fdopen(pipe_fd[0], "r")) != NULL)
        {
            memset(so_buf, 0x0, so_buf_sz);

            while((fgets(so_read_buf, IO_READ_BUF_LEN, output)) != NULL)
            {
                strlcat(so_buf, so_read_buf, so_buf_sz);

                if(strlen(so_buf) >= so_buf_sz-1)
                    break;
            }
            fclose(output);
        }
        else
        {
            log_msg(LOG_ERR,
                    "[*] Could not fdopen() pipe output file descriptor.");
            free_argv(argv_new, &argc_new);
            return -1;
        }
    }

    waitpid(pid, &status, 0);

    free_argv(argv_new, &argc_new);

    return(retval);



    if(so_buf == NULL)
    {

        /* Since we do not have to capture output, we will fork here (which we
         * would have to do anyway if we are running as another user as well).
        */
        pid = fork();
        if(pid == -1)
        {
            log_msg(LOG_ERR, "run_extcmd: fork failed: %s", strerror(errno));
            return(EXTCMD_FORK_ERROR);
        }
        else if (pid == 0)
        {
            /* We are the child */
            /* If user is not null, then we setuid to that user before running the
            * command.
            */
            if(user_uid > 0)
            {
                if(setuid(user_uid) < 0)
                {
                    exit(EXTCMD_SETUID_ERROR);
                }
            }
            res = system(cmd);
            exit(WEXITSTATUS(res));
        }

        /* Retval is forced to 0 as we don't care about the exit status of
         * the child (for now)>
        */
        retval = 0;
    }
    else
    {
        /* Looking for output use popen and fill the buffer to its limit.
        */
        ipt = popen(cmd, "r");

        if(ipt == NULL)
        {
            log_msg(LOG_ERR, "Got popen error %i:  %s", errno, strerror(errno));
            retval = -1;
        }
        else
        {
            memset(so_buf, 0x0, so_buf_sz);

            while((fgets(so_read_buf, IO_READ_BUF_LEN, ipt)) != NULL)
            {
                strlcat(so_buf, so_read_buf, so_buf_sz);

                if(strlen(so_buf) >= so_buf_sz-1)
                    break;
            }

            pclose(ipt);
        }
    }

    return(retval);
}


#if 0 /* --DSS the original method that did not work on some systems */

    /* Create the pipes we will use for getting stdout and stderr
     * from the child process.
    */
    if(pipe(so) != 0)
        return(EXTCMD_PIPE_ERROR);

    if(pipe(se) != 0)
        return(EXTCMD_PIPE_ERROR);

    /* Fork off a child process to run the command and provide its outputs.
    */
    pid = fork();
    if(pid == -1)
    {
        return(EXTCMD_FORK_ERROR);
    }
    else if (pid == 0)
    {
        /* We are the child, so we dup stdout and stderr to our respective
         * write-end of the pipes, close stdin and the read-end of the pipes
         * (since we don't need them here).  Then use system() to run the
         * command and exit with the exit status of that command so we can
         * grab it from the waitpid call in the parent.
        */
        close(fileno(stdin));
        dup2(so[1], fileno(stdout));
        dup2(se[1], fileno(stderr));
        close(so[0]);
        close(se[0]);

        /* If user is not null, then we setuid to that user before running the
         * command.
        */
        if(user_uid > 0)
        {
            if(setuid(user_uid) < 0)
            {
                exit(EXTCMD_SETUID_ERROR);
            }
        }

        /* --DSS XXX: Would it be more efficient to use one of the exec()
         *            calls (i.e. 'return(execvp(ext_cmd, &argv[1]));')?
         *            For now, we use system() and exit with the external
         *            command exit status.
        */
        exit(WEXITSTATUS(system(cmd)));
    }

    /* Parent from here */

    /* Give the exit status an initial value of -1.
    */
    *status = -1;

    /* Close the write-end of the pipes (we are only reading).
    */
    close(so[1]);
    close(se[1]);

    /* Set our pipes to non-blocking
    */
    set_nonblock(so[0]);
    set_nonblock(se[0]);

    tv.tv_sec = EXTCMD_DEF_TIMEOUT;
    tv.tv_usec = 0;

    /* Initialize and setup our file descriptor sets for select.
    */
    FD_ZERO(&rfds);
    FD_ZERO(&efds);
    FD_SET(so[0], &rfds);
    FD_SET(se[0], &rfds);
    FD_SET(so[0], &efds);
    FD_SET(se[0], &efds);

    /* Start with fully clear buffers.
    */
    memset(so_buf, 0x0, so_buf_sz);
    memset(se_buf, 0x0, se_buf_sz);

    /* Read both stdout and stderr piped from the child until we get eof,
     * fill the buffers, or error out.
    */
    while(so_buf_remaining > 0 || se_buf_remaining > 0)
    {
        selval = select(8, &rfds, NULL, &efds, &tv);

        if(selval == -1)
        {
            /* Select error - so kill the child and bail.
            */
            kill(pid, SIGTERM);
            retval |= EXTCMD_SELECT_ERROR;
            break;
        }

        if(selval == 0)
        {
            /* Timeout - so kill the child and bail
            */
            kill(pid, SIGTERM);
            retval |= EXTCMD_EXECUTION_TIMEOUT;
            break;
        }

        /* The stdout pipe...
        */
        bytes_read = read(so[0], so_read_buf, IO_READ_BUF_LEN);
        if(so_buf_remaining > 0)
        {
            if(bytes_read > 0)
            {
                /* We have data, so process it...
                */
                if(bytes_read > so_buf_remaining)
                {
                    bytes_read = so_buf_remaining;
                    retval |= EXTCMD_SUCCESS_PARTIAL_STDOUT;
                }

                memcpy(so_buf, so_read_buf, bytes_read);
                so_buf += bytes_read;
                so_buf_remaining -= bytes_read;
            }
            else if(bytes_read < 0)
            {
                /* Anything other than EAGAIN or EWOULDBLOCK is conisdered
                 * error enough to bail.  We are done here so we force the
                 * buf_remaining value to 0.
                */
                if(errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    retval |= EXTCMD_STDOUT_READ_ERROR;
                    so_buf_remaining = 0;
                }
            }
            else
            {
                /* Bytes read was 0 which indicate end of file. So we are
                 * done.
                */
                so_buf_remaining = 0;
            }
        }
        else
            break;

        /* The stderr pipe...
        */
        bytes_read = read(se[0], se_read_buf, IO_READ_BUF_LEN);
        if(se_buf_remaining > 0)
        {
            if(bytes_read > 0)
            {
                /* We have data, so process it...
                */
                if(bytes_read > se_buf_remaining)
                {
                    bytes_read = se_buf_remaining;
                    retval |= EXTCMD_SUCCESS_PARTIAL_STDERR;
                }

                memcpy(se_buf, se_read_buf, bytes_read);
                se_buf += bytes_read;
                se_buf_remaining -= bytes_read;
            }
            else if(bytes_read < 0)
            {
                /* Anything other than EAGAIN or EWOULDBLOCK is conisdered
                 * error enough to bail.  We are done here so we force the
                 * buf_remaining value to 0.
                */
                if(errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    retval |= EXTCMD_STDERR_READ_ERROR;
                    se_buf_remaining = 0;
                }
            }
            else
            {
                /* Bytes read was 0 which indicate end of file. So we are
                 * done.
                */
                se_buf_remaining = 0;
            }
        }
        else
            break;
    }

    close(so[0]);
    close(se[0]);

    /* Wait for the external command to finish and capture its exit status.
    */
    waitpid(pid, status, 0);

    if(*status != 0)
        retval != EXTCMD_EXECUTION_ERROR;

    /* Return the our status of this operation command.
    */
    return(retval);
}
#endif

/* Run an external command.  This is wrapper around _run_extcmd()
*/
int
run_extcmd(const char *cmd, char *so_buf, const size_t so_buf_sz,
        const int timeout, const fko_srv_options_t * const opts)
{
    return _run_extcmd(0, cmd, so_buf, so_buf_sz, timeout, opts);
}

/* Run an external command as the specified user.  This is wrapper around _run_extcmd()
*/
int
run_extcmd_as(uid_t user_uid, const char *cmd,char *so_buf, const size_t so_buf_sz,
        const int timeout, const fko_srv_options_t * const opts)
{
    return _run_extcmd(user_uid, cmd, so_buf, so_buf_sz, timeout, opts);
}
