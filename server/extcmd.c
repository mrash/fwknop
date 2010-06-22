/* extcmd.c
 *
 * A test program to run an external command and capture its
 * stdout and stderr and exit code into varaibles to print later.
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/select.h>
#include <signal.h>
#include "extcmd.h"


/* Takes a file descriptor and makes it non-blocking.
*/
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

/* Run en external command returning exit status, and filling provided
 * buffers with STDOUT an STDERR up to the size provided.
*/
int
run_extcmd(char *cmd, char *so_buf, char *se_buf, size_t so_buf_sz, size_t se_buf_sz, int *status)
{
    pid_t pid;

    struct timeval  tv;
    fd_set          rfds;
    fd_set          efds; 
    int             selval;

    int so[2], se[2];   /* For our pipes */

    int bytes_read;

    char so_read_buf[IO_READ_BUF_LEN];
    char se_read_buf[IO_READ_BUF_LEN];

    /* Set our remaining_buf counters to one less than the given size so we
     * can leave room for a terminating '\0'.
    */
    int so_buf_remaining = (so_buf_sz > 0) ? so_buf_sz-1 : 0;
    int se_buf_remaining = (se_buf_sz > 0) ? se_buf_sz-1 : 0;

    /* Be optimistic :)
    */
    int retval = EXTCMD_SUCCESS_ALL_OUTPUT;

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

        /* --DSS XXX: It would be more efficient to use one of the exec()
         *            calls.  (i.e. 'return(execvp(ext_cmd, &argv[1]));' ).
         *            but for now, we use system() and exit with the external
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
