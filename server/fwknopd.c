/* $Id$
 *****************************************************************************
 *
 * File:    fwknopd.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: An implementation of an fwknop server.
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
#include <sys/file.h>

#include "fwknopd.h"
#include "config_init.h"
#include "process_packet.h"
#include "pcap_capture.h"
#include "log_msg.h"
#include "utils.h"
#include "sig_handler.h"
#include "replay_dbm.h"

/* Prototypes
*/
static void daemonize_process(fko_srv_options_t *opts);
static int write_pid_file(fko_srv_options_t *opts);
static pid_t get_running_pid(fko_srv_options_t *opts);

int
main(int argc, char **argv)
{
    fko_ctx_t           ctx;
    int                 res, last_sig, rpdb_count;
    char               *spa_data, *version;
    char                access_buf[MAX_LINE_LEN];
    pid_t               old_pid;

    fko_srv_options_t   opts;

    while(1)
    {
        /* Handle command line
        */
        config_init(&opts, argc, argv);

        /* Process any options that do their thing and exit. */

        /* Show config and exit dump config was wanted.
        */
        if(opts.dump_config == 1)
        {
            dump_config(&opts);
            exit(EXIT_SUCCESS);
        }

        /* Kill the currently running fwknopd?
        */
        if(opts.kill == 1)
        {
            old_pid = get_running_pid(&opts);

            if(old_pid > 0)
            {
                res = kill(old_pid, SIGTERM);
                if(res == 0)
                {
                    fprintf(stderr, "Killed fwknopd (pid=%i)\n", old_pid);
                    exit(EXIT_SUCCESS);
                }
                else
                {
                    perror("Unable to kill fwknop: ");
                    exit(EXIT_FAILURE);
                }
            }
            else
            {
                fprintf(stderr, "No running fwknopd detected.\n", old_pid);
                exit(EXIT_FAILURE);
            }
        }

        /* Restart the currently running fwknopd?
        */
        if(opts.restart == 1)
        {
            old_pid = get_running_pid(&opts);

            if(old_pid > 0)
            {
                res = kill(old_pid, SIGHUP);
                if(res == 0)
                {
                    fprintf(stderr, "Sent restart signal to fwknopd (pid=%i)\n", old_pid);
                    exit(EXIT_SUCCESS);
                }
                else
                {
                    perror("Unable to send signal to fwknop: ");
                    exit(EXIT_FAILURE);
                }
            }
            else
            {
                fprintf(stderr, "No running fwknopd detected.\n", old_pid);
                exit(EXIT_FAILURE);
            }
        }

        /* Status of the currently running fwknopd?
        */
        if(opts.status == 1)
        {
            fprintf(stderr, "Status option not implemented yet.\n");
            exit(EXIT_SUCCESS);
        }

        /* Initialize logging.
        */
        init_logging(&opts);

        if(get_running_pid(&opts) != getpid())
        {
            /* If foreground mode is not set, the fork off and become a daemon.
            * Otherwise, attempt to get the pid fiel lock and go on.
            */
            if(opts.foreground == 0)
            {
                daemonize_process(&opts);
            }
            else
            {
                old_pid = write_pid_file(&opts);
                if(old_pid > 0)
                {
                    fprintf(stderr,
                        "* An instance of fwknopd is already running: (PID=%i).\n", old_pid
                    );

                    exit(EXIT_FAILURE);
                }
                else if(old_pid < 0)
                {
                    fprintf(stderr, "* PID file error. The lock may not be effective.\n");
                }
            }

            log_msg(LOG_INFO, "Starting %s", MY_NAME);
        }
        else
        {
            log_msg(LOG_INFO, "Re-starting %s", MY_NAME);
        }

        dump_config(&opts);

        if((strncasecmp(opts.config[CONF_AUTH_MODE], "pcap", 4)) != 0)
        {
            log_msg(LOG_ERR|LOG_STDERR,
                "Capture/auth mode other than 'PCAP' is not supported."
            );
            exit(EXIT_FAILURE);
        }

        /* Initialize the digest cache (replay attack detection dbm).
        */
        rpdb_count = replay_db_init(&opts);

fprintf(stderr, "RPDB Count: %i\n", rpdb_count);

        /* Intiate pcap capture mode...
        */
        pcap_capture(&opts);

        if(last_sig = got_signal) {
            got_signal = 0;
            if(got_sighup)
            {
                log_msg(LOG_WARNING|LOG_STDERR, "Got SIGHUP.  Re-reading configs.");
                free_configs(&opts);
                got_sighup = 0;
            }
            else if(got_sigint)
            {
                log_msg(LOG_WARNING|LOG_STDERR, "Got SIGINT.  Exiting...");
                got_sigint = 0;
                break;
            }
            else if(got_sigterm)
            {
                log_msg(LOG_WARNING|LOG_STDERR, "Got SIGTERM.  Exiting...");
                got_sigterm = 0;
                break;
            }
            else
            {
                log_msg(LOG_WARNING|LOG_STDERR,
                    "Got signal %i. No defined action but to exit.", last_sig);
                break;
            }
        }
        else    /* got_signal was not set (should be if we are here) */
        {
            log_msg(LOG_WARNING|LOG_STDERR,
                "Capture ended without signal.  Exiting...");
            break;
        }
    }

    /* Other cleanup.
    */
    free_logging();
    free_configs(&opts);

    return(0);
}

/* Become a daemon: fork(), start a new session, chdir "/",
 * and close unneeded standard filehandles.
*/
static void
daemonize_process(fko_srv_options_t *opts)
{
    pid_t pid, old_pid;

    /* Reset the our umask
    */
    umask(0);

    if ((pid = fork()) < 0)
    {
        perror("Unable to fork: ");
        exit(EXIT_FAILURE);
    }
    else if (pid != 0) /* parent */
    {
        exit(EXIT_SUCCESS);
    }

    /* Child process from here on out */

    /* Start a new session
    */
    setsid();

    /* Create the PID file (or be blocked by an existing one).
    */
    old_pid = write_pid_file(opts);
    if(old_pid > 0)
    {
        fprintf(stderr,
            "* An instance of fwknopd is already running: (PID=%i).\n", old_pid
        );

        exit(EXIT_FAILURE);
    }
    else if(old_pid < 0)
    {
        fprintf(stderr, "* PID file error. The lock may not be effective.\n");
    }

    /* Chdir to the root of the filesystem 
    */
    if ((chdir("/")) < 0) {
        perror("Could not chdir() to /: ");
        exit(EXIT_FAILURE);
    }

    /* Close un-needed file handles
    */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    return;
}

static int
write_pid_file(fko_srv_options_t *opts)
{
    pid_t   old_pid, my_pid;
    int     op_fd, lck_res;
    char    buf[6]  = {0};

    /* Reset errno (just in case)
    */
    errno = 0;

    /* Open the PID file
    */
    op_fd = open(
        opts->config[CONF_FWKNOP_PID_FILE], O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR
    );

    if(op_fd == -1)
    {
        perror("Error trying to open PID file: ");
        return -1;
    }

    /* Attempt to lock the PID file.  If we get an EWOULDBLOCK
     * error, another instance already has the lock. So we grab
     * the pid from the existing lock file, complain and bail.
    */
    lck_res = flock(op_fd, LOCK_EX|LOCK_NB);
    if(lck_res == -1)
    {
        if(errno != EWOULDBLOCK)
        {
            perror("Unexpected error from flock: ");
            return -1;
        }

        close(op_fd);

        /* Look for an existing lock holder. If we get a pid return it.
        */
        old_pid = get_running_pid(opts);
        if(old_pid)
            return old_pid;
 
        /* Otherwise, consider it an error.
        */
        perror("Unable read existing PID file: ");
        return -1;
    }

    /* Write our PID to the file
    */
    my_pid = getpid();
    snprintf(buf, 6, "%i\n", my_pid);

    if(opts->verbose)
        fprintf(stderr, "[+] Writing my PID (%i) to the lock file: %s\n",
            my_pid, opts->config[CONF_FWKNOP_PID_FILE]);

    write(op_fd, buf, strlen(buf));

    if(errno)
        perror("Lock may not be valid. PID file write error: ");

    /* Sync/flush regardless...
    */
    fsync(op_fd);

    return 0;
}

static pid_t
get_running_pid(fko_srv_options_t *opts)
{
    int     op_fd;
    char    buf[6]  = {0};
    pid_t   rpid    = 0;

    op_fd = open(opts->config[CONF_FWKNOP_PID_FILE], O_RDONLY);

    if(op_fd > 0)
    {
        read(op_fd, buf, 6);
        rpid = (pid_t)atoi(buf);
        close(op_fd);
    }

    return(rpid);
}

/***EOF***/
