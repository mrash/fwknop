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
static void check_dir_path(const char *path, const char *path_name, unsigned char use_basename);
static int make_dir_path(const char *path);
static void daemonize_process(fko_srv_options_t *opts);
static int write_pid_file(fko_srv_options_t *opts);
static pid_t get_running_pid(fko_srv_options_t *opts);

int
main(int argc, char **argv)
{
    fko_ctx_t           ctx;
    int                 res, last_sig, rpdb_count;
    char               *spa_data, *version;
    char               *locale;
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

#if HAVE_LOCALE_H
        /* Set the locale if specified.
        */
        if(opts.config[CONF_LOCALE] != NULL)
        {
            locale = setlocale(LC_ALL, opts.config[CONF_LOCALE]);

            if(locale == NULL)
            {
                log_msg(LOG_ERR|LOG_STDERR,
                    "WARNING: Unable to set locale to %s.",
                    opts.config[CONF_LOCALE]
                );
            }
            else
            {
                if(opts.verbose)
                    log_msg(LOG_ERR|LOG_STDERR,
                        "Locale set to %s.", opts.config[CONF_LOCALE]
                    );
            }
        }
#endif

        /* Make sure we have a valid run dir and path leading to digest file
         * in case it configured to be somewhere other than the run dir.
        */
        check_dir_path((const char *)opts.config[CONF_FWKNOP_RUN_DIR], "Run", 0);
        check_dir_path((const char *)opts.config[CONF_DIGEST_FILE], "Run", 1);

        /* If we are a new process (just being started), proceed with normal
         * startp.  Otherwise, we are here as a result of a signal sent to an
         * existing process and we want to restart.
        */
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

        /* We only support pcap capture at this point.
        */
        if((strncasecmp(opts.config[CONF_AUTH_MODE], "pcap", 4)) != 0)
        {
            log_msg(LOG_ERR|LOG_STDERR,
                "Capture/auth mode other than 'PCAP' is not supported."
            );
            exit(EXIT_FAILURE);
        }

        if(opts.verbose > 1)
            dump_config(&opts);

        /* Initialize the digest cache (replay attack detection dbm)
         * if so configured.
        */
        if(strncasecmp(opts.config[CONF_ENABLE_DIGEST_PERSISTENCE], "Y", 1) == 0)
        {
            rpdb_count = replay_db_init(&opts);

            if(opts.verbose)
                log_msg(LOG_ERR|LOG_STDERR,
                    "Using Digest Cache: '%s' (entry count = %i)",
                    opts.config[CONF_DIGEST_FILE], rpdb_count
                );
        }

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
        else if (opts.packet_ctr >= opts.packet_ctr_limit)
        {
            log_msg(LOG_INFO|LOG_STDERR,
                "Packet count limit (%d) reached.  Exiting...",
                opts.packet_ctr_limit);
            break;
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

/* Ensure the specified directory exists.  If not, create it or die.
*/
static void
check_dir_path(const char *filepath, const char *fp_desc, unsigned char use_basename)
{
    struct stat     st;
    int             res;
    char            tmp_path[MAX_PATH_LEN];
    char            *ndx;

    /* 
     * FIXME:  We shouldn't use a hard-coded dir-separator here.
    */
    /* But first make sure we are using an absolute path.
    */
    if(*filepath != '/')
    {
        log_msg(LOG_ERR|LOG_STDERR,
            "Configured %s directory (%s) is not an absolute path.", fp_desc, filepath
        );
        exit(EXIT_FAILURE);
    }

    /* If this is a file path that we want to use only the basename, strip
     * the trailing filename here.
    */
    if(use_basename && ((ndx = strrchr(filepath, '/')) != NULL))
        strlcpy(tmp_path, filepath, (ndx-filepath)+1);
    else
        strcpy(tmp_path, filepath);

    /* At this point, we should make the path is more than just "/".
     * If it is not, silently return.
    */
    if(strlen(tmp_path) < 2)
        return;

    /* Make sure we have a valid directory.
    */
    res = stat(tmp_path, &st);
    if(res != 0)
    {
        if(errno == ENOENT)
        {
            log_msg(LOG_WARNING|LOG_STDERR,
                "%s directory: %s does not exist.  Attempting to create it.", fp_desc, tmp_path
            );

            /* Directory does not exist, so attempt to create it.
            */
            res = make_dir_path(tmp_path);
            if(res != 0)
            {
                log_msg(LOG_ERR|LOG_STDERR,
                    "Unable to create %s directory: %s (error: %i)", fp_desc, tmp_path, errno
                );
                exit(EXIT_FAILURE);
            }

            log_msg(LOG_ERR|LOG_STDERR,
                "Successfully created %s directory: %s", fp_desc, tmp_path
            );
        }
        else
        {
            log_msg(LOG_ERR|LOG_STDERR,
                "Stat of %s returned error %i", tmp_path, errno
            );
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        /* It is a file, but is it a directory?
        */
        if(! S_ISDIR(st.st_mode))
        {
            log_msg(LOG_ERR|LOG_STDERR,
                "Specified %s directory: %s is NOT a directory\n\n", fp_desc, tmp_path
            );
            exit(EXIT_FAILURE);
        }
    }
}

static int
make_dir_path(const char *run_dir)
{
    struct stat     st;
    int             res, len;
    char            tmp_path[MAX_PATH_LEN];
    char            *ndx;

    strlcpy(tmp_path, run_dir, MAX_PATH_LEN);

    len = strlen(tmp_path);

    /* Strip any trailing dir sep char.
    */
    if(tmp_path[len-1] == '/')
        tmp_path[len-1] = '\0';

    for(ndx = tmp_path+1; *ndx; ndx++)
    {
        if(*ndx == '/')
        {
            *ndx = '\0';

            /* Stat this part of the path to see if it is a valid directory.
             * If it does not exist, attempt to create it. If it does, and
             * it is a directory, go on.  Otherwise, any other error cause it
             * to bail.
            */
            if(stat(tmp_path, &st) != 0)
            {
                if(errno == ENOENT)
                    res = mkdir(tmp_path, S_IRWXU);

                if(res != 0)
                    return res;
            }

            if(! S_ISDIR(st.st_mode))
            {
                log_msg(LOG_ERR|LOG_STDERR,
                    "Component: %s of %s is NOT a directory\n\n", tmp_path, run_dir
                );
                return(ENOTDIR);
            }

            *ndx = '/';
        }
    }

    res = mkdir(tmp_path, S_IRWXU);

    return(res);
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
