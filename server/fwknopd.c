/*
 *****************************************************************************
 *
 * File:    fwknopd.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: An implementation of an fwknop server.
 *
 * Copyright 2010-2013 Damien Stuart (dstuart@dstuart.org)
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
 *
 *****************************************************************************
*/
#include "fwknopd.h"
#include "access.h"
#include "config_init.h"
#include "process_packet.h"
#include "pcap_capture.h"
#include "log_msg.h"
#include "utils.h"
#include "fw_util.h"
#include "sig_handler.h"
#include "replay_cache.h"
#include "tcp_server.h"

/* Prototypes
*/
static void check_dir_path(const char * const path,
        const char * const path_name, const unsigned char use_basename);
static int make_dir_path(const char * const path);
static void daemonize_process(fko_srv_options_t * const opts);
static int write_pid_file(fko_srv_options_t *opts);
static pid_t get_running_pid(const fko_srv_options_t *opts);

int
main(int argc, char **argv)
{
    int                 res, last_sig, rp_cache_count, is_err;
    char               *locale;
    pid_t               old_pid;

    fko_srv_options_t   opts;

    while(1)
    {
        /* Handle command line
        */
        config_init(&opts, argc, argv);

        /* Process any options that do their thing and exit.
        */

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
                    fprintf(stdout, "Killed fwknopd (pid=%i)\n", old_pid);
                    clean_exit(&opts, NO_FW_CLEANUP, EXIT_SUCCESS);
                }
                else
                {
                    perror("Unable to kill fwknop: ");
                    clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);
                }
            }
            else
            {
                fprintf(stderr, "No running fwknopd detected.\n");
                clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }

        /* Status of the currently running fwknopd?
        */
        if(opts.status == 1)
        {
            old_pid = write_pid_file(&opts);

            if(old_pid > 0)
                fprintf(stdout, "Detected fwknopd is running (pid=%i).\n", old_pid);
            else
                fprintf(stdout, "No running fwknopd detected.\n");

            clean_exit(&opts, NO_FW_CLEANUP, EXIT_SUCCESS);
        }

        /* Restart the currently running fwknopd?
        */
        if(opts.restart == 1 || opts.status == 1)
        {
            old_pid = get_running_pid(&opts);

            if(old_pid > 0)
            {
                res = kill(old_pid, SIGHUP);
                if(res == 0)
                {
                    fprintf(stdout, "Sent restart signal to fwknopd (pid=%i)\n", old_pid);
                    clean_exit(&opts, NO_FW_CLEANUP, EXIT_SUCCESS);
                }
                else
                {
                    perror("Unable to send signal to fwknop: ");
                    clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);
                }
            }
            else
            {
                fprintf(stdout, "No running fwknopd detected.\n");
                clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }

        /* Initialize logging.
        */
        init_logging(&opts);

        /* Update the verbosity level for the log module */
        log_set_verbosity(LOG_DEFAULT_VERBOSITY + opts.verbose);

#if HAVE_LOCALE_H
        /* Set the locale if specified.
        */
        if(opts.config[CONF_LOCALE] != NULL
          && strncasecmp(opts.config[CONF_LOCALE], "NONE", 4) != 0)
        {
            locale = setlocale(LC_ALL, opts.config[CONF_LOCALE]);

            if(locale == NULL)
            {
                log_msg(LOG_ERR,
                    "WARNING: Unable to set locale to '%s'.",
                    opts.config[CONF_LOCALE]
                );
            }
            else
            {
                log_msg(LOG_INFO,
                    "Locale set to '%s'.", opts.config[CONF_LOCALE]
                );
            }
        }
#endif

        /* Make sure we have a valid run dir and path leading to digest file
         * in case it configured to be somewhere other than the run dir.
        */
        check_dir_path((const char *)opts.config[CONF_FWKNOP_RUN_DIR], "Run", 0);

        /* Initialize the firewall rules handler based on the fwknopd.conf
         * file, but (for iptables firewalls) don't flush any rules or create
         * any chains yet.  This allows us to dump the current firewall rules
         * via fw_rules_dump() in --fw-list mode before changing around any rules
         * of an existing fwknopd process.
        */
        fw_config_init(&opts);

        if(opts.fw_list == 1 || opts.fw_list_all == 1)
        {
            fw_dump_rules(&opts);
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_SUCCESS);
        }

        if(opts.fw_flush == 1)
        {
            fprintf(stdout, "Deleting any existing firewall rules...\n");
            clean_exit(&opts, FW_CLEANUP, EXIT_SUCCESS);
        }

        /* Process the access.conf file.
        */
        parse_access_file(&opts);

        /* Show config (including access.conf vars) and exit dump config was
         * wanted.
        */
        if(opts.dump_config == 1)
        {
            dump_config(&opts);
            dump_access_list(&opts);
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_SUCCESS);
        }

        /* If we are a new process (just being started), proceed with normal
         * start-up.  Otherwise, we are here as a result of a signal sent to an
         * existing process and we want to restart.
        */
        if(get_running_pid(&opts) != getpid())
        {
            /* If foreground mode is not set, then fork off and become a daemon.
            * Otherwise, attempt to get the pid file lock and go on.
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
                        "[*] An instance of fwknopd is already running: (PID=%i).\n", old_pid
                    );

                    clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);
                }
                else if(old_pid < 0)
                {
                    fprintf(stderr, "[*] PID file error. The lock may not be effective.\n");
                }
            }

            log_msg(LOG_INFO, "Starting %s", MY_NAME);
        }
        else
        {
            log_msg(LOG_INFO, "Re-starting %s", MY_NAME);
        }

        if(opts.verbose > 1 && opts.foreground)
        {
            dump_config(&opts);
            dump_access_list(&opts);
        }

        /* Initialize the digest cache for replay attack detection (either
         * with dbm support or with the default simple cache file strategy)
         * if so configured.
        */
        if(strncasecmp(opts.config[CONF_ENABLE_DIGEST_PERSISTENCE], "Y", 1) == 0)
        {
            rp_cache_count = replay_cache_init(&opts);

            if(rp_cache_count < 0)
            {
                log_msg(LOG_WARNING,
                    "Error opening digest cache file. Incoming digests will not be remembered."
                );
                /* Destination points to heap memory, and is guaranteed to be
                 * at least two bytes large via validate_options(),
                 * DEF_ENABLE_DIGEST_PERSISTENCE, and set_config_entry()
                */
                strlcpy(opts.config[CONF_ENABLE_DIGEST_PERSISTENCE], "N", 2);
            }

            if(opts.verbose)
                log_msg(LOG_ERR,
                    "Using Digest Cache: '%s' (entry count = %i)",
#if USE_FILE_CACHE
                    opts.config[CONF_DIGEST_FILE], rp_cache_count
#else
                    opts.config[CONF_DIGEST_DB_FILE], rp_cache_count
#endif
                );
        }

        /* Prepare the firewall - i.e. flush any old rules and (for iptables)
         * create fwknop chains.
        */
        fw_initialize(&opts);

        /* If the TCP server option was set, fire it up here.
        */
        if(strncasecmp(opts.config[CONF_ENABLE_TCP_SERVER], "Y", 1) == 0)
        {

            strtol_wrapper(opts.config[CONF_TCPSERV_PORT],
                    1, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
            if(is_err == FKO_SUCCESS)
            {
                run_tcp_server(&opts);
            }
            else
            {
                log_msg(LOG_WARNING,
                    "WARNING: ENABLE_TCP_SERVER is set, but TCPSERV_PORT is not valid. TCP server not started!"
                );
            }
        }

        /* Intiate pcap capture mode...
        */
        pcap_capture(&opts);

        if(got_signal) {
            last_sig   = got_signal;
            got_signal = 0;

            if(got_sighup)
            {
                log_msg(LOG_WARNING, "Got SIGHUP.  Re-reading configs.");
                free_configs(&opts);
                kill(opts.tcp_server_pid, SIGTERM);
                usleep(1000000);
                got_sighup = 0;
            }
            else if(got_sigint)
            {
                log_msg(LOG_WARNING, "Got SIGINT.  Exiting...");
                got_sigint = 0;
                break;
            }
            else if(got_sigterm)
            {
                log_msg(LOG_WARNING, "Got SIGTERM.  Exiting...");
                got_sigterm = 0;
                break;
            }
            else
            {
                log_msg(LOG_WARNING,
                    "Got signal %i. No defined action but to exit.", last_sig);
                break;
            }
        }
        else if (opts.packet_ctr_limit > 0
            && opts.packet_ctr >= opts.packet_ctr_limit)
        {
            log_msg(LOG_INFO,
                "Packet count limit (%d) reached.  Exiting...",
                opts.packet_ctr_limit);
            break;
        }
        else    /* got_signal was not set (should be if we are here) */
        {
            log_msg(LOG_WARNING,
                "Capture ended without signal.  Exiting...");
            break;
        }
    }

    log_msg(LOG_INFO, "Shutting Down fwknopd.");

    /* Kill the TCP server (if we have one running).
    */
    if(opts.tcp_server_pid > 0)
    {
        log_msg(LOG_INFO, "Killing the TCP server (pid=%i)",
            opts.tcp_server_pid);

        kill(opts.tcp_server_pid, SIGTERM);

        /* --DSS XXX: This seems to be necessary if the tcp server
         *            was restarted by this program.  We need to
         *            investigate and fix this. For now, this works
         *            (it is kludgy, but does no harm afaik).
        */
        kill(opts.tcp_server_pid, SIGKILL);
    }

    /* Other cleanup.
    */
    fw_cleanup(&opts);
    free_logging();

#if USE_FILE_CACHE
    free_replay_list(&opts);
#endif

    free_configs(&opts);

    return(0);
}

/* Ensure the specified directory exists.  If not, create it or die.
*/
static void
check_dir_path(const char * const filepath, const char * const fp_desc, const unsigned char use_basename)
{
    struct stat     st;
    int             res = 0;
    char            tmp_path[MAX_PATH_LEN];
    char            *ndx;

    /*
     * FIXME:  We shouldn't use a hard-coded dir-separator here.
    */
    /* But first make sure we are using an absolute path.
    */
    if(*filepath != PATH_SEP)
    {
        log_msg(LOG_ERR,
            "Path '%s' is not absolute.", filepath
        );
        exit(EXIT_FAILURE);
    }

    /* If this is a file path that we want to use only the basename, strip
     * the trailing filename here.
    */
    if(use_basename && ((ndx = strrchr(filepath, PATH_SEP)) != NULL))
        strlcpy(tmp_path, filepath, (ndx-filepath)+1);
    else
        strlcpy(tmp_path, filepath, sizeof(tmp_path));

    /* At this point, we should make the path is more than just the
     * PATH_SEP.  If it is not, silently return.
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
            log_msg(LOG_WARNING,
                "%s directory: %s does not exist.  Attempting to create it.",
                fp_desc, tmp_path
            );

            /* Directory does not exist, so attempt to create it.
            */
            res = make_dir_path(tmp_path);
            if(res != 0)
            {
                log_msg(LOG_ERR,
                    "Unable to create %s directory: %s (error: %i)",
                    fp_desc, tmp_path, errno
                );
                exit(EXIT_FAILURE);
            }

            log_msg(LOG_ERR,
                "Successfully created %s directory: %s", fp_desc, tmp_path
            );
        }
        else
        {
            log_msg(LOG_ERR,
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
            log_msg(LOG_ERR,
                "Specified %s directory: %s is NOT a directory\n\n", fp_desc, tmp_path
            );
            exit(EXIT_FAILURE);
        }
    }
}

static int
make_dir_path(const char * const run_dir)
{
    struct stat     st;
    int             res = 0, len = 0;
    char            tmp_path[MAX_PATH_LEN];
    char            *ndx;

    strlcpy(tmp_path, run_dir, sizeof(tmp_path));

    len = strlen(tmp_path);

    /* Strip any trailing dir sep char.
    */
    if(tmp_path[len-1] == PATH_SEP)
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
                {
                    res = mkdir(tmp_path, S_IRWXU);
                    if(res != 0)
                        return res;

                    /* run stat() against the component since we just
                     * created it
                    */
                    if(stat(tmp_path, &st) != 0)
                    {
                        log_msg(LOG_ERR,
                            "Could not create component: %s of %s\n\n", tmp_path, run_dir
                        );
                        return(ENOTDIR);
                    }
                }
            }

            if(! S_ISDIR(st.st_mode))
            {
                log_msg(LOG_ERR,
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
daemonize_process(fko_srv_options_t * const opts)
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
            "[*] An instance of fwknopd is already running: (PID=%i).\n", old_pid
        );

        exit(EXIT_FAILURE);
    }
    else if(old_pid < 0)
    {
        fprintf(stderr,
                "[*] PID file error. The lock may not be effective.\n");
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
    int     op_fd, lck_res, num_bytes;
    char    buf[PID_BUFLEN] = {0};

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

    if(fcntl(op_fd, F_SETFD, FD_CLOEXEC) == -1)
    {
        close(op_fd);
        perror("Unexpected error from fcntl: ");
        return -1;
    }

    /* Attempt to lock the PID file.  If we get an EWOULDBLOCK
     * error, another instance already has the lock. So we grab
     * the pid from the existing lock file, complain and bail.
    */
    lck_res = lockf(op_fd, F_TLOCK, 0);
    if(lck_res == -1)
    {
        close(op_fd);

        if(errno != EAGAIN)
        {
            perror("Unexpected error from lockf: ");
            return -1;
        }

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
    snprintf(buf, PID_BUFLEN, "%i\n", my_pid);

    log_msg(LOG_DEBUG, "[+] Writing my PID (%i) to the lock file: %s\n",
        my_pid, opts->config[CONF_FWKNOP_PID_FILE]);

    num_bytes = write(op_fd, buf, strlen(buf));

    if(errno || num_bytes != strlen(buf))
        perror("Lock may not be valid. PID file write error: ");

    /* Sync/flush regardless...
    */
    fsync(op_fd);

    /* Put the lock file discriptor in out options struct so any
     * child processes we my spawn can close and release it.
    */
    opts->lock_fd = op_fd;

    return 0;
}

static pid_t
get_running_pid(const fko_srv_options_t *opts)
{
    int     op_fd, is_err;
    char    buf[PID_BUFLEN] = {0};
    pid_t   rpid            = 0;


    verify_file_perms_ownership(opts->config[CONF_FWKNOP_PID_FILE]);

    op_fd = open(opts->config[CONF_FWKNOP_PID_FILE], O_RDONLY);

    if(op_fd == -1)
    {
        perror("Error trying to open PID file: ");
        return(rpid);
    }

    if (read(op_fd, buf, PID_BUFLEN) > 0)
    {
        buf[PID_BUFLEN-1] = '\0';
        /* max pid value is configurable on Linux
        */
        rpid = (pid_t) strtol_wrapper(buf, 0, (2 << 30),
                NO_EXIT_UPON_ERR, &is_err);
        if(is_err != FKO_SUCCESS)
            rpid = 0;
    }

    close(op_fd);

    return(rpid);
}

void
clean_exit(fko_srv_options_t *opts, unsigned int fw_cleanup_flag, unsigned int exit_status)
{
    if(fw_cleanup_flag == FW_CLEANUP)
        fw_cleanup(opts);

#if USE_FILE_CACHE
    free_replay_list(opts);
#endif

    free_logging();
    free_configs(opts);
    exit(exit_status);
}

/***EOF***/
