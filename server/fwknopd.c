/**
 * \file server/fwknopd.c
 *
 * \brief An implementation of an fwknop server.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
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
#include "fwknopd.h"
#include "access.h"
#include "config_init.h"
#include "log_msg.h"
#include "utils.h"
#include "fw_util.h"
#include "sig_handler.h"
#include "replay_cache.h"
#include "tcp_server.h"
#include "udp_server.h"

#if USE_LIBNETFILTER_QUEUE
  #include "nfq_capture.h"
#endif
#if USE_LIBPCAP
  #include "pcap_capture.h"
#endif

/* Prototypes
*/
static int check_dir_path(const char * const path,
        const char * const path_name, const unsigned char use_basename);
static int make_dir_path(const char * const path);
static void daemonize_process(fko_srv_options_t * const opts);
static int stop_fwknopd(fko_srv_options_t * const opts);
static int status_fwknopd(fko_srv_options_t * const opts);
static int restart_fwknopd(fko_srv_options_t * const opts);
static int write_pid_file(fko_srv_options_t *opts);
static int handle_signals(fko_srv_options_t *opts);
static void setup_pid(fko_srv_options_t *opts);
static void init_digest_cache(fko_srv_options_t *opts);
static void set_locale(fko_srv_options_t *opts);
static pid_t get_running_pid(const fko_srv_options_t *opts);
#if AFL_FUZZING
static void afl_enc_pkt_from_file(fko_srv_options_t *opts);
static void afl_pkt_from_stdin(fko_srv_options_t *opts);
#endif

#if HAVE_LIBFIU
static void enable_fault_injections(fko_srv_options_t * const opts);
#endif

#if AFL_FUZZING
#define AFL_MAX_PKT_SIZE  1024
#define AFL_DUMP_CTX_SIZE 4096
#endif

int
main(int argc, char **argv)
{
    fko_srv_options_t   opts;
    int depth = 0;

    while(1)
    {
        /* Handle command line
        */
        config_init(&opts, argc, argv);

#if HAVE_LIBFIU
        /* Set any fault injection points early
        */
        enable_fault_injections(&opts);
#endif

        /* Process any options that do their thing and exit.
        */

        /* Kill the currently running fwknopd process?
        */
        if(opts.kill == 1)
            clean_exit(&opts, NO_FW_CLEANUP, stop_fwknopd(&opts));

        /* Status of the currently running fwknopd process?
        */
        if(opts.status == 1)
            clean_exit(&opts, NO_FW_CLEANUP, status_fwknopd(&opts));

        /* Restart the currently running fwknopd process?
        */
        if(opts.restart == 1)
            clean_exit(&opts, NO_FW_CLEANUP, restart_fwknopd(&opts));

        /* Initialize logging.
        */
        init_logging(&opts);

        /* Update the verbosity level for the log module */
        log_set_verbosity(LOG_DEFAULT_VERBOSITY + opts.verbose);

#if HAVE_LOCALE_H
        /* Set the locale if specified.
        */
        set_locale(&opts);
#endif

        /* Make sure we have a valid run dir and path leading to digest file
         * in case it configured to be somewhere other than the run dir.
        */
        if(!opts.afl_fuzzing
                && ! check_dir_path((const char *)opts.config[CONF_FWKNOP_RUN_DIR], "Run", 0))
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);

        /* Initialize the firewall rules handler based on the fwknopd.conf
         * file, but (for iptables firewalls) don't flush any rules or create
         * any chains yet. This allows us to dump the current firewall rules
         * via fw_rules_dump() in --fw-list mode before changing around any rules
         * of an existing fwknopd process.
        */
        if(fw_config_init(&opts) != 1)
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);

        if(opts.fw_list == 1 || opts.fw_list_all == 1)
        {
            fw_dump_rules(&opts);
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_SUCCESS);
        }

        if(opts.fw_flush == 1)
        {
            fprintf(stdout, "Deleting any existing firewall rules...\n");
            opts.enable_fw = 1;
            clean_exit(&opts, FW_CLEANUP, EXIT_SUCCESS);
        }

        if (opts.config[CONF_ACCESS_FOLDER] != NULL) //If we have an access folder, process it
        {
            if (parse_access_folder(&opts, opts.config[CONF_ACCESS_FOLDER], &depth) != EXIT_SUCCESS)
            {
                clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }
        /* Process the access.conf file, but only if no access.conf folder was specified.
        */
        else if (parse_access_file(&opts, opts.config[CONF_ACCESS_FILE], &depth) != EXIT_SUCCESS)
        {
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }

        /* We must have at least one valid access stanza at this point
        */
        if(! valid_access_stanzas(opts.acc_stanzas))
        {
            log_msg(LOG_ERR, "Fatal, could not find any valid access.conf stanzas");
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }

        /* Show config (including access.conf vars) and exit dump config was
         * wanted.
        */
        if(opts.dump_config == 1)
        {
            dump_config(&opts);
            dump_access_list(&opts);
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_SUCCESS);
        }

        /* Now is the right time to bail if we're just parsing the configs
        */
        if(opts.exit_after_parse_config)
        {
            log_msg(LOG_INFO, "Configs parsed, exiting.");
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_SUCCESS);
        }

        /* Acquire pid, become a daemon or run in the foreground, write pid
         * to pid file.
        */
        if(! opts.exit_parse_digest_cache)
            setup_pid(&opts);

        if(opts.verbose > 1 && opts.foreground)
        {
            dump_config(&opts);
            dump_access_list(&opts);
        }

        /* Initialize the digest cache for replay attack detection (either
         * with dbm support or with the default simple cache file strategy)
         * if so configured.
        */
        init_digest_cache(&opts);

        if(opts.exit_parse_digest_cache)
        {
            log_msg(LOG_INFO, "Digest cache parsed, exiting.");
            clean_exit(&opts, NO_FW_CLEANUP, EXIT_SUCCESS);
        }

#if AFL_FUZZING
        /* SPA data from STDIN. */
        if(opts.afl_fuzzing)
        {
            if(opts.config[CONF_AFL_PKT_FILE] != 0x0)
            {
                afl_enc_pkt_from_file(&opts);
            }
            else
            {
                afl_pkt_from_stdin(&opts);
            }
        }
#endif

        /* Prepare the firewall - i.e. flush any old rules and (for iptables)
         * create fwknop chains.
        */
        if(!opts.test && opts.enable_fw && (fw_initialize(&opts) != 1))
            clean_exit(&opts, FW_CLEANUP, EXIT_FAILURE);

#if USE_LIBNETFILTER_QUEUE
        /* If we are to acquire SPA data via a libnetfilter_queue, start it up here.
        */
        if(opts.enable_nfq_capture ||
                strncasecmp(opts.config[CONF_ENABLE_NFQ_CAPTURE], "Y", 1) == 0)
        {
            nfq_capture(&opts);
        }
        else
#endif
        /* If we are to acquire SPA data via a UDP socket, start it up here.
        */
        if(opts.enable_udp_server ||
                strncasecmp(opts.config[CONF_ENABLE_UDP_SERVER], "Y", 1) == 0)
        {
            if(run_udp_server(&opts) < 0)
            {
                log_msg(LOG_ERR, "Fatal run_udp_server() error");
                clean_exit(&opts, FW_CLEANUP, EXIT_FAILURE);
            }
            else
            {
                break;
            }
        }

        /* If the TCP server option was set, fire it up here. Note that in
         * this mode, fwknopd still acquires SPA packets via libpcap. If you
         * want to use UDP only without the libpcap dependency, then fwknop
         * needs to be compiled with --enable-udp-server. Note that the UDP
         * server can be run even when fwknopd links against libpcap as well,
         * but there is no reason to link against it if SPA packets are
         * always going to be acquired via a UDP socket.
        */
        if(strncasecmp(opts.config[CONF_ENABLE_TCP_SERVER], "Y", 1) == 0)
        {
            if(run_tcp_server(&opts) < 0)
            {
                log_msg(LOG_ERR, "Fatal run_tcp_server() error");
                clean_exit(&opts, FW_CLEANUP, EXIT_FAILURE);
            }
        }

#if USE_LIBPCAP
        /* Intiate pcap capture mode...
        */
        if(!opts.enable_udp_server
            && strncasecmp(opts.config[CONF_ENABLE_UDP_SERVER], "N", 1) == 0)
        {
            pcap_capture(&opts);
        }
        else
        {
            log_msg(LOG_ERR, "No available capture mode specified.  Aborting.");
            clean_exit(&opts, FW_CLEANUP, EXIT_FAILURE);
        }
#endif

        /* Deal with any signals that we've received and break out
         * of the loop for any terminating signals
        */
        if(handle_signals(&opts) == 1)
            break;
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
         *            was restarted by this program. We need to
         *            investigate and fix this. For now, this works
         *            (it is kludgy, but does no harm afaik).
        */
        kill(opts.tcp_server_pid, SIGKILL);
    }

    clean_exit(&opts, FW_CLEANUP, EXIT_SUCCESS);

    return(EXIT_SUCCESS);  /* This never gets called */
}

static void set_locale(fko_srv_options_t *opts)
{
    char               *locale;

    if(opts->config[CONF_LOCALE] != NULL
      && strncasecmp(opts->config[CONF_LOCALE], "NONE", 4) != 0)
    {
        locale = setlocale(LC_ALL, opts->config[CONF_LOCALE]);

        if(locale == NULL)
        {
            log_msg(LOG_ERR,
                "WARNING: Unable to set locale to '%s'.",
                opts->config[CONF_LOCALE]
            );
        }
        else
        {
            log_msg(LOG_INFO,
                "Locale set to '%s'.", opts->config[CONF_LOCALE]
            );
        }
    }
    return;
}

#if AFL_FUZZING
static void afl_enc_pkt_from_file(fko_srv_options_t *opts)
{
    FILE                *fp = NULL;
    fko_ctx_t           decrypt_ctx = NULL;
    unsigned char       enc_spa_pkt[AFL_MAX_PKT_SIZE] = {0}, rc;
    int                 res = 0, es = EXIT_SUCCESS, enc_msg_len;
    char                dump_buf[AFL_DUMP_CTX_SIZE];

    fp = fopen(opts->config[CONF_AFL_PKT_FILE], "rb");
    if(fp != NULL)
    {
        enc_msg_len = 0;
        while(fread(&rc, 1, 1, fp))
        {
            enc_spa_pkt[enc_msg_len] = rc;
            enc_msg_len++;
            if(enc_msg_len == AFL_MAX_PKT_SIZE-1)
                break;
        }
        fclose(fp);

        fko_new(&decrypt_ctx);

        res = fko_afl_set_spa_data(decrypt_ctx, (const char *)enc_spa_pkt,
                enc_msg_len);
        if(res == FKO_SUCCESS)
            res = fko_decrypt_spa_data(decrypt_ctx, "fwknoptest",
                    strlen("fwknoptest"));
        if(res == FKO_SUCCESS)
            res = dump_ctx_to_buffer(decrypt_ctx, dump_buf, sizeof(dump_buf));
        if(res == FKO_SUCCESS)
            log_msg(LOG_INFO, "%s", dump_buf);
        else
            log_msg(LOG_ERR, "Error (%d): %s", res, fko_errstr(res));

        fko_destroy(decrypt_ctx);

        if(res == FKO_SUCCESS)
        {
            log_msg(LOG_INFO, "SPA packet decode: %s", fko_errstr(res));
            es = EXIT_SUCCESS;
        }
        else
        {
            log_msg(LOG_ERR, "Could not decode SPA packet: %s", fko_errstr(res));
            es = EXIT_FAILURE;
        }
    }
    else
        log_msg(LOG_ERR, "Could not acquire SPA packet from file: %s.",
                opts->config[CONF_AFL_PKT_FILE]);

    clean_exit(opts, NO_FW_CLEANUP, es);
}

static void afl_pkt_from_stdin(fko_srv_options_t *opts)
{
    FILE                *fp = NULL;
    fko_ctx_t           decode_ctx = NULL;
    unsigned char       spa_pkt[AFL_MAX_PKT_SIZE] = {0};
    int                 res = 0, es = EXIT_SUCCESS;
    char                dump_buf[AFL_DUMP_CTX_SIZE];

    fp = fdopen(STDIN_FILENO, "r");
    if(fp != NULL)
    {
        if(fgets((char *)spa_pkt, AFL_MAX_PKT_SIZE, fp) == NULL)
        {
            fclose(fp);
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }

        fclose(fp);

        fko_new(&decode_ctx);

        res = fko_set_encoded_data(decode_ctx, (char *) spa_pkt,
                strlen((char *)spa_pkt), 0, FKO_DIGEST_SHA256);

        if(res == FKO_SUCCESS)
            res = fko_set_spa_data(decode_ctx, (const char *) spa_pkt);
        if(res == FKO_SUCCESS)
            res = fko_decode_spa_data(decode_ctx);
        if(res == FKO_SUCCESS)
            res = dump_ctx_to_buffer(decode_ctx, dump_buf, sizeof(dump_buf));
        if(res == FKO_SUCCESS)
            log_msg(LOG_INFO, "%s", dump_buf);

        fko_destroy(decode_ctx);

        if(res == FKO_SUCCESS)
        {
            log_msg(LOG_INFO, "SPA packet decode: %s", fko_errstr(res));
            es = EXIT_SUCCESS;
        }
        else
        {
            log_msg(LOG_ERR, "Could not decode SPA packet: %s", fko_errstr(res));
            es = EXIT_FAILURE;
        }
    }
    else
        log_msg(LOG_ERR, "Could not acquire SPA packet from stdin.");

    clean_exit(opts, NO_FW_CLEANUP, es);
}
#endif

static void init_digest_cache(fko_srv_options_t *opts)
{
    int     rp_cache_count;

#if AFL_FUZZING
    if(opts->afl_fuzzing)
        return;
#endif

    if(strncasecmp(opts->config[CONF_ENABLE_DIGEST_PERSISTENCE], "Y", 1) == 0)
    {
        rp_cache_count = replay_cache_init(opts);

        if(rp_cache_count < 0)
        {
            log_msg(LOG_WARNING,
                "Error opening digest cache file. Incoming digests will not be remembered."
            );
            /* Destination points to heap memory, and is guaranteed to be
             * at least two bytes large via validate_options(),
             * DEF_ENABLE_DIGEST_PERSISTENCE, and set_config_entry()
            */
            strlcpy(opts->config[CONF_ENABLE_DIGEST_PERSISTENCE], "N", 2);
        }

        if(opts->verbose)
            log_msg(LOG_ERR,
                "Using Digest Cache: '%s' (entry count = %i)",
#if USE_FILE_CACHE
                opts->config[CONF_DIGEST_FILE], rp_cache_count
#else
                opts->config[CONF_DIGEST_DB_FILE], rp_cache_count
#endif
            );
    }
    return;
}

static void setup_pid(fko_srv_options_t *opts)
{
    pid_t    old_pid;

#if AFL_FUZZING
    if(opts->afl_fuzzing)
        return;
#endif

    /* If we are a new process (just being started), proceed with normal
     * start-up. Otherwise, we are here as a result of a signal sent to an
     * existing process and we want to restart.
    */
    if(get_running_pid(opts) != getpid())
    {
        /* If foreground mode is not set, then fork off and become a daemon.
        * Otherwise, attempt to get the pid file lock and go on.
        */
        if(opts->foreground == 0)
        {
            daemonize_process(opts);
        }
        else
        {
            old_pid = write_pid_file(opts);
            if(old_pid > 0)
            {
                fprintf(stderr,
                    "[*] An instance of fwknopd is already running: (PID=%i).\n", old_pid
                );

                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
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

    return;
}

static int restart_fwknopd(fko_srv_options_t * const opts)
{
    int      res = 0;
    pid_t    old_pid;

    old_pid = get_running_pid(opts);

    if(old_pid > 0)
    {
        res = kill(old_pid, SIGHUP);
        if(res == 0)
        {
            fprintf(stdout, "Sent restart signal to fwknopd (pid=%i)\n", old_pid);
            return EXIT_SUCCESS;
        }
        else
        {
            perror("Unable to send signal to fwknop: ");
            return EXIT_FAILURE;
        }
    }

    fprintf(stdout, "No running fwknopd detected.\n");
    return EXIT_FAILURE;
}

static int status_fwknopd(fko_srv_options_t * const opts)
{
    pid_t    old_pid;

    old_pid = write_pid_file(opts);

    if(old_pid > 0)
    {
        fprintf(stdout, "Detected fwknopd is running (pid=%i).\n", old_pid);
        return EXIT_SUCCESS;
    }

    fprintf(stdout, "No running fwknopd detected.\n");
    return EXIT_FAILURE;
}

static int handle_signals(fko_srv_options_t *opts)
{
    int      last_sig = 0, rv = 1;

    if(got_signal) {
        last_sig   = got_signal;
        got_signal = 0;

        if(got_sighup)
        {
            log_msg(LOG_WARNING, "Got SIGHUP. Re-reading configs.");
            free_configs(opts);
            if(opts->tcp_server_pid > 0)
                kill(opts->tcp_server_pid, SIGTERM);
            usleep(1000000);
            got_sighup = 0;
            rv = 0;  /* this means fwknopd will not exit */
        }
        else if(got_sigint)
        {
            log_msg(LOG_WARNING, "Got SIGINT. Exiting...");
            got_sigint = 0;
        }
        else if(got_sigterm)
        {
            log_msg(LOG_WARNING, "Got SIGTERM. Exiting...");
            got_sigterm = 0;
        }
        else
        {
            log_msg(LOG_WARNING,
                "Got signal %i. No defined action but to exit.", last_sig);
        }
    }
    else if (opts->packet_ctr_limit > 0
        && opts->packet_ctr >= opts->packet_ctr_limit)
    {
        log_msg(LOG_INFO,
            "Packet count limit (%d) reached. Exiting...",
            opts->packet_ctr_limit);
    }
    else    /* got_signal was not set (should be if we are here) */
    {
        log_msg(LOG_WARNING,
            "Capture ended without signal. Exiting...");
    }
    return rv;
}

static int stop_fwknopd(fko_srv_options_t * const opts)
{
    int      res = 0, is_err = 0;
    pid_t    old_pid;

    old_pid = get_running_pid(opts);

    if(old_pid > 0)
    {
        res    = kill(old_pid, SIGTERM);
        is_err = kill(old_pid, 0);

        if(res == 0 && is_err != 0)
        {
            fprintf(stdout, "Killed fwknopd (pid=%i)\n", old_pid);
            return EXIT_SUCCESS;
        }
        else
        {
            /* give a bit of time for process shutdown and check again
            */
            sleep(1);
            is_err = kill(old_pid, 0);
            if(is_err != 0)
            {
                fprintf(stdout, "Killed fwknopd (pid=%i) via SIGTERM\n",
                        old_pid);
                return EXIT_SUCCESS;
            }
            else
            {
                res    = kill(old_pid, SIGKILL);
                is_err = kill(old_pid, 0);
                if(res == 0 && is_err != 0)
                {
                    fprintf(stdout,
                            "Killed fwknopd (pid=%i) via SIGKILL\n",
                            old_pid);
                    return EXIT_SUCCESS;
                }
                else
                {
                    sleep(1);
                    is_err = kill(old_pid, 0);
                    if(is_err != 0)
                    {
                        fprintf(stdout,
                                "Killed fwknopd (pid=%i) via SIGKILL\n",
                                old_pid);
                        return EXIT_SUCCESS;
                    }
                    else
                    {
                        perror("Unable to kill fwknop: ");
                        return EXIT_FAILURE;
                    }
                }
            }
        }
    }

    fprintf(stderr, "No running fwknopd detected.\n");
    return EXIT_FAILURE;
}

/* Ensure the specified directory exists. If not, create it or die.
*/
static int
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
        return 0;
    }

    /* If this is a file path that we want to use only the basename, strip
     * the trailing filename here.
    */
    if(use_basename && ((ndx = strrchr(filepath, PATH_SEP)) != NULL))
        strlcpy(tmp_path, filepath, (ndx-filepath)+1);
    else
        strlcpy(tmp_path, filepath, sizeof(tmp_path));

    /* At this point, we should make the path is more than just the
     * PATH_SEP. If it is not, silently return.
    */
    if(strlen(tmp_path) < 2)
        return 1;

    /* Make sure we have a valid directory.
    */
    res = stat(tmp_path, &st);
    if(res != 0)
    {
        if(errno == ENOENT)
        {
            log_msg(LOG_WARNING,
                "%s directory: %s does not exist. Attempting to create it.",
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
                return 0;
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
            return 0;
        }
    }
    else
    {
        /* It is a file, but is it a directory?
        */
        if(! S_ISDIR(st.st_mode))
        {
            log_msg(LOG_ERR,
                "Specified %s directory: %s is NOT a directory", fp_desc, tmp_path
            );
            return 0;
        }
    }
    return 1;
}

static int
make_dir_path(const char * const run_dir)
{
    struct stat     st;
    int             res = 0;
    char            tmp_path[MAX_PATH_LEN];
    char            *ndx;

    strlcpy(tmp_path, run_dir, sizeof(tmp_path));

    /* Strip any trailing dir sep char.
    */
    chop_char(tmp_path, PATH_SEP);

    for(ndx = tmp_path+1; *ndx; ndx++)
    {
        if(*ndx == '/')
        {
            *ndx = '\0';

            /* Stat this part of the path to see if it is a valid directory.
             * If it does not exist, attempt to create it. If it does, and
             * it is a directory, go on. Otherwise, any other error cause it
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
                            "Could not create component: %s of %s", tmp_path, run_dir
                        );
                        return(ENOTDIR);
                    }
                }
            }

            if(! S_ISDIR(st.st_mode))
            {
                log_msg(LOG_ERR,
                    "Component: %s of %s is NOT a directory", tmp_path, run_dir
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
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }
    else if (pid != 0) /* parent */
    {
        clean_exit(opts, NO_FW_CLEANUP, EXIT_SUCCESS);
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
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
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
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
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

    /* Attempt to lock the PID file. If we get an EWOULDBLOCK
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

    log_msg(LOG_DEBUG, "[+] Writing my PID (%i) to the lock file: %s",
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
    int     op_fd, is_err, bytes_read = 0;
    char    buf[PID_BUFLEN] = {0};
    pid_t   rpid            = 0;


    if(verify_file_perms_ownership(opts->config[CONF_FWKNOP_PID_FILE]) != 1)
    {
        fprintf(stderr, "verify_file_perms_ownership() error\n");
        return(rpid);
    }

    op_fd = open(opts->config[CONF_FWKNOP_PID_FILE], O_RDONLY);

    if(op_fd == -1)
    {
        if((opts->foreground != 0) && (opts->verbose != 0))
            perror("Error trying to open PID file: ");
        return(rpid);
    }

    bytes_read = read(op_fd, buf, PID_BUFLEN);
    if (bytes_read > 0)
    {
        buf[PID_BUFLEN-1] = '\0';
        /* max pid value is configurable on Linux
        */
        rpid = (pid_t) strtol_wrapper(buf, 0, (2 << 30),
                NO_EXIT_UPON_ERR, &is_err);
        if(is_err != FKO_SUCCESS)
            rpid = 0;
    }
    else if (bytes_read < 0)
        perror("Error trying to read() PID file: ");

    close(op_fd);

    return(rpid);
}

#if HAVE_LIBFIU
static void
enable_fault_injections(fko_srv_options_t * const opts)
{
    if(opts->config[CONF_FAULT_INJECTION_TAG] != NULL)
    {
        if(opts->verbose)
            log_msg(LOG_INFO, "Enable fault injection tag: %s",
                    opts->config[CONF_FAULT_INJECTION_TAG]);
        if(fiu_init(0) != 0)
        {
            fprintf(stderr, "[*] Could not enable fault injection tag: %s\n",
                    opts->config[CONF_FAULT_INJECTION_TAG]);
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }
        if (fiu_enable(opts->config[CONF_FAULT_INJECTION_TAG], 1, NULL, 0) != 0)
        {
            fprintf(stderr, "[*] Could not enable fault injection tag: %s\n",
                    opts->config[CONF_FAULT_INJECTION_TAG]);
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }
    }
    return;
}
#endif

/***EOF***/
