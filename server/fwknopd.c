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

/* Prototypes
*/
void daemonize_process(const char *pid_file);
void write_pid(const char *pid_file, const pid_t pid);

int
main(int argc, char **argv)
{
    fko_ctx_t           ctx;
    int                 res;
    char               *spa_data, *version;
    char                access_buf[MAX_LINE_LEN];

    fko_srv_options_t   opts;

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
        //sendsig_fwknopd(&opts, SIGTERM);
        fprintf(stderr, "Kill option no implemented yet.\n");
        exit(EXIT_SUCCESS);
    }

    /* Restart the currently running fwknopd?
    */
    if(opts.restart == 1)
    {
        //sendsig_fwknopd(&opts, SIGHUP);
        fprintf(stderr, "Restart option no implemented yet.\n");
        exit(EXIT_SUCCESS);
    }

    /* Status of the currently running fwknopd?
    */
    if(opts.status == 1)
    {
        //fwknopd_status(&opts, SIGHUP);
        fprintf(stderr, "Status option no implemented yet.\n");
        exit(EXIT_SUCCESS);
    }

    /* If foreground mode is not set, the fork off and become a daemon.
    */
    if(opts.foreground == 0)
        daemonize_process(opts.config[CONF_FWKNOP_PID_FILE]);

    log_msg(LOG_INFO, "Starting %s", MY_NAME);

    if((strncasecmp(opts.config[CONF_AUTH_MODE], "pcap", 4)) != 0)
    {
        log_msg(LOG_ERR|LOG_STDERR,
            "Capture/auth mode other than 'PCAP' is not supported."
        );
        exit(EXIT_FAILURE);
    }

#ifndef HAVE_LIBPCAP
    log_msg(LOG_ERR|LOG_STDERR,
        "libpcap is not avaiable, I'm hosed (for now).");
    exit(EXIT_FAILURE);
#endif
 
    /* Intiate pcap capture mode...
    */
    pcap_capture(&opts);

    return(0);
}

/* Become a daemon: fork(), start a new session, chdir "/",
 * and close unneeded standard filehandles.
*/
void daemonize_process(const char *pid_file)
{
    pid_t child_pid, sid;

    if ((child_pid = fork()) < 0) {
        perror("Unable to fork: ");
        exit(EXIT_FAILURE);
    }

    /* The parent will write the child PID to the pid_file
     * then exit.
    */
    if (child_pid > 0) {
        write_pid(pid_file, child_pid);
        exit(EXIT_SUCCESS);
    }

    /* Child process from here on out */

    /* Start a new session
    */
    if ((sid = setsid()) < 0) {
        perror("Error from setsid(): ");
        exit(EXIT_FAILURE);
    }

    /* Chdir to  "/"
    */
    if ((chdir("/")) < 0) {
        perror("Could not chdir() to /: ");
        exit(EXIT_FAILURE);
    }

    /* Reset the our umask
    */
    umask(0);

    /* Close un-needed file handles
    */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    return;
}

void write_pid(const char *pid_file, const pid_t pid)
{
    FILE *pidfile_ptr;

    if ((pidfile_ptr = fopen(pid_file, "w")) == NULL) {
        fprintf(stderr, "Could not open the pid file: %s: %s",
            pid_file, strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Write the pid to the pid file
    */
    if (fprintf(pidfile_ptr, "%d\n", pid) == 0) {
        fprintf(stderr, "PID: %d could not be written to pid file: %s: %s",
            pid, pid_file, strerror(errno));
        exit(EXIT_FAILURE);
    }

    fclose(pidfile_ptr);

    chmod(pid_file, 0600);

    return;
}

/***EOF***/
