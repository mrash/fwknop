/*
*****************************************************************************
*
*  File: knopwatchd.c
*
*  Purpose: knopwatchd checks on an interval of every five seconds to make
*           sure that both knopmd and fwknop are running on the box.  If
*           either daemon has died, knopwatchd will restart it and notify
*           each email address in EMAIL_ADDRESSES that the daemon has been
*           restarted.
*
*  Author: Michael Rash (mbr@cipherdyne.org)
*
*  Credits:  (see the CREDITS file)
*
*  Version: 1.9.12
*
*  Copyright (C) 2004-2009 Michael Rash (mbr@cipherdyne.org)
*
*  License (GNU General Public License):
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
*
*  $Id: knopwatchd.c 1533 2009-09-08 02:44:02Z mbr $
*/

/* includes */
#include "fwknop.h"

/* Default configuration file to parse */
#define FWKNOP_CONF     "/etc/fwknop/fwknop.conf"

/* Maximum number of overwrite files allowed on the command line */
#define MAX_OVW_FILES   3

/* globals */
unsigned short int fwknopd_syscalls_ctr = 0;
unsigned short int knopmd_syscalls_ctr = 0;
unsigned short int no_email = 0;
unsigned short int check_knopmd;
char default_mail_sender[] = "root";
char hostname[MAX_GEN_LEN];
char mail_addrs[MAX_GEN_LEN];
char shCmd[MAX_GEN_LEN];
char mailCmd[MAX_GEN_LEN];
char sendmailCmd[MAX_GEN_LEN];
char fwknop_run_dir[MAX_PATH_LEN];
char alerting_methods[MAX_GEN_LEN];
char fwknopdCmd[MAX_PATH_LEN];
char fwknopd_pid_file[MAX_PATH_LEN];
char fwknopd_cmdline_file[MAX_PATH_LEN];
char knopmdCmd[MAX_PATH_LEN];
char knoptmCmd[MAX_PATH_LEN];
char knopmd_pid_file[MAX_PATH_LEN];
char knoptm_pid_file[MAX_PATH_LEN];
char knopwatchd_pid_file[MAX_PATH_LEN];
char char_knopwatchd_check_interval[MAX_NUM_LEN];
char char_knopwatchd_max_retries[MAX_NUM_LEN];
char enable_syslog_file[MAX_GEN_LEN];
char auth_mode[MAX_GEN_LEN];
unsigned int knopwatchd_check_interval = 0;
unsigned int knopwatchd_max_retries = 0;
unsigned char dump_cfg;

static volatile sig_atomic_t received_sighup = 0;

/* prototypes */
static void usage(void);
static void clean_settings(void);
static void parse_config(char *file);
static void check_config(void);
static void dump_config(void);
static void expand_config_vars(void);
static void find_sub_var_value(
    char *value,
    char *sub_var,
    char *pre_str,
    char *post_str
);

static void check_process(
    const char *pid_name,
    const char *pid_file,
    const char *cmdline_file,
    const char *binary_path,
    unsigned int max_retries
);

static unsigned short int is_knopmd_required(void);
static void incr_syscall_ctr(const char *pid_name, unsigned int max_retries);
static void reset_syscall_ctr(const char *pid_name);
static void give_up(const char *pid_name);
static void exec_binary(const char *binary_path, const char *cmdline_file);
static void sighup_handler(int sig);

/* main */
int main(int argc, char *argv[]) {

    int    cmdlopt;
    char **ovw_file_ptr;
    char  *overwrite_files[MAX_OVW_FILES+1];
    char   overwrite_cmd[MAX_PATH_LEN];
    char   config_file[MAX_PATH_LEN];

#ifdef DEBUG
    fprintf(stderr, "[+] Entering DEBUG mode...\n");
    sleep(1);
#endif

    overwrite_files[0] = NULL;
    strlcpy(config_file, FWKNOP_CONF, MAX_PATH_LEN);
    dump_cfg = 0;

    /* handle command line arguments */
    while((cmdlopt = getopt(argc, argv, "c:O:Dh")) != -1) {
        switch(cmdlopt) {
            case 'c':
                strlcpy(config_file, optarg, MAX_PATH_LEN);
                break;
            case 'O':
                strlcpy(overwrite_cmd, optarg, MAX_PATH_LEN);
                list_to_array(overwrite_cmd, ',', overwrite_files, MAX_OVW_FILES);
                break;
            case 'D':
                dump_cfg = 1;
                break;
            default:
                usage();
        }
    }

    /* clean our settings */
    clean_settings();

    /* Parse both the overwrite and configuration file */
    for (ovw_file_ptr=overwrite_files; *ovw_file_ptr!=NULL; ovw_file_ptr++)
        parse_config(*ovw_file_ptr);
    parse_config(config_file);

    /* Check our settings */
    check_config();

    if (dump_cfg == 1)
        dump_config();

    /* see if we are supposed to disable all email alerts */
    if (strncmp("noemail", alerting_methods, MAX_GEN_LEN) == 0)
        no_email = 1;

    /* first make sure there isn't another knopwatchd already running */
    check_unique_pid(knopwatchd_pid_file, "knopwatchd");

#ifndef DEBUG
    /* become a daemon */
    daemonize_process(knopwatchd_pid_file);
#endif

    /* install signal handler for HUP signals */
    signal(SIGHUP, sighup_handler);

    /* start doing the real work now that the daemon is running and
     * the config file has been processed */

    /* MAIN LOOP */
    for (;;) {
        /* restart processes as necessary */
        check_process("fwknopd", fwknopd_pid_file, fwknopd_cmdline_file,
            fwknopdCmd, knopwatchd_max_retries);

        check_process("knoptm", knoptm_pid_file, NULL,
            knoptmCmd, knopwatchd_max_retries);

        if (check_knopmd)
            check_process("knopmd", knopmd_pid_file, NULL,
                knopmdCmd, knopwatchd_max_retries);

        /* sleep and then check to see if we received any signals */
        sleep(knopwatchd_check_interval);

        /* check for sighup */
        if (received_sighup) {
            received_sighup = 0;

            /* clean our settings */
            clean_settings();

            /* reparse the config file since we received a HUP signal */
            for (ovw_file_ptr=overwrite_files; *ovw_file_ptr!=NULL; ovw_file_ptr++)
                parse_config(*ovw_file_ptr);
            parse_config(config_file);

            check_config();

            slogr("fwknopd(knopwatchd)",
                    "received HUP signal, re-imported fwknop.conf");
        }
    }

    /* this statement doesn't get executed, but for completeness... */
    exit(EXIT_SUCCESS);
}
/******************** end main ********************/

static void check_process(
    const char *pid_name,
    const char *pid_file,
    const char *cmdline_file,
    const char *binary_path,
    unsigned int max_retries)
{
    FILE *pidfile_ptr;
    pid_t pid;
    unsigned short int restart = 0;
    char syslog_str[MAX_MSG_LEN] = "";
    char pid_line[MAX_PID_SIZE];
    fwatch_email alert_email;

    if ((pidfile_ptr = fopen(pid_file, "r")) == NULL) {
#ifdef DEBUG
    fprintf(stderr, "[+] Could not open pid_file: %s\n", pid_file);
#endif
        /* the pid file must not exist (or we can't read it), so
         * setup to start the appropriate process */
        restart = 1;
    }

    /* read the first line of the pid_file, which will contain the
     * process id of any running pid_name process. */
    if (! restart) {
        if (fgets(pid_line, MAX_PID_SIZE, pidfile_ptr) == NULL) {
#ifdef DEBUG
            fprintf(stderr, "[+] Could not read the pid_file: %s\n", pid_file);
#endif
            /* see if we need to give up */
            incr_syscall_ctr(pid_name, max_retries);
            fclose(pidfile_ptr);
            return;
        }

        /* convert the pid_line into an integer */
        pid = atoi(pid_line);

        /* close the pid_file now that we have read it */
        fclose(pidfile_ptr);

        if (kill(pid, 0) != 0) {
            /* the process is not running so start it */
            restart = 1;
        }
    }

    if (restart) {

        snprintf(syslog_str, MAX_MSG_LEN,
            "restarting %s on %s", pid_name, hostname);
        slogr("fwknopd(knopwatchd)", syslog_str);

        /* send the email */
        if (! no_email) {

            alert_email.cmd = (*sendmailCmd != '\0') ? sendmailCmd : mailCmd;
            alert_email.sender = default_mail_sender;
            alert_email.recipient = mail_addrs;
            snprintf(alert_email.subject, sizeof(alert_email.subject),
                        "[*] knopwatchd: Restarting %s on %s",
                        pid_name, hostname);
            alert_email.subject[sizeof(alert_email.subject)-1] = '\0';

            send_alert_email(shCmd, alert_email);
        }

        /* execute the binary_path fwknopd daemon */
        exec_binary(binary_path, cmdline_file);

        /* increment the number of times we have tried to restart the binary */
        incr_syscall_ctr(pid_name, max_retries);
    } else {
#ifdef DEBUG
        fprintf(stderr, "[+] %s is running.\n", pid_name);
#endif
        /* reset the syscall counter since the process is successfully
         * running. */
        reset_syscall_ctr(pid_name);
    }
    return;
}

static void incr_syscall_ctr(const char *pid_name, unsigned int max_retries)
{
    if (strcmp("fwknopd", pid_name) == 0) {
        fwknopd_syscalls_ctr++;
#ifdef DEBUG
        fprintf(stderr,
            "[+] %s not running.  Trying to restart (%d tries so far).\n",
            pid_name, fwknopd_syscalls_ctr);
#endif
        if (fwknopd_syscalls_ctr >= max_retries)
            give_up(pid_name);
    } else if (strcmp("knopmd", pid_name) == 0) {
        knopmd_syscalls_ctr++;
#ifdef DEBUG
        fprintf(stderr,
            "[+] %s not running.  Trying to restart (%d tries so far).\n",
            pid_name, knopmd_syscalls_ctr);
#endif
        if (knopmd_syscalls_ctr >= max_retries)
            give_up(pid_name);
    }
    return;
}

static void reset_syscall_ctr(const char *pid_name)
{
    if (strcmp("fwknopd", pid_name) == 0) {
        fwknopd_syscalls_ctr = 0;
    } else if (strcmp("knopmd", pid_name) == 0) {
        knopmd_syscalls_ctr = 0;
    }
    return;
}

static void give_up(const char *pid_name)
{
    fwatch_email alert_email;

#ifdef DEBUG
    fprintf(stderr, "[*] Could not restart %s process.  Exiting.\n", pid_name);
#endif

    if (! no_email) {

        alert_email.cmd = (*sendmailCmd != '\0') ? sendmailCmd : mailCmd;
        alert_email.sender = default_mail_sender;
        alert_email.recipient = mail_addrs;
        snprintf(alert_email.subject, sizeof(alert_email.subject),
                    "[*] knopwatchd: Could not restart %s on %s. Exiting.",
                    pid_name, hostname);
        alert_email.subject[sizeof(alert_email.subject)-1] = '\0';

        send_alert_email(shCmd, alert_email);
    }

    exit(EXIT_FAILURE);
}

static void exec_binary(const char *binary, const char *cmdlinefile)
{
    FILE *cmdline_ptr;
    char *prog_argv[MAX_ARG_LEN];
    char cmdline_buf[MAX_LINE_BUF];
    char *index;
    pid_t child_pid;
    int arg_num=0, non_ws, i;

#ifdef DEBUG
    fprintf(stderr, "[+] executing exec_binary(%s)\n", binary);
#endif

    prog_argv[arg_num] = (char *) safe_malloc(strlen(binary)+1);
    if (prog_argv[arg_num] == NULL) {
        exit(EXIT_FAILURE);
    }
    strlcpy(prog_argv[arg_num], binary, strlen(binary)+1);
    arg_num++;

    if (cmdlinefile != NULL) {
        /* restart binary with its command line arguments intact */
        if ((cmdline_ptr = fopen(cmdlinefile, "r")) == NULL) {
            exit(EXIT_FAILURE);
        }
        if ((fgets(cmdline_buf, MAX_LINE_BUF, cmdline_ptr)) == NULL) {
            exit(EXIT_FAILURE);
        }
        fclose(cmdline_ptr);

        /* initialize index to the beginning of the line */
        index = cmdline_buf;

        /* advance the index pointer through any whitespace
         * at the beginning of the line */
        while (isspace(*index)) index++;

        while (*index != '\n' && *index != '\0') {
            non_ws = 0;
            while (!isspace(*index) && index != '\0' && *index != '\n') {
                index++;
                non_ws++;
            }
            prog_argv[arg_num] = (char *) safe_malloc(non_ws+1);
            if (prog_argv[arg_num] == NULL) {
                exit(EXIT_FAILURE);
            }
            for (i=0; i<non_ws; i++)
                prog_argv[arg_num][i] = *(index - (non_ws - i));
            prog_argv[arg_num][i] = '\0';

            arg_num++;

            /* get past any whitespace */
            while (isspace(*index)) index++;
        }
    }

    if (arg_num >= MAX_ARG_LEN)
        exit(EXIT_FAILURE);
    prog_argv[arg_num] = NULL;

    if ((child_pid = fork()) < 0)
        /* could not fork */
        exit(EXIT_FAILURE);
    else if (child_pid > 0) {
        wait(NULL);
        for (i=0; i<=arg_num; i++) {
            free(prog_argv[i]);
        }
    } else {
#ifdef DEBUG
        fprintf(stderr, "[+] restarting %s\n", binary);
#endif
        exit(execve(binary, prog_argv, NULL));  /* don't use environment */
    }
    return;
}

static void parse_config(char * file)
{
    FILE *config_ptr;         /* FILE pointer to the config file */
    int linectr = 0;
    char config_buf[MAX_LINE_BUF];
    char *index;
    int tmp;

#ifdef DEBUG
    fprintf(stderr, "[+] Parsing file %s\n", file);
#endif

    if ((config_ptr = fopen(file, "r")) == NULL) {
        perror("[*] Could not open file");
        exit(EXIT_FAILURE);
    }

    /* increment through each line of the config file */
    while ((fgets(config_buf, MAX_LINE_BUF, config_ptr)) != NULL) {
        linectr++;
        index = config_buf;  /* set the index pointer to the
                                beginning of the line */
        /* advance the index pointer through any whitespace
         * at the beginning of the line */
        while (isspace(*index)) index++;

        /* skip comments and blank lines, etc. */
        if ((*index != '#') && (*index != '\n') &&
                (*index != ';') && (index != NULL)) {

            find_char_var("fwknopdCmd", fwknopdCmd, index);
            find_char_var("HOSTNAME", hostname, index);
            find_char_var("FWKNOP_RUN_DIR", fwknop_run_dir, index);
            find_char_var("FWKNOP_PID_FILE", fwknopd_pid_file, index);
            find_char_var("FWKNOP_CMDLINE_FILE", fwknopd_cmdline_file, index);
            find_char_var("knopmdCmd", knopmdCmd, index);
            find_char_var("knoptmCmd", knoptmCmd, index);
            find_char_var("KNOPMD_PID_FILE", knopmd_pid_file, index);
            find_char_var("KNOPTM_PID_FILE", knoptm_pid_file, index);
            find_char_var("shCmd", shCmd, index);
            find_char_var("mailCmd", mailCmd, index);
            find_char_var("EMAIL_ADDRESSES", mail_addrs, index);
            find_char_var("KNOPWATCHD_CHECK_INTERVAL",
                char_knopwatchd_check_interval, index);
            find_char_var("KNOPWATCHD_MAX_RETRIES",
                char_knopwatchd_max_retries, index);
            find_char_var("AUTH_MODE", auth_mode, index);
            find_char_var("ENABLE_SYSLOG_FILE", enable_syslog_file, index);
            find_char_var("KNOPWATCHD_PID_FILE", knopwatchd_pid_file, index);
            find_char_var("ALERTING_METHODS", alerting_methods, index);
            find_char_var("sendmailCmd", sendmailCmd, index);
        }
    }
    fclose(config_ptr);

    tmp = atoi(char_knopwatchd_check_interval);
    if (tmp != 0)
        knopwatchd_check_interval = tmp;

    tmp = atoi(char_knopwatchd_max_retries);
    if (tmp != 0)
        knopwatchd_max_retries = tmp;

    return;
}

static void check_config(void)
{
    unsigned char err;

#ifdef DEBUG
    fprintf(stderr, "[+] Checking configuration...\n");
#endif

    err = 1;
    if (fwknopdCmd[0] == '\0')
        fprintf(stderr, "[*] Could not find fwknopdCmd\n");

    else if (hostname[0] == '\0')
        fprintf(stderr, "[*] Could not find HOSTNAME\n");

    else if (fwknopd_pid_file[0] == '\0')
        fprintf(stderr, "[*] Could not find FWKNOP_PID_FILE\n");

    else if (fwknopd_cmdline_file[0] == '\0')
        fprintf(stderr, "[*] Could not find FWKNOP_CMDLINE_FILE\n");

    else if (knopmdCmd[0] == '\0')
        fprintf(stderr, "[*] Could not find knopmdCmd\n");

    else if (knoptmCmd[0] == '\0')
        fprintf(stderr, "[*] Could not find knoptmCmd\n");

    else if (knopmd_pid_file[0] == '\0')
        fprintf(stderr, "[*] Could not find KNOPMD_PID_FILE\n");

    else if (knoptm_pid_file[0] == '\0')
        fprintf(stderr, "[*] Could not find KNOPTM_PID_FILE\n");

    else if (shCmd[0] == '\0')
        fprintf(stderr, "[*] Could not find shCmd\n");

    else if ((mailCmd[0] == '\0') && (sendmailCmd[0] == '\0'))
        fprintf(stderr, "[*] One of the sendmailCmd or mailCmd variables must \
                                be specified\n");

    else if (mail_addrs[0] == '\0')
        fprintf(stderr, "[*] Could not find EMAIL_ADDRESSES\n");

    else if (knopwatchd_pid_file[0] == '\0')
        fprintf(stderr, "[*] Could not find KNOPWATCHD_PID_FILE\n");

    else if (auth_mode[0] == '\0')
        fprintf(stderr, "[*] Could not find AUTH_MODE\n");

    else if (enable_syslog_file[0] == '\0')
        fprintf(stderr, "[*] Could not find ENABLE_SYSLOG_FILE\n");

    else if (knopwatchd_check_interval <= 0)
        fprintf(stderr, "[*] KNOPWATCHD_CHECK_INTERVAL must be > 0\n");

    else if (knopwatchd_max_retries <= 0)
        fprintf(stderr, "[*] KNOPWATCHD_MAX_RETRIES must be > 0\n");

    else {

        /* Resolve any embedded variables */
        expand_config_vars();

        /* Refresh the need to check knopmd */
        check_knopmd = is_knopmd_required();

        err = 0;
    }

    if (err == 1)
        exit(EXIT_FAILURE);
}

/*
 * Check to see if knopmd should not be running:
 *
 *   - first check if we are using the KNOCK mode
 *   - then, in PK mode, see if ENABLE_SYSLOG_FILE is enabled, so
 *     fwknopd is just parsing a file written to by syslog directly
 *
 * \return 0 if not required
 *         1 otherwise
 */
static unsigned short int is_knopmd_required(void)
{
    unsigned short int required;

    required = 0;

    if (strncmp(auth_mode, "KNOCK", MAX_GEN_LEN) == 0)
        required = 1;

    if ( (check_knopmd) && (strncmp(enable_syslog_file, "Y", 1) == 0) )
        required = 0;

    return required;
}

static void expand_config_vars(void)
{
    char sub_var[MAX_GEN_LEN]  = "";
    char pre_str[MAX_GEN_LEN]  = "";
    char post_str[MAX_GEN_LEN] = "";
    int found_sub_var = 1, resolve_ctr = 0;

    while (found_sub_var) {
        resolve_ctr++;
        if (resolve_ctr >= 20) {
            fprintf(stderr, "[*] Exceeded maximum variable resolution attempts.\n");
            exit(EXIT_FAILURE);
        }
        found_sub_var = 0;
        if (has_sub_var("EMAIL_ADDRESSES", mail_addrs, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(mail_addrs, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("HOSTNAME", hostname, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(hostname, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("FWKNOP_RUN_DIR", fwknop_run_dir, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(fwknop_run_dir, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("FWKNOP_PID_FILE", fwknopd_pid_file, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(fwknopd_pid_file, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("FWKNOP_CMDLINE_FILE", fwknopd_cmdline_file, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(fwknopd_cmdline_file, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("KNOPMD_PID_FILE", knopmd_pid_file, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(knopmd_pid_file, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("KNOPTM_PID_FILE", knoptm_pid_file, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(knoptm_pid_file, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("KNOPWATCHD_PID_FILE", knopwatchd_pid_file, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(knopwatchd_pid_file, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("KNOPWATCHD_CHECK_INTERVAL",
                char_knopwatchd_check_interval, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(char_knopwatchd_check_interval,
                sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("KNOPWATCHD_MAX_RETRIES", char_knopwatchd_max_retries,
                sub_var, pre_str, post_str)) {
            find_sub_var_value(char_knopwatchd_max_retries,
                sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("mailCmd", mailCmd, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(mailCmd, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("sendmailCmd", sendmailCmd, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(sendmailCmd, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("shCmd", shCmd, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(shCmd, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("knopmdCmd", knopmdCmd, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(knopmdCmd, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("fwknopdCmd", fwknopdCmd, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(fwknopdCmd, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }
    }

    return;
}

static void find_sub_var_value(char *value, char *sub_var, char *pre_str,
    char *post_str)
{
    int found_var = 0;
    if (strncmp(sub_var, "EMAIL_ADDRESSES", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, mail_addrs, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "HOSTNAME", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, hostname, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "FWKNOP_RUN_DIR", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, fwknop_run_dir, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "FWKNOP_PID_FILE", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, fwknopd_pid_file, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "FWKNOP_CMDLINE_FILE", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, fwknopd_cmdline_file, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "KNOPMD_PID_FILE", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, knopmd_pid_file, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "KNOPTM_PID_FILE", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, knoptm_pid_file, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "KNOPWATCHD_PID_FILE", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, knopwatchd_pid_file, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "KNOPWATCDHD_CHECK_INTERVAL", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, char_knopwatchd_check_interval, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "KNOPWATCDHD_MAX_RETRIES", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, char_knopwatchd_max_retries, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "mailCmd", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, mailCmd, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "sendmailCmd", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, sendmailCmd, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "shCmd", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, shCmd, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "knopmdCmd", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, knopmdCmd, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "fwknopdCmd", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, fwknopdCmd, MAX_GEN_LEN);
        found_var = 1;
    }

    if (found_var)

        /* substitute the variable value */
        expand_sub_var_value(value, sub_var, pre_str, post_str);

    else {
        fprintf(stderr, "[*] Could not resolve sub-var: %s to a value.\n",
            sub_var);
        exit(EXIT_FAILURE);
    }
    return;
}

static void sighup_handler(int sig)
{
    received_sighup = 1;
}

static void clean_settings (void)
{
#ifdef DEBUG
    fprintf(stderr, "[+] Cleaning settings\n");
#endif

    /* Set the default values used by knopwatchd when trying to 
     * restart the fwknopd, knoptm and knopmd daemons (5s /10 times) */
    knopwatchd_check_interval = 5;
    knopwatchd_max_retries    = 10;

    *hostname                       = '\0';
    *mail_addrs                     = '\0';
    *shCmd                          = '\0';
    *mailCmd                        = '\0';
    *sendmailCmd                    = '\0';
    *fwknop_run_dir                 = '\0';
    *alerting_methods               = '\0';
    *fwknopdCmd                     = '\0';
    *fwknopd_pid_file               = '\0';
    *fwknopd_cmdline_file           = '\0';
    *knopmdCmd                      = '\0';
    *knoptmCmd                      = '\0';
    *knopmd_pid_file                = '\0';
    *knoptm_pid_file                = '\0';
    *knopwatchd_pid_file            = '\0';
    *char_knopwatchd_check_interval = '\0';
    *char_knopwatchd_max_retries    = '\0';
    *enable_syslog_file             = '\0';
    *auth_mode                      = '\0';
}

static void dump_config (void)
{
    fprintf(stdout, "[+] Dumping settings...\n\n");

    fprintf(stderr, "%30s\t%s\n", "fwknopdCmd", fwknopdCmd);
    fprintf(stderr, "%30s\t%s\n", "hostname", hostname);
    fprintf(stderr, "%30s\t%s\n", "fwknopd_pid_file", fwknopd_pid_file);
    fprintf(stderr, "%30s\t%s\n", "fwknopd_cmdline_file", fwknopd_cmdline_file);
    fprintf(stderr, "%30s\t%s\n", "knopmdCmd", knopmdCmd);
    fprintf(stderr, "%30s\t%s\n", "knoptmCmd", knoptmCmd);
    fprintf(stderr, "%30s\t%s\n", "knopmd_pid_file", knopmd_pid_file);
    fprintf(stderr, "%30s\t%s\n", "knoptm_pid_file", knoptm_pid_file);
    fprintf(stderr, "%30s\t%s\n", "knopwatchd_pid_file", knopwatchd_pid_file);
    fprintf(stderr, "%30s\t%s\n", "shCmd", shCmd);
    fprintf(stderr, "%30s\t%s\n", "mailCmd", mailCmd);
    fprintf(stderr, "%30s\t%s\n", "sendmailCmd", sendmailCmd);
    fprintf(stderr, "%30s\t%s\n", "mail_addrs", mail_addrs);
    fprintf(stderr, "%30s\t%u\n", "knopwatchd_check_interval",
                                knopwatchd_check_interval);
    fprintf(stderr, "%30s\t%u\n", "knopwatchd_max_retries",
                                knopwatchd_max_retries);
    fprintf(stderr, "%30s\t%s\n", "alerting_methods", alerting_methods);
    fprintf(stderr, "%30s\t%s\n", "ENABLE_SYSLOG_FILE", enable_syslog_file);
    fprintf(stderr, "%30s\t%s\n", "AUTH_MODE", auth_mode);

    exit(EXIT_SUCCESS);
}

static void usage (void)
{
    fprintf(stderr, "knopwatchd - Fwknop watch daemon\n\n");

    fprintf(stderr, "[+] Version: %s\n", FWKNOP_VERSION);
    fprintf(stderr,
"    By Michael Rash (mbr@cipherdyne.org)\n"
"    URL: http://www.cipherdyne.org/fwknop/\n\n");

    fprintf(stderr, "Usage: knopwatchd [options]\n\n");

    fprintf(stderr,
"Options:\n"
"    -c <file>          - Specify path to config file instead of using the\n"
"                         default $config_file.\n"
"    -D                 - Dump  the  configuration values that fwknopd\n"
"                         derives from the /etc/fwknop/fwknop.conf (or other\n"
"                         override files) on STDERR\n"
"    -h                 - Display this usage message and exit\n"
"    -O <file>          - Override config variable values that are normally\n"
"                         read from the /etc/fwknop/fwknop.conf file with\n"
"                         values from the specified file\n");

    exit(EXIT_FAILURE);
}
