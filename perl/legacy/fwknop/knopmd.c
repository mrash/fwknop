/*
******************************************************************************
*
*  File: knopmd.c
*
*  Purpose: knopmd separates iptables messages from all other kernel
*           messages.  NOTE: This daemon is obselete since the main method
*           of passive authorization is Single Packet Authorization (SPA),
*           which offers better security properties than port knocking.
*
*  Author: Michael Rash (mbr@cipherdyne.org)
*
*  Version: 1.8
*
*  Copyright (C) 2004-2009 Michael Rash (mbr@cipherdyne.org)
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
*  NOTE: This code is essentially borrowed from kmsgsd.c that is bundled
*        psad: http://www.cipherdyne.org/psad/
*
******************************************************************************
*
*  $Id: knopmd.c 1519 2009-08-11 23:56:57Z mbr $
*/

/* includes */
#include "fwknop.h"
#include <getopt.h>

/* defines */
#define FWKNOP_CONF "/etc/fwknop/fwknop.conf"

/* globals */
static volatile sig_atomic_t received_sighup = 0;
extern char *optarg; /* for getopt */
extern int   optind; /* for getopt */
char *fw_msg_search[MAX_GEN_LEN];
int num_fw_search_strings = 0;
int fw_search_all_flag = 1;  /* default to parse all iptables messages */
char fwknopfifo_file[MAX_PATH_LEN];
char fwdata_file[MAX_PATH_LEN];
char config_file[MAX_PATH_LEN];
char fw_search_file[MAX_PATH_LEN];
char knopmd_pid_file[MAX_PATH_LEN];
char fwknop_dir[MAX_PATH_LEN];
char fwknop_fifo_dir[MAX_PATH_LEN];
char fwknop_run_dir[MAX_PATH_LEN];

/* prototypes */
static void parse_config(void);
static void find_sub_var_value(
    char *value,
    char *sub_var,
    char *pre_str,
    char *post_str
);
static void expand_config_vars(void);
static void check_auth_mode(void);
static int match_fw_msg(char *fw_mgs);
static void sighup_handler(int sig);

/* main */
int main(int argc, char *argv[]) {
    char buf[MAX_LINE_BUF];
    int fifo_fd, fwdata_fd;  /* file descriptors */
    int cmdlopt, numbytes;
#ifdef DEBUG
    int matched_ipt_log_msg = 0;
    int fwlinectr = 0;
#endif

#ifdef DEBUG
    fprintf(stderr, "[+] Entering DEBUG mode\n");
    fprintf(stderr, "[+] Firewall messages will be written to both ");
    fprintf(stderr, "STDOUT _and_ to fwdata.\n\n");
#endif

    strlcpy(config_file, FWKNOP_CONF, MAX_PATH_LEN);

    while((cmdlopt = getopt(argc, argv, "c:")) != -1) {
        switch(cmdlopt) {
            case 'c':
                strlcpy(config_file, optarg, MAX_PATH_LEN);
                break;
            default:
                printf("[+] Usage:  knopmd [-c <config file>] ");
                exit(EXIT_FAILURE);
        }
    }

#ifdef DEBUG
    fprintf(stderr, "[+] parsing config_file: %s\n", config_file);
#endif
    /* parse config file (knopmd.conf) */
    parse_config();

    /* make sure there isn't another knopmd already running */
    check_unique_pid(knopmd_pid_file, "knopmd");

#ifndef DEBUG
    /* become a daemon */
    daemonize_process(knopmd_pid_file);
#endif

    /* install signal handler for HUP signals */
    signal(SIGHUP, sighup_handler);

    /* start doing the real work now that the daemon is running and
     * the config file has been processed */

    /* open the fwknopfifo named pipe.  Note that we are opening the pipe
     * _without_ the O_NONBLOCK flag since we want the read on the file
     * descriptor to block until there is something new in the pipe.
     * Also, not that we are opening with O_RDWR, since this seems to
     * fix the problem with knopmd not blocking on the read() if the
     * system logger dies (and hence closes its file descriptor for the
     * fwknopfifo). */
    if ((fifo_fd = open(fwknopfifo_file, O_RDWR)) < 0) {
        fprintf(stderr, "[-] Could not open %s for reading.\n",
            fwknopfifo_file);
        exit(EXIT_FAILURE);  /* could not open fwknopfifo named pipe */
    }

    /* open the fwdata file in append mode so we can write messages from
     * the pipe into this file. */
    if ((fwdata_fd = open(fwdata_file,
            O_CREAT|O_WRONLY|O_APPEND, 0600)) < 0) {
        fprintf(stderr, "[-] Could not open %s for writing.\n", fwdata_file);
        exit(EXIT_FAILURE);  /* could not open fwdata file */
    }

    /* MAIN LOOP;
     * Read data from the pipe indefinitely (we opened it _without_
     * O_NONBLOCK) and write it to the fwdata file if it is a firewall message
     */
    while ((numbytes = read(fifo_fd, buf, MAX_LINE_BUF-1)) >= 0) {

#ifdef DEBUG
        fprintf(stderr,
            "read %d bytes from %s fifo.\n", numbytes, fwknopfifo_file);
#endif

        /* make sure the buf contents qualifies as a string */
        buf[numbytes] = '\0';

        if (received_sighup) {
            /* clear the signal flag */
            received_sighup = 0;

            /* re-parse the config file after receiving HUP signal */
            parse_config();

            /* close file descriptors and re-open them after
             * re-reading config file */
            close(fifo_fd);
            close(fwdata_fd);

            /* re-open fwknopfifo and fwdata files */
            if ((fifo_fd = open(fwknopfifo_file, O_RDONLY)) < 0) {
                fprintf(stderr, "[-] Could not open %s for reading.\n",
                    fwknopfifo_file);
                exit(EXIT_FAILURE);  /* could not open fwknopfifo named pipe */
            }

            if ((fwdata_fd = open(fwdata_file, O_CREAT|O_WRONLY|O_APPEND,
                    0600)) < 0) {
                fprintf(stderr, "[-] Could not open %s for writing.\n",
                    fwdata_file);
                exit(EXIT_FAILURE);  /* could not open fwdata file */
            }
            slogr("fwknop(knopmd)",
                    "[+] received HUP signal, re-imported knopmd.conf");
        }

        /* see if we matched a firewall message and write it to the
         * fwdata file */
        if ((strstr(buf, "OUT") != NULL
                && strstr(buf, "IN") != NULL)) {
            if (! fw_search_all_flag) {  /* we are looking for specific log prefixes */
                if (match_fw_msg(buf)) {
                    if (write(fwdata_fd, buf, numbytes) < 0) {
                        exit(EXIT_FAILURE);  /* could not write to the fwdata file */
                    }
#ifdef DEBUG
                    matched_ipt_log_msg = 1;
#endif
                }
            } else {
                if (write(fwdata_fd, buf, numbytes) < 0)
                    exit(EXIT_FAILURE);  /* could not write to the fwdata file */
#ifdef DEBUG
                matched_ipt_log_msg = 1;
#endif
            }
#ifdef DEBUG
            if (matched_ipt_log_msg) {
                puts(buf);
                fprintf(stderr, "[+] Line matched search strings.\n");
                fwlinectr++;
                if (fwlinectr % 50 == 0)
                    fprintf(stderr,
                        "[+] Processed %d firewall lines.\n", fwlinectr);
                matched_ipt_log_msg = 0;
            } else {
                puts(buf);
                printf("[-] Line did not match search strings.\n");
            }
#endif
        }
    }

    /* these statements don't get executed, but for completeness... */
    close(fifo_fd);
    close(fwdata_fd);

    exit(EXIT_SUCCESS);
}
/******************** end main ********************/

static int match_fw_msg(char *fw_msg)
{
    int i;
    for (i=0; i < num_fw_search_strings; i++)
        if (strstr(fw_msg, fw_msg_search[i]) != NULL)
            return 1;
    return 0;
}

static void parse_config(void)
{
    FILE *config_ptr;   /* FILE pointer to the config file */
    unsigned int linectr = 0, i;
    char config_buf[MAX_LINE_BUF], tmp_fw_search_buf[MAX_GEN_LEN];
    char *index;

    /* first check to see if knopmd should not be running (i.e.
     * AUTH_MODE in the fwknop.conf file is set to a pcap-based
     * method). */
    check_auth_mode();

    for (i=0; i < num_fw_search_strings; i++)
        free(fw_msg_search[i]);

    num_fw_search_strings = 0;
    fw_msg_search[num_fw_search_strings] = NULL;

    if ((config_ptr = fopen(config_file, "r")) == NULL) {
        fprintf(stderr, "[-] Could not open %s for reading.\n",
            config_file);
        exit(EXIT_FAILURE);
    }

    /* increment through each line of the config file */
    while ((fgets(config_buf, MAX_LINE_BUF, config_ptr)) != NULL) {
        linectr++;
        /* set the index pointer to the beginning of the line */
        index = config_buf;

        /* advance the index pointer through any whitespace
         * at the beginning of the line */
        while (*index == ' ' || *index == '\t') index++;

        /* skip comments and blank lines, etc. */
        if ((*index != '#') && (*index != '\n') &&
                (*index != ';') && (index != NULL)) {

            find_char_var("FWKNOP_DIR", fwknop_dir, index);
            find_char_var("KNOPMD_FIFO", fwknopfifo_file, index);
            find_char_var("FW_DATA_FILE", fwdata_file, index);
            find_char_var("KNOPMD_PID_FILE", knopmd_pid_file, index);
            find_char_var("FWKNOP_LIB_DIR", fwknop_fifo_dir, index);
            find_char_var("FWKNOP_RUN_DIR", fwknop_run_dir, index);

            if (find_char_var("FW_MSG_SEARCH", tmp_fw_search_buf, index)) {
                fw_msg_search[num_fw_search_strings]
                    = (char *) safe_malloc(strlen(tmp_fw_search_buf)+1);
                strlcpy(fw_msg_search[num_fw_search_strings],
                    tmp_fw_search_buf, MAX_GEN_LEN);
                num_fw_search_strings++;
            }
            if (find_char_var("FW_SEARCH_ALL", tmp_fw_search_buf, index)) {
                if (tmp_fw_search_buf[0] == 'N')
                    fw_search_all_flag = 0;
            }
        }
    }
    fclose(config_ptr);

    /* resolve any embedded variables */
    expand_config_vars();

#ifdef DEBUG
    fprintf(stderr, "[+] FWKNOP_DIR: %s\n", fwknop_dir);
    fprintf(stderr, "[+] KNOPMD_FIFO: %s\n", fwknopfifo_file);
    fprintf(stderr, "[+] FW_DATA_FILE: %s\n", fwdata_file);
    fprintf(stderr, "[+] KNOPMD_PID_FILE: %s\n", knopmd_pid_file);
#endif
    return;
}

static void check_auth_mode(void)
{
    FILE *config_ptr;   /* FILE pointer to the config file */
    char config_buf[MAX_LINE_BUF];
    char auth_mode[MAX_GEN_LEN];
    char *index;

    if ((config_ptr = fopen(FWKNOP_CONF, "r")) == NULL) {
        fprintf(stderr, "[-] Could not open %s for reading.\n",
            FWKNOP_CONF);
        exit(EXIT_FAILURE);
    }

    auth_mode[0] = '\0';

    /* increment through each line of the config file */
    while ((fgets(config_buf, MAX_LINE_BUF, config_ptr)) != NULL) {
        /* set the index pointer to the beginning of the line */
        index = config_buf;

        /* advance the index pointer through any whitespace
         * at the beginning of the line */
        while (*index == ' ' || *index == '\t') index++;

        /* skip comments and blank lines, etc. */
        if ((*index != '#') && (*index != '\n') &&
                (*index != ';') && (index != NULL)) {

            find_char_var("AUTH_MODE ", auth_mode, index);
        }
    }
    fclose(config_ptr);

    /* see if we are using the ULOG_PCAP mode */
    if (strncmp(auth_mode, "ULOG_PCAP", MAX_GEN_LEN) == 0)
        exit(EXIT_FAILURE);

    /* see if we are using the PCAP mode */
    if (strncmp(auth_mode, "PCAP", MAX_GEN_LEN) == 0)
        exit(EXIT_FAILURE);

    return;
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

        if (has_sub_var("FW_DATA_FILE", fwdata_file, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(fwdata_file, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("KNOPMD_FIFO", fwknopfifo_file, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(fwknopfifo_file, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }

        if (has_sub_var("KNOPMD_PID_FILE", knopmd_pid_file, sub_var,
                pre_str, post_str)) {
            find_sub_var_value(knopmd_pid_file, sub_var, pre_str, post_str);
            found_sub_var = 1;
        }
    }
    return;
}

static void find_sub_var_value(char *value, char *sub_var, char *pre_str,
    char *post_str)
{
    int found_var = 0;
    if (strncmp(sub_var, "FWKNOP_DIR", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, fwknop_dir, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "FWKNOP_LIB_DIR", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, fwknop_fifo_dir, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "FWKNOP_RUN_DIR", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, fwknop_run_dir, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "FW_DATA_FILE", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, fwdata_file, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "KNOPMD_FIFO", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, fwknopfifo_file, MAX_GEN_LEN);
        found_var = 1;
    } else if (strncmp(sub_var, "KNOPMD_PID_FILE", MAX_GEN_LEN) == 0) {
        strlcpy(sub_var, knopmd_pid_file, MAX_GEN_LEN);
        found_var = 1;
    }

    if (found_var) {

        /* substitute the variable value */
        expand_sub_var_value(value, sub_var, pre_str, post_str);

    } else {
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
