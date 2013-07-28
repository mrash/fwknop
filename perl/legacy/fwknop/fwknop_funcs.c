/*
********************************************************************************
*
*  File: fwknop_funcs.c
*
*  Purpose: fwknop_funcs.c contains several functions that are needed by
*           the fwkmd and fwkwd daemons, so putting these functions in
*           a single file make sense.
*
*  Author: Michael Rash (mbr@cipherdyne.org)
*
*  Version: 0.1
*
*  Copyright (C) 2004 Michael Rash (mbr@cipherdyne.org)
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
********************************************************************************
*
*  $Id: fwknop_funcs.c 1375 2009-01-09 06:01:14Z mbr $
*/

/* includes */
#include "fwknop.h"

/* shared functions */
void slogr(const char *ident, const char *msg) {
    openlog(ident, LOG_DAEMON, LOG_LOCAL7);
    syslog(LOG_INFO, "%s", msg);
    closelog();
    return;
}

void check_unique_pid(const char *pid_file, const char *prog_name)
{
    FILE *pidfile_ptr;
    pid_t pid;
    char pid_line[MAX_PID_SIZE+1];

#ifdef DEBUG
    fprintf(stderr,
        "[+] check_unique_pid(): opening pid file %s\n", pid_file);
#endif

    if ((pidfile_ptr = fopen(pid_file, "r")) == NULL) {
        /* the pid file must not exist (or we can't read it), so
         * return... write_pid() will create it */
        return;
    }

    /* read the first line of the pid_file, which will contain the
     * process id of any running fwknop process */
    if (fgets(pid_line, MAX_PID_SIZE+1, pidfile_ptr) == NULL) {
        return;
    }

    /* turn the pid_line into an integer */
    pid = atoi(pid_line);

    /* close the pid_file now that we have read it */
    fclose(pidfile_ptr);

#ifdef DEBUG
    fprintf(stderr,
        "[+] check_unique_pid(): checking pid: %d with kill 0\n", pid);
#endif

    if (kill(pid, 0) == 0) {  /* another prog_name is already running */
        fprintf(stderr, "[*] %s is already running as pid: %d\n",
            prog_name, pid);
        exit(EXIT_FAILURE);
    } else {
        return;
    }

    return; /* for completness */
}

void write_pid(const char *pid_file, const pid_t pid)
{
    FILE *pidfile_ptr;

    if ((pidfile_ptr = fopen(pid_file, "w")) == NULL) {
        /* could not open the pid file */
        fprintf(stderr, "[*] Could not open the pid file: %s", pid_file);
        exit(EXIT_FAILURE);
    }

    /* write the pid to the pid file */
    if (fprintf(pidfile_ptr, "%d\n", pid) == 0) {
        fprintf(stderr, "[*] pid: %d could not be written to pid file: %s",
                pid, pid_file);
        exit(EXIT_FAILURE);
    }

    /* close the pid_file now that we have read it */
    fclose(pidfile_ptr);

    /* set permissions to 0600 (suggested by Franck Joncourt) */
    chmod(pid_file, 0600);

    return;
}

int find_char_var(char *search_str, char *charvar, char *line)
{
    char *index_tmp;
    char *ptEnd;
    int i;

    /* There is no need to check for this  variable since this one
     * is already setup */
    if (*charvar != 0)
        return 0;

    index_tmp = line;

    /* look for specific variables in the config
     * file that match the search_str */
    for (i=0; i < strlen(search_str); i++)
        if (*index_tmp++ != search_str[i])
            return 0;

    /* require trailing space char or tab */
    if (!isspace(*index_tmp++))
        return 0;

#ifdef DEBUG
    fprintf(stderr, "[+] find_char_var(): found %s in line: %s",
            search_str, line);
#endif

    /* go to the beginning of the value */
    while(isspace(*index_tmp))
        index_tmp++;

    /* make sure that the variable has a semicolon at the end of the line */
    ptEnd = strchr(index_tmp, ';');
    if (ptEnd == NULL) {
        fprintf(stderr,
            "[*] find_char_var(): No ending semicolon found for: %s.\n",
            search_str);
        exit(EXIT_FAILURE);
    }

    /* make sure the value is not too long */
    *ptEnd = '\0';
    if (strlen(index_tmp) > MAX_GEN_LEN-1) {
        fprintf(stderr,
                "[*] find_char_var(): the config line for %s is too long. ",
                search_str);
        fprintf(stderr, "Exiting.\n");
        exit(EXIT_FAILURE);
    }

    /* copy the value to charvar */
    strlcpy(charvar, index_tmp, MAX_GEN_LEN);
    return 1;
}

void *safe_malloc(const unsigned int len)
{
    void *buf = NULL;
    buf = malloc(len);
    if (buf == NULL) {
        fprintf(stderr, "[*] Could not malloc() %d bytes\n", len);
        exit(EXIT_FAILURE);
    }
    return buf;
}

int has_sub_var(char *var_name, char *value, char *sub_var,
    char *pre_str, char *post_str)
{
    unsigned int i, sub_var_ctr = 0, found_sub_var = 0;
    unsigned int pre_str_ctr = 0, found_pre_str = 1;
    unsigned int post_str_ctr = 0, found_post_str = 0;
    unsigned int found_one_var = 0;

    sub_var[0]  = '\0';
    pre_str[0]  = '\0';
    post_str[0] = '\0';

    for (i=0; i < strlen(value); i++) {
        if (found_sub_var) {
            if (! isdigit(value[i])
                    && ! isalpha(value[i]) && value[i] != '_') {
                found_sub_var  = 0;
                found_post_str = 1;
                found_one_var  = 1;
            } else {
                if (! found_one_var) {
                    sub_var[sub_var_ctr] = value[i];
                    sub_var_ctr++;
                }
            }
        }

        if (found_pre_str && value[i] != '$') {
            pre_str[pre_str_ctr] = value[i];
            pre_str_ctr++;
        }

        if (found_post_str) {
            post_str[post_str_ctr] = value[i];
            post_str_ctr++;
        }

        if (value[i] == '$') {
            found_sub_var = 1;
            found_pre_str = 0;
            pre_str[pre_str_ctr] = '\0';
        }
    }
    if (sub_var_ctr >= MAX_GEN_LEN - 1) {
        printf("[*] Sub-var length exceeds maximum of %d chars within var: %s\n",
                MAX_GEN_LEN, var_name);
        exit(EXIT_FAILURE);
    }
    if (sub_var[0] != '\0') {
        sub_var[sub_var_ctr]   = '\0';
        post_str[post_str_ctr] = '\0';
        if (strncmp(sub_var, var_name, MAX_GEN_LEN) == 0) {
            printf("[*] Cannot have identical var to sub-var: %s\n",
                    sub_var);
            exit(EXIT_FAILURE);
        }
        return 1;
    }

    return 0;
}

void expand_sub_var_value(char *value, const char *sub_var,
    const char *pre_str, const char *post_str)
{
    if (strlen(sub_var) + strlen(pre_str) + strlen(post_str)
            > MAX_GEN_LEN) {
        printf("[*] Variable value too long: %s%s%s\n",
            sub_var, pre_str, post_str);
        exit(EXIT_FAILURE);
    }
    strlcpy(value, pre_str, MAX_GEN_LEN);
    strlcat(value, sub_var, MAX_GEN_LEN);
    strlcat(value, post_str, MAX_GEN_LEN);
    return;
}

/*
 * Do everything required to cleanly become a daemon: fork(), start
 * a new session, chdir "/", and close un-needed standard filehandles.
 */
void daemonize_process(const char *pid_file)
{
    pid_t child_pid, sid;

    if ((child_pid = fork()) < 0) {
        fprintf(stderr, "[*] Could not fork()");
        exit(EXIT_FAILURE);
    }

    if (child_pid > 0) {
#ifdef DEBUG
        fprintf(stderr, "[+] writing pid: %d to pid file: %s\n",
                child_pid, pid_file);
#endif
        write_pid(pid_file, child_pid);
        exit(EXIT_SUCCESS);   /* exit the parent process */
    }

    /*
     * Now we are in the child process
     */

    /* start a new session */
    if ((sid = setsid()) < 0) {
        fprintf(stderr, "[*] setsid() Could not start a new session");
        exit(EXIT_FAILURE);
    }

    /* make "/" the current directory */
    if ((chdir("/")) < 0) {
        fprintf(stderr, "[*] Could not chdir() to /");
        exit(EXIT_FAILURE);
    }

    /* reset the our umask (for completeness) */
    umask(0);

    /* close un-needed file handles */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    return;
}

/*
 * This function sends an email alert.
 * The mail command is executed from the shell interpreter without relying on
 * any local environment variable.
 *
 * @shCmd: command to use to invoke the shell niterpreter
 * @fwk_email: structure containing data required to send an email
 */
void send_alert_email(const char *shCmd, fwatch_email fwk_email)
{
    char *cmd_name;
    char  exec_line[MAX_MSG_LEN];
    pid_t child_pid;

    /* Set a pointer on the name of the mail command to use */
    cmd_name = strrchr(fwk_email.cmd, '/');
    cmd_name = (cmd_name == NULL) ? fwk_email.cmd : cmd_name+1;

    /* Write the invocation of the sendmail command*/
    if (strncmp(cmd_name, "sendmail", 8) == 0) {
        snprintf(exec_line, sizeof(exec_line),
                    "%s -t << EOF\nFrom: %s\nTo: %s\nSubject: %s\n\nEOF",
                    fwk_email.cmd, fwk_email.sender, fwk_email.recipient,
                    fwk_email.subject);

    /* Write the invokation of the mail command */
    } else {
        snprintf(exec_line, sizeof(exec_line),
                     "%s -s \"%s\" %s < /dev/null > /dev/null 2>&1",
                     fwk_email.cmd, fwk_email.subject, fwk_email.recipient);
    }

    /* Make sure the string is NULL-terminated if truncated */
    exec_line[sizeof(exec_line)-1] = '\0';

#ifdef DEBUG
    fprintf(stderr, "[+] sending mail with the following command:\n%s\n",
                exec_line);
#endif

    /* Fork and execute the mail command from the sh interpreter
     * without local env */
    if ((child_pid = fork()) < 0)
        exit(EXIT_FAILURE);

    else if (child_pid > 0)
        wait(NULL);  /* mail better work */

    else {
        exit(execle(shCmd, shCmd, "-c", exec_line, NULL, NULL));
    }
    return;
}

void list_to_array(char *list_ptr, const char sep, char **array,
        unsigned char max_arg)
{
    unsigned char  ix;

    ix = 0;

    while ( (list_ptr != NULL) && (ix < max_arg) ) {

        array[ix] = list_ptr;

        list_ptr = strchr(list_ptr, sep);
        if (list_ptr != NULL)
            *list_ptr++ = '\0';

        ix++;
    }

    array[ix] = NULL;
}
