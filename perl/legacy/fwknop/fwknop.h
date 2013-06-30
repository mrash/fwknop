/*
********************************************************************************
*
*  File: fwknop.h
*
*  Author: Michael Rash (mbr@cipherdyne.org)
*
*  Purpose: fwknop.h include appropriate system header files, and defines file
*           paths, function prototypes, and constants that are needed by
*           the C versions of fwknop.
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
********************************************************************************
*
*  $Id: fwknop.h 1533 2009-09-08 02:44:02Z mbr $
*/

#ifndef __FWKNOP_H__
#define __FWKNOP_H__

/* INCLUDES *******************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>    /* read(), write(), and close() */
#include <fcntl.h>     /* open() */
#include <sys/stat.h>  /* umask */
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>
#include <ctype.h>

/* DEFINES ********************************************************************/
#define FWKNOP_VERSION      "1.9.12"
#define MAX_LINE_BUF 1024
#define MAX_PID_SIZE 6
#define MAX_PATH_LEN 100
#define MAX_MSG_LEN 300 /* might have a long string of email addresses */
#define MAX_GEN_LEN 80
#define MAX_ARG_LEN 30
#define MAX_NUM_LEN 6

/* This structure defines data to send an email
 *   - cmd: command to use (sendmail, mail)
 *   - sender: sender of the email
 *   - recipient: recipient of the email (can be a comma separated list)
 *   - subject: subject of the email
 */
typedef struct
{
    char *cmd;
    char *sender;
    char *recipient;
    char  subject[MAX_GEN_LEN];
} fwatch_email;

/* PROTOTYPES *****************************************************************/
void slogr(const char *, const char *);
void check_unique_pid(const char *, const char *);
void write_pid(const char *, pid_t);
void daemonize_process(const char *);
void send_alert_email(const char *shCmd, fwatch_email stEmail);
int has_sub_var(char *var_name, char *value, char *sub_var,
    char *pre_str, char *post_str);
void expand_sub_var_value(char *value, const char *sub_var,
    const char *pre_str, const char *post_str);
int find_char_var(char *, char *, char *);
void *safe_malloc(const unsigned int len);
void list_to_array(char *ptList, const char sep, char **array,
    unsigned char max_arg);

/* From OpenBSD */
size_t strlcpy(char *, const char *, size_t);
size_t strlcat(char *, const char *, size_t);

#endif  /* __FWKNOP_H__ */
