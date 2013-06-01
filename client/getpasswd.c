/*
 *****************************************************************************
 *
 * File:    getpasswd.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Routines for obtaining a password from a user.
 *
 * Copyright 2009-2010 Damien Stuart (dstuart@dstuart.org)
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
#include <stdio.h>
#include <signal.h>

#ifdef WIN32
  #include <conio.h>
#else
  #include <termios.h>
#endif

#include "fwknop_common.h"
#include "getpasswd.h"

#define PW_BUFSIZE              128                 /*!< Maximum number of chars an encryption key or a password can contain */

#define PW_BREAK_CHAR           0x03                /*!< Ascii code for the Ctrl-C char */
#define PW_BS_CHAR              0x08                /*!< Ascii code for the backspace char */
#define PW_LF_CHAR              0x0A                /*!< Ascii code for the \n char */
#define PW_CR_CHAR              0x0D                /*!< Ascii code for the \r char */
#define PW_CLEAR_CHAR           0x15                /*!< Ascii code for the Ctrl-U char */

#define ARRAY_FIRST_ELT_ADR(t)  &((t)[0])           /*!< Macro to get the first element of an array */
#define ARRAY_LAST_ELT_ADR(t)   &((t)[sizeof(t)-1]) /*!< Macro to get the last element of an array */

/**
 * @brief Read a password from a stream object
 *
 * @param stream Pointer to a FILE object that identifies an input stream.
 *
 * @return The password buffer or NULL if not set
 */
static char *
read_passwd_from_stream(FILE *stream)
{
    static char     password[PW_BUFSIZE] = {0};
    int             c;
    char           *ptr;

    ptr = ARRAY_FIRST_ELT_ADR(password);

#ifdef WIN32
    while((c = _getch()) != PW_CR_CHAR)
#else
    while( ((c = getc(stream)) != EOF) && (c != PW_LF_CHAR) && (c != PW_BREAK_CHAR) )
#endif
    {
        /* Handle a backspace without backing up too far. */
        if (c == PW_BS_CHAR)
        {
            if (ptr != ARRAY_FIRST_ELT_ADR(password))
                ptr--;
        }

        /* Handle a Ctrl-U to clear the password entry and start over */
        else if (c == PW_CLEAR_CHAR)
            ptr = ARRAY_FIRST_ELT_ADR(password);

        /* Fill in the password buffer until it reach the last -1 char.
         * The last char is used to NULL terminate the string. */
        else if (ptr < ARRAY_LAST_ELT_ADR(password))
        {
            *ptr++ = c;
        }

        /* Discard char */
        else;
    }

    /* A CTRL-C char has been detected, we discard the password */
    if (c == PW_BREAK_CHAR)
        password[0] = '\0';

    /* Otherwise we NULL terminate the string here. Overflows are handled
     * previously, so we can add the char without worrying */
    else
        *ptr = '\0';

    return password;
}

/**
 * @brief Function for accepting password input from users
 *
 * The functions reads chars from the terminal and store them in a buffer of chars.
 *
 * @param prompt String displayed on the terminal to prompt the user for a password
 *               or an encryption key
 * @param fd     File descriptor
 *
 * @return NULL if a problem occured or the user killed the terminal (Ctrl-C)\n
 *         otherwise the password - empty password is accepted.
 */
char*
getpasswd(const char *prompt, int fd)
{
    char *ptr;
    
#ifndef WIN32
    sigset_t        sig, old_sig;
    struct termios  ts, old_ts;
    FILE           *fp;
    int             use_ext_fd = 0;

    if (fd >= 0)
    {
        fp = fdopen(fd, "r");
        if (fp == NULL)
        {
            log_msg(LOG_VERBOSITY_ERROR, "getpasswd() - "
                "Unable to create a stream from file descriptor : %s",
                strerror(errno));
            exit(EXIT_FAILURE);
        }
        use_ext_fd = 1;
    }

    if (use_ext_fd == 0)
    {
        if((fp = fopen(ctermid(NULL), "r+")) == NULL)
            return(NULL);

        setbuf(fp, NULL);

        /* Setup blocks for SIGINT and SIGTSTP and save the original signal
        * mask.
        */
        sigemptyset(&sig);
        sigaddset(&sig, SIGINT);
        sigaddset(&sig, SIGTSTP);
        sigprocmask(SIG_BLOCK, &sig, &old_sig);

        /*
        * Save current tty state for later restoration after we :
        *   - disable echo of characters to the tty
        *   - disable signal generation
        *   - disable cannonical mode (input read line by line mode)
        */
        tcgetattr(fileno(fp), &ts);
        old_ts = ts;
        ts.c_lflag &= ~(ECHO | ICANON | ISIG);
        tcsetattr(fileno(fp), TCSAFLUSH, &ts);

        fputs(prompt, fp);
    }
#else
    _cputs(prompt);
#endif

    /* Read the password */
    ptr = read_passwd_from_stream(fp);

#ifndef WIN32

    if (use_ext_fd == 0)
    {
        /* we can go ahead and echo out a newline.
        */
        putc(PW_LF_CHAR, fp);

        /* Restore our tty state and signal handlers.
        */
        tcsetattr(fileno(fp), TCSAFLUSH, &old_ts);
        sigprocmask(SIG_BLOCK, &old_sig, NULL);

        fclose(fp);
    }
#else
    /* In Windows, it would be a CR-LF
     */
    _putch(PW_CR_CHAR);
    _putch(PW_LF_CHAR);
#endif

    return (ptr);
}

/* Function for accepting password input from a file
*/
void
get_key_file(char *key, int *key_len, const char *key_file,
    fko_ctx_t ctx, const fko_cli_options_t *options)
{
    FILE           *pwfile_ptr;
    unsigned int    numLines = 0, i = 0, found_dst;

    char            conf_line_buf[MAX_LINE_LEN] = {0};
    char            tmp_char_buf[MAX_LINE_LEN]  = {0};
    char           *lptr;

    memset(key, 0x00, MAX_KEY_LEN+1);
    memset(conf_line_buf, 0x00, MAX_LINE_LEN);
    memset(tmp_char_buf, 0x00, MAX_LINE_LEN);

    if ((pwfile_ptr = fopen(key_file, "r")) == NULL)
    {
        log_msg(LOG_VERBOSITY_ERROR, "Could not open config file: %s", key_file);
        fko_destroy(ctx);
        ctx = NULL;
        exit(EXIT_FAILURE);
    }

    while ((fgets(conf_line_buf, MAX_LINE_LEN, pwfile_ptr)) != NULL)
    {
        numLines++;
        conf_line_buf[MAX_LINE_LEN-1] = '\0';
        lptr = conf_line_buf;

        memset(tmp_char_buf, 0x0, MAX_LINE_LEN);

        while (*lptr == ' ' || *lptr == '\t' || *lptr == '=')
            lptr++;

        /* Get past comments and empty lines.
        */
        if (*lptr == '#' || *lptr == '\n' || *lptr == '\r' || *lptr == '\0' || *lptr == ';')
            continue;

        /* Look for a line like "<SPA destination IP>: <password>" - this allows
        * multiple keys to be placed within the same file, and the client will
        * reference the matching one for the SPA server we are contacting
        */
        found_dst = 1;
        for (i=0; i < strlen(options->spa_server_str); i++)
            if (*lptr++ != options->spa_server_str[i])
                found_dst = 0;

        if (! found_dst)
            continue;

        if (*lptr == ':')
            lptr++;
        else
            continue;

        /* Skip whitespace until we get to the password
        */
        while (*lptr == ' ' || *lptr == '\t' || *lptr == '=')
            lptr++;

        i = 0;
        while (*lptr != '\0' && *lptr != '\n') {
            key[i] = *lptr;
            lptr++;
            i++;
        }
        key[i] = '\0';
    }

    fclose(pwfile_ptr);

    if (key[0] == '\0') {
        log_msg(LOG_VERBOSITY_ERROR, "Could not get key for IP: %s from: %s",
            options->spa_server_str, key_file);
        fko_destroy(ctx);
        ctx = NULL;
        exit(EXIT_FAILURE);
    }

    *key_len = strlen(key);

    return;
}

/***EOF***/
