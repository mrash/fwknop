/**
 * @file    utils.c
 *
 * @author  Damien S. Stuart
 *
 * @brief   General/Generic functions for the fwknop server.
 *
 * Copyright 2010-2013 Damien Stuart (dstuart@dstuart.org)
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
 */

#include "fwknopd_common.h"
#include "utils.h"
#include "log_msg.h"
#include <stdarg.h>

/* Generic hex dump function.
*/
void
hex_dump(const unsigned char *data, const int size)
{
    int ln, i, j = 0;
    char ascii_str[17] = {0};

    for(i=0; i<size; i++)
    {
        if((i % 16) == 0)
        {
            printf(" %s\n  0x%.4x:  ", ascii_str, i);
            memset(ascii_str, 0x0, 17);
            j = 0;
        }

        printf("%.2x ", data[i]);

        ascii_str[j++] = (data[i] < 0x20 || data[i] > 0x7e) ? '.' : data[i];

        if(j == 8)
            printf(" ");
    }

    /* Remainder...
    */
    ln = strlen(ascii_str);
    if(ln > 0)
    {
        for(i=0; i < 16-ln; i++)
            printf("   ");
        if(ln < 8)
            printf(" ");

        printf(" %s\n\n", ascii_str);
    }
}

/* Basic directory checks (stat() and whether the path is actually
 * a directory).
*/
int
is_valid_dir(const char *path)
{
#if HAVE_STAT
    struct stat st;

    /* If we are unable to stat the given dir, then return with error.
    */
    if(stat(path, &st) != 0)
    {
        log_msg(LOG_ERR, "[-] unable to stat() directory: %s: %s",
            path, strerror(errno));
        return(0);
    }

    if(!S_ISDIR(st.st_mode))
        return(0);
#endif /* HAVE_STAT */

    return(1);
}

int
verify_file_perms_ownership(const char *file)
{
    int res = 1;

#if HAVE_STAT
    struct stat st;

    /* Every file that fwknopd deals with should be owned
     * by the user and permissions set to 600 (user read/write)
    */
    if((stat(file, &st)) == 0)
    {
        /* Make sure it is a regular file
        */
        if(S_ISREG(st.st_mode) != 1 && S_ISLNK(st.st_mode) != 1)
        {
            log_msg(LOG_WARNING,
                "[-] file: %s is not a regular file or symbolic link.",
                file
            );
            /* when we start in enforcing this instead of just warning
             * the user
            res = 0;
            */
        }

        if((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != (S_IRUSR|S_IWUSR))
        {
            log_msg(LOG_WARNING,
                "[-] file: %s permissions should only be user read/write (0600, -rw-------)",
                file
            );
            /* when we start in enforcing this instead of just warning
             * the user
            res = 0;
            */
        }

        if(st.st_uid != getuid())
        {
            log_msg(LOG_WARNING, "[-] file: %s not owned by current effective user id",
                file);
            /* when we start in enforcing this instead of just warning
             * the user
            res = 0;
            */
        }
    }
    else
    {
        /* if the path doesn't exist, just return, but otherwise something
         * went wrong
        */
        if(errno != ENOENT)
        {
            log_msg(LOG_ERR, "[-] stat() against file: %s returned: %s",
                file, strerror(errno));
            res = 0;
        }
    }

#endif

    return res;
}

/* Determine if a buffer contains only characters from the base64
 * encoding set
*/
int
is_base64(const unsigned char *buf, const unsigned short int len)
{
    unsigned short int  i;
    int                 rv = 1;

    for(i=0; i<len; i++)
    {
        if(!(isalnum(buf[i]) || buf[i] == '/' || buf[i] == '+' || buf[i] == '='))
        {
            rv = 0;
            break;
        }
    }

    return rv;
}

/***EOF***/
