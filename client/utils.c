/*
 *****************************************************************************
 *
 * File:    utils.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: General/Generic functions for the fwknop client.
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
#include "fwknop_common.h"
#include "utils.h"

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

        printf(" %s\n\n", ascii_str);
    }
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

int
set_file_perms(const char *file)
{
    int res = 0;

    res = chmod(file, S_IRUSR | S_IWUSR);

    if(res != 0)
    {
        fprintf(stderr,
            "[-] unable to chmod file %s to user read/write (0600, -rw-------): %s\n",
            file,
            strerror(errno)
        );
    }
    return res;
}

int
verify_file_perms_ownership(const char *file)
{
#if HAVE_STAT
    struct stat st;

    /* Every file that the fwknop client deals with should be owned
     * by the user and permissions set to 600 (user read/write)
    */
    if((stat(file, &st)) != 0)
    {
        fprintf(stderr, "[-] unable to run stat() against file: %s: %s\n",
            file, strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Make sure it is a regular file or symbolic link
    */
    if(S_ISREG(st.st_mode) != 1 && S_ISLNK(st.st_mode) != 1)
    {
        fprintf(stderr,
            "[-] file: %s is not a regular file or symbolic link.\n",
            file
        );
        return 0;
    }

    if((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != (S_IRUSR|S_IWUSR))
    {
        fprintf(stderr,
            "[-] file: %s permissions should only be user read/write (0600, -rw-------)\n",
            file
        );
        return 0;
    }

    if(st.st_uid != getuid())
    {
        fprintf(stderr, "[-] file: %s not owned by current effective user id.\n",
            file);
        return 0;
    }
#endif

    return 1;
}

/***EOF***/
