/*
 *****************************************************************************
 *
 * File:    fwknop.h
 *
 * Author:  Michael Rash (mbr@cipherdyne.org)
 *
 * Purpose: Header file for fwknop client test program.
 *
 * Copyright (C) 2009 Michael Rash (mbr@cipherdyne.org)
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
 *
 * $Id$
 *
*/

#ifndef __FWKNOP_H__
#define __FWKNOP_H__

/* includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "fko.h"

/* defines */
#define FWKNOP_VERSION "2.0.0-pre1"

/* for command argument processing */
typedef struct {
    unsigned char src_addr;  /* -s */
    int quiet;
    int verbose;
} cmdl_opts;

#endif  /* __FWKNOP_H__ */
