/* $Id$
 *****************************************************************************
 *
 * File:    fko_util.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Header for utility functions used by libfko
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
#ifndef FKO_UTIL_H
#define FKO_UTIL_H 1

#include "fko_common.h"

/* Function prototypes
*/
size_t strlcat(char *dst, const char *src, size_t siz);
size_t strlcpy(char *dst, const char *src, size_t siz);

#endif /* FKO_UTIL_H */

/***EOF***/
