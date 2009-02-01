/* $Id$
 *****************************************************************************
 *
 * File:    fko_common.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Common header for libfko source files.
 *
 * Copyright (C) 2008 Damien Stuart (dstuart@dstuart.org)
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
#ifndef FKO_COMMON_H
#define FKO_COMMON_H 1

#if HAVE_CONFIG_H
  #include "config.h"
#endif

#include <stdio.h>
#include <sys/types.h>

#if STDC_HEADERS
  #include <stdlib.h>
  #include <string.h>
#elif HAVE_STRINGS_H
  #include <strings.h>
#endif /*STDC_HEADERS*/

#if HAVE_UNISTD_H
  #include <unistd.h>
#endif

#if HAVE_CTYPE_H
  #include <ctype.h> /* Using this if isdigit() */
#else
  /* Fall-back does not account for locale */
  #define isdigit(c) (c >= 48 && c <= 57)
#endif

/* Convenient macros for wrapping sections in 'extern "C" {' constructs.
*/
#ifdef __cplusplus
  #define BEGIN_C_DECLS extern "C" {
  #define END_C_DECLS   }
#else /* !__cplusplus */
  #define BEGIN_C_DECLS
  #define END_C_DECLS
#endif /* __cplusplus */

/* Pull in gpgme.h if we have it.
*/
#if HAVE_LIBGPGME
  #include <gpgme.h>
#endif

#include "fko_types.h"
#include "fko_util.h"
#include "fko_limits.h"
#include "fko_state.h"
#include "fko_context.h"

/* Try to cover for those that do not have bzero.
*/
#if !HAVE_BZERO && HAVE_MEMSET
# define bzero(buf, bytes)      ((void) memset (buf, 0, bytes))
#endif

#endif /* FKO_COMMON_H */

/***EOF***/
