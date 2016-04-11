/**
 * \file server/fwknopd.h
 *
 * \brief Header file for fwknopd server program.
 */

/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
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
 *
 *****************************************************************************
*/
#ifndef FWKNOPD_H
#define FWKNOPD_H

#include "fwknopd_common.h"

#include <sys/file.h>
#include <sys/fcntl.h>

#if HAVE_LOCALE_H
  #include <locale.h>
#endif

/* If the flock flags are not defined at this point, we take the liberty
 * of defining them here.
*/
#ifndef LOCK_SH
  /**
   * \def LOCK_SH
   *
   * \brief Shared file lock
   */
  #define   LOCK_SH        0x01
#endif
#ifndef LOCK_EX
  /**
   * \def LOCK_EX
   *
   * \brief Exclusive file lock
   */
  #define   LOCK_EX        0x02
#endif
#ifndef LOCK_NB
  /**
   * \def LOCK_NB
   *
   * \brief Do not block when locking
   */
  #define   LOCK_NB        0x04
#endif
#ifndef LOCK_UN
  /**
   * \def LOCK_UN
   *
   * \brief Unlock file
   */
  #define   LOCK_UN        0x08
#endif

  /**
   * \def PID_BUFLEN
   *
   * \brief Buffer length for PID
   */
#define PID_BUFLEN 7

#endif  /* FWKNOPD_H */
