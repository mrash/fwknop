/**
 * \file server/nfq_capture.h
 *
 * \brief Header file for nfq_capture.c
 */

/*
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
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
#ifndef NFQ_CAPTURE_H
#define NFQ_CAPTURE_H

/* How many consecutive capture errors will we allow
 * before giving up and bailing out.
*/
#define MAX_NFQ_ERRORS_BEFORE_BAIL 100

/* Prototypes
*/
int nfq_capture(fko_srv_options_t *opts);

#endif  /* NFQ_CAPTURE_H */
