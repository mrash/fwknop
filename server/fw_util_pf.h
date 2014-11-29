/*
 *****************************************************************************
 *
 * File:    fw_util_pf.h
 *
 * Purpose: Header file for fw_util_pf.c.
 *
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
#ifndef FW_UTIL_PF_H
#define FW_UTIL_PF_H

#define MAX_PF_ANCHOR_SEARCH_LEN    (MAX_PF_ANCHOR_LEN+11)   /* room for 'anchor "' string */
#define MAX_PF_NEW_RULE_LEN         140

#if HAVE_EXECVPE
  #define SH_REDIR "" /* the shell is not used when execvpe() is available */
#else
  #define SH_REDIR " 2>&1"
#endif

/* pf command args
*/
#define PF_ADD_RULE_ARGS              "pass in quick proto %u from %s to %s port %u keep state label " EXPIRE_COMMENT_PREFIX "%u"
#define PF_WRITE_ANCHOR_RULES_ARGS    "-a %s -f -"
#if HAVE_EXECVPE
  #define PF_LIST_ANCHOR_RULES_ARGS   "-a %s -s rules"
#else
  #define PF_LIST_ANCHOR_RULES_ARGS   "-a %s -s rules 2> /dev/null"
#endif
#define PF_ANCHOR_CHECK_ARGS          "-s Anchor" SH_REDIR  /* to check for fwknop anchor */
#define PF_DEL_ALL_ANCHOR_RULES       "-a %s -F all" SH_REDIR
#define PF_ANY_IP                     "any"

#endif /* FW_UTIL_PF_H */

/***EOF***/
