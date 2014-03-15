/*
 *****************************************************************************
 *
 * File:    fw_util_ipfw.h
 *
 * Purpose: Header file for fw_util_ipfw.c.
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
#ifndef FW_UTIL_IPFW_H
#define FW_UTIL_IPFW_H

enum {
    RULE_FREE = 0,
    RULE_ACTIVE,
    RULE_EXPIRED,
    RULE_TMP_MARKED
};

/* ipfw command args
*/
#define IPFW_ADD_RULE_ARGS           "add %u set %u pass %u from %s to me dst-port %u setup keep-state // " EXPIRE_COMMENT_PREFIX "%u"
#define IPFW_ADD_CHECK_STATE_ARGS    "add %u set %u check-state"
#define IPFW_MOVE_RULE_ARGS          "set move rule %u to %u"
#define IPFW_MOVE_SET_ARGS           "set move %u to %u"
#define IPFW_DISABLE_SET_ARGS        "set disable %u"
#define IPFW_LIST_ALL_RULES_ARGS     "list"
#define IPFW_DEL_RULE_SET_ARGS       "delete set %u"

#ifdef __APPLE__
    #define IPFW_DEL_RULE_ARGS           "delete %u" //--DSS diff args
    #define IPFW_LIST_RULES_ARGS         "-d -S -T list | grep 'set %u'"
    #define IPFW_LIST_SET_RULES_ARGS     "-S list | grep 'set %u'"
    #define IPFW_LIST_EXP_SET_RULES_ARGS "-S list | grep 'set %u'"
    #define IPFW_LIST_SET_DYN_RULES_ARGS "-d list | grep 'set %u'"
#else
  #define IPFW_DEL_RULE_ARGS           "set %u delete %u"
  #define IPFW_LIST_RULES_ARGS         "-d -S -T set %u list"
  #define IPFW_LIST_SET_RULES_ARGS     "set %u list"
  #define IPFW_LIST_EXP_SET_RULES_ARGS "-S set %u list"
  #define IPFW_LIST_SET_DYN_RULES_ARGS "-d set %u list"
#endif

void ipfw_purge_expired_rules(const fko_srv_options_t *opts);

#endif /* FW_UTIL_IPFW_H */

/***EOF***/
