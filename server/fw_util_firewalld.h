/*
 *****************************************************************************
 *
 * File:    fw_util_firewalld.h
 *
 * Purpose: Header file for fw_util_firewalld.c.
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
#ifndef FW_UTIL_FIREWALLD_H
#define FW_UTIL_FIREWALLD_H

#define SNAT_TARGET_BUFSIZE         64

#if HAVE_EXECVPE
  #define SH_REDIR "" /* the shell is not used when execvpe() is available */
#else
  #define SH_REDIR " 2>&1"
#endif

/* firewalld command args
*/
#define FIREWD_CHK_RULE_ARGS       "-C %s %s" /* the other macros add SH_REDIR if necessary */
#define FIREWD_RULE_ARGS           "-t %s -p %i -s %s -d %s --dport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s" SH_REDIR
#define FIREWD_OUT_RULE_ARGS       "-t %s -p %i -d %s -s %s --sport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s" SH_REDIR
#define FIREWD_FWD_RULE_ARGS       "-t %s -p %i -s %s -d %s --dport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s" SH_REDIR
#define FIREWD_FWD_ALL_RULE_ARGS   "-t %s -s %s -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s" SH_REDIR
#define FIREWD_DNAT_RULE_ARGS      "-t %s -p %i -s %s -d %s --dport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s --to-destination %s:%i" SH_REDIR
#define FIREWD_DNAT_ALL_RULE_ARGS  "-t %s -s %s -d %s -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s --to-destination %s" SH_REDIR
#define FIREWD_SNAT_RULE_ARGS      "-t %s -p %i -d %s --dport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s %s" SH_REDIR
#define FIREWD_SNAT_ALL_RULE_ARGS     "-t %s -s %s -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s %s" SH_REDIR
#define FIREWD_TMP_COMMENT_ARGS    "-t %s -I %s %i -s " DUMMY_IP " -m comment --comment " TMP_COMMENT " -j %s" SH_REDIR
#define FIREWD_TMP_CHK_RULE_ARGS   "-t %s -I %s %i -s " DUMMY_IP " -p udp -j %s" SH_REDIR
#define FIREWD_TMP_VERIFY_CHK_ARGS "-t %s -C %s -s " DUMMY_IP " -p udp -j %s" SH_REDIR
#define FIREWD_DEL_RULE_ARGS       "-t %s -D %s %i" SH_REDIR
#define FIREWD_NEW_CHAIN_ARGS      "-t %s -N %s" SH_REDIR
#define FIREWD_FLUSH_CHAIN_ARGS    "-t %s -F %s" SH_REDIR
#define FIREWD_CHAIN_EXISTS_ARGS   "-t %s -L %s -n" SH_REDIR
#define FIREWD_DEL_CHAIN_ARGS      "-t %s -X %s" SH_REDIR
#define FIREWD_CHK_JUMP_RULE_ARGS  "-t %s -j %s" SH_REDIR
#define FIREWD_ADD_JUMP_RULE_ARGS  "-t %s -I %s %i -j %s" SH_REDIR
#define FIREWD_DEL_JUMP_RULE_ARGS  "-t %s -D %s -j %s" SH_REDIR  /* let firewalld work out the rule number */
#define FIREWD_LIST_RULES_ARGS     "-t %s -L %s --line-numbers -n" SH_REDIR
#define FIREWD_LIST_ALL_RULES_ARGS "-t %s -v -n -L --line-numbers" SH_REDIR
#define FIREWD_ANY_IP              "0.0.0.0/0"

int validate_firewd_chain_conf(const char * const chain_str);

#endif /* FW_UTIL_FIREWALLD_H */

/***EOF***/
