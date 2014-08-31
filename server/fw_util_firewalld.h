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

/* firewalld command args
*/
#define FIREWD_CHK_RULE_ARGS       "--direct --passthrough -C %s %s"  /* 2>&1 is always added in the second %s */
#define FIREWD_RULE_ARGS           "--direct --passthrough -t %s -p %i -s %s --dport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s 2>&1"
#define FIREWD_OUT_RULE_ARGS       "--direct --passthrough -t %s -p %i -d %s --sport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s 2>&1"
#define FIREWD_FWD_RULE_ARGS       "--direct --passthrough -t %s -p %i -s %s -d %s --dport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s 2>&1"
#define FIREWD_DNAT_RULE_ARGS      "--direct --passthrough -t %s -p %i -s %s --dport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s --to-destination %s:%i 2>&1"
#define FIREWD_SNAT_RULE_ARGS      "--direct --passthrough -t %s -p %i -d %s --dport %i -m comment --comment " EXPIRE_COMMENT_PREFIX "%u -j %s %s 2>&1"
#define FIREWD_TMP_COMMENT_ARGS    "--direct --passthrough -t %s -I %s %i -s 127.0.0.2 -m comment --comment " TMP_COMMENT " -j %s 2>&1"
#define FIREWD_TMP_CHK_RULE_ARGS   "--direct --passthrough -t %s -I %s %i -s 127.0.0.2 -p udp -j %s 2>&1"
#define FIREWD_TMP_VERIFY_CHK_ARGS "--direct --passthrough -t %s -C %s -s 127.0.0.2 -p udp -j %s 2>&1"
#define FIREWD_DEL_RULE_ARGS       "--direct --passthrough -t %s -D %s %i 2>&1"
#define FIREWD_NEW_CHAIN_ARGS      "--direct --passthrough -t %s -N %s 2>&1"
#define FIREWD_FLUSH_CHAIN_ARGS    "--direct --passthrough -t %s -F %s 2>&1"
#define FIREWD_CHAIN_EXISTS_ARGS   "--direct --passthrough -t %s -L %s -n 2>&1"
#define FIREWD_DEL_CHAIN_ARGS      "--direct --passthrough -t %s -X %s 2>&1"
#define FIREWD_CHK_JUMP_RULE_ARGS  "--direct --passthrough -t %s -j %s 2>&1"
#define FIREWD_ADD_JUMP_RULE_ARGS  "--direct --passthrough -t %s -I %s %i -j %s 2>&1"
#define FIREWD_DEL_JUMP_RULE_ARGS  "--direct --passthrough -t %s -D %s -j %s 2>&1"  /* let firewalld work out the rule number */
#define FIREWD_LIST_RULES_ARGS     "--direct --passthrough -t %s -L %s --line-numbers -n 2>&1"
#define FIREWD_LIST_ALL_RULES_ARGS "--direct --passthrough -t %s -v -n -L --line-numbers 2>&1"

int validate_firewd_chain_conf(const char * const chain_str);

#endif /* FW_UTIL_FIREWALLD_H */

/***EOF***/
