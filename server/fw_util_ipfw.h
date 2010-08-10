/* $Id$
 *****************************************************************************
 *
 * File:    fw_util_ipfw.h
 *
 * Author:  Damien Stuart (dstuart@dstuart.org)
 *
 * Purpose: Header file for fw_util_ipfw.c.
 *
 * Copyright (C) 2010 Damien Stuart (dstuart@dstuart.org)
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
#ifndef FW_UTIL_IPFW_H
#define FW_UTIL_IPFW_H

#define SNAT_TARGET_BUFSIZE         64

/* ipfw command args   (gotta flesh these out)         
*/
#define IPFW_ADD_RULE_ARGS ""
#define IPFW_ADD_OUT_RULE_ARGS ""
#define IPFW_ADD_FWD_RULE_ARGS ""
#define IPFW_ADD_DNAT_RULE_ARGS ""
#define IPFW_ADD_SNAT_RULE_ARGS ""
#define IPFW_DEL_RULE_ARGS ""
#define IPFW_LIST_RULES_ARGS ""

#endif /* FW_UTIL_IPFW_H */

/***EOF***/
