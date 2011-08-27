/*
 *****************************************************************************
 *
 * File:    fw_util_pf.h
 *
 * Author:  Damien Stuart (dstuart@dstuart.org), Michael Rash
 *                                                  (mbr@cipherdyne.org)
 *
 * Purpose: Header file for fw_util_pf.c.
 *
 * Copyright 2010 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU Public License):
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

/* pf command args
*/
#define PF_LIST_RULES_ARGS "-a %s -s rules"
#define PF_LIST_ALL_RULES_ARGS "-s rules"  /* to check for fwknop anchor */

#endif /* FW_UTIL_PF_H */

/***EOF***/
