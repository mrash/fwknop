/**
 ******************************************************************************
 *
 * @file    config_init.h
 *
 * @author  Damien Stuart
 *
 * @brief   Header file for fwknop config_init.
 *
 * Copyright 2009-2010 Damien Stuart (dstuart@dstuart.org)
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
 ******************************************************************************
*/
#ifndef CONFIG_INIT_H
#define CONFIG_INIT_H

#include <getopt.h>
#include <sys/stat.h>

/* String compare macro.
*/
#define CONF_VAR_IS(n, v) (strcmp(n, v) == 0)

/* Function Prototypes
*/
void config_init(fko_cli_options_t *options, int argc, char **argv);
void usage(void);

#endif /* CONFIG_INIT_H */

/***EOF***/
