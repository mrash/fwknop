/**
 * \file server/config_init.h
 *
 * \brief Header file for fwknopd config_init.
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
 ******************************************************************************
*/
#ifndef CONFIG_INIT_H
#define CONFIG_INIT_H

#include <getopt.h>
#include <sys/stat.h>

/* Function Prototypes
*/

/**
 * \brief Initializes the program config
 *
 * This function sets default config options and loads the config information from the command line.
 *
 * \param opts fko_srv_options_t struct that is populated with configuration
 * \param argc argument count, the number of command line arguments
 * \param argv argument vector, an array of the command line arguments
 *
 */
void config_init(fko_srv_options_t *opts, int argc, char **argv);

/**
 * \brief dumps current config to std out
 *
 * \param opts Pointer to the program options struct to dump
 *
 */
void dump_config(const fko_srv_options_t *opts);

/**
 * \brief Frees config memory
 *
 * \param opts fko_srv_options_t struct that is to be freed
 *
 */
void free_configs(fko_srv_options_t *opts);

/**
 * \brief Prints program help message to stdout
 *
 */
void usage(void);

#endif /* CONFIG_INIT_H */

/***EOF***/
