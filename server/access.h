/**
 * \file server/access.h
 *
 * \brief Header file for fwknopd access.c.
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
#ifndef ACCESS_H
#define ACCESS_H

#define PROTO_TCP   6
#define PROTO_UDP   17

/**
 * \def ACCESS_BUF_LEN
 *
 * \brief Allow strings as large as 123.123.123.123/255.255.255.255
 */
#define ACCESS_BUF_LEN  33

/**
 * \def MAX_DEPTH
 *
 * \brief Recursion depth
 *
 * We won't recurse more than 3 deep.  Access.conf can include a file
 * that includes a file, but that's the limit.
*/
#define MAX_DEPTH 3

/* Function Prototypes
*/

/**
 * \brief Loads an access.conf file
 *
 * Also handles includes by calling itself recursively, only recurses 3 levels deep
 *
 * \param opts Pointer to the fko_srv_options_t struct to populate
 * \param access_filename Pointer to the filename to load
 * \param depth Pointer to the current depth.  This starts at 0 and is incremented for each recursion
 *
 * \return Returns an error status, or EXIT_SUCCESS
 *
 */
int parse_access_file(fko_srv_options_t *opts, char *access_filename, int *depth);

/**
 * \brief Loads access.conf files in a folder
 *
 * This function does not recurse into subfolders, but calls parse_access_file
 * for each contained file.  This function does not increment the depth int.
 *
 * \param opts Pointer to the fko_srv_options_t struct to populate
 * \param access_folder Pointer to the folder name to process
 * \param depth Pointer to the current depth.
 *
 * \return Returns an error status, or EXIT_SUCCESS
 *
 */
int parse_access_folder(fko_srv_options_t *opts, char *access_folder, int *depth);

/**
 * \brief Basic validation for a access stanzas
 *
 * This is a basic check to ensure there is at least one access stanza
 * with the "source" variable populated, and this function is only
 * called after all access.conf files are processed. This allows
 * %include_folder processing to proceed against directories that
 * have files that are not access.conf files. Additional stronger
 * validations are done in acc_data_is_valid(), but this function
 * is only called when a "SOURCE" variable has been parsed out of
 * the file.
 *
 * \param acc Pointer to the acc_stanza_t struct that holds the access stanza
 *
 * \return Returns an error status, or EXIT_SUCCESS
 *
 */
int valid_access_stanzas(acc_stanza_t *acc);

/**
 * \brief Compares address lists
 *
 * This function walks a linked list looking for a matching IP address.
 * Primarily intended to find a matching access stanza for an
 * incoming SPA packet.
 *
 * \param source_list pointer to linked list to walk
 * \param ip Address to compare
 *
 * \return Returns true on a match
 *
 */
int compare_addr_list(acc_int_list_t *source_list, const uint32_t ip);

/**
 * \brief Check for a proto-port string
 *
 * Take a proto/port string (or mulitple comma-separated strings) and check
 * them against the list for the given access stanza.
 *
 * \param acc Pointer to the acc_stanza_t struct that holds the access stanzas
 * \param port_str pointer to the port string to look for
 *
 * \return Returns true if allowed
 *
 */
int acc_check_port_access(acc_stanza_t *acc, char *port_str);

/**
 * \brief Dumps the current configuration to stdout
 *
 * \param opts pointer to the server options struct
 *
 */
void dump_access_list(const fko_srv_options_t *opts);

/**
 * \brief Expands a proto/port string to a list of access proto-port struct.
 *
 * This takes a single string of comma separated proto/port values and separates
 * them into a linked list
 *
 * \param plist Double pointer to the acc_port_list_t to hold the proto/ports
 * \param plist_str Pointer to the list of proto/port values
 *
 * \return Returns true if successful
 *
 */
int expand_acc_port_list(acc_port_list_t **plist, char *plist_str);

/**
 * \brief Sets do_acc_stanza_init to true, which enables free_acc_stanzas()
 *
 */
void enable_acc_stanzas_init(void);

/**
 * \brief Free memory for all access stanzas
 *
 * \param opts Pointer to fko_srv_options_t that contains the access stanza chain to free
 *
 */
void free_acc_stanzas(fko_srv_options_t *opts);

/**
 * \brief free a port list
 *
 * \param plist Pointer to acc_port_list_t to free
 *
 */
void free_acc_port_list(acc_port_list_t *plist);

#ifdef HAVE_C_UNIT_TESTS
int register_ts_access(void);
#endif

#endif /* ACCESS_H */

/***EOF***/
