/**
 *
 * @file    cmd_cycle.h
 *
 * @brief: Function prototypes for managing command cycles as defined via
 *          access.conf stanzas (CMD_CYCLE_OPEN and CMD_CYCLE_CLOSE).
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
*/

#ifndef CMD_CYCLE_H
#define CMD_CYCLE_H

#define CMD_CYCLE_BUFSIZE 256

int cmd_cycle_open(fko_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, const int stanza_num, int *res);
void cmd_cycle_close(fko_srv_options_t *opts);
void free_cmd_cycle_list(fko_srv_options_t *opts);

#endif  /* CMD_CYCLE_H */
