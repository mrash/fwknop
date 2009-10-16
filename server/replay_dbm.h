/*
 *****************************************************************************
 *
 * File:    replay_dbm.h
 *
 * Author:  Damien Stuart (dstuart@dstuart.org)
 *
 * Purpose: Header file for fwknopd replay_dbm.c functions.
 *
 * Copyright (C) 2009 Damien Stuart (dstuart@dstuart.org)
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
#ifndef REPLAY_DBM_H
#define REPLAY_DBM_H

#include "fwknopd_common.h"
#include "fko.h"

/* Prototypes
*/
int replay_db_init(fko_srv_options_t *opts);
int replay_check(fko_srv_options_t *opts, fko_ctx_t ctx);

#endif  /* REPLAY_DBM_H */
