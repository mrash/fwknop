/*
 *****************************************************************************
 *
 * File:    replay_dbm.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Provides the functions to check for possible replay attacks
 *          by using a dbm (ndbm or gdbm in ndbm compatibility mode) file
 *          to store a digest of previously received SPA packets.
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
#include "replay_dbm.h"
#include "log_msg.h"

#if HAVE_LIBGDBM
  /* NOTE: We are using gdbm in ndbm compatibility mode so we grab its
   * version of ndbm.h
  */
//  #include <gdbm.h>
  #include <gdbm/ndbm.h>
#elif HAVE_LIBNDBM
  #include <ndbm.h>
#else
  #error "No DBM header file found. WTF?"
#endif

#if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
#endif
#include <arpa/inet.h>

#include <fcntl.h>

#define MAX_DIGEST_SIZE 64

/* Check for the existence of the replay dbm file, and create it if it does
 * not exist.  Returns the number of db entries or -1 on error.
*/
int
replay_db_init(fko_srv_options_t *opts)
{
    DBM    *rpdb;
    datum   db_ent;

    int     db_count = 0;

    rpdb = dbm_open(opts->config[CONF_DIGEST_FILE], O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);

    if(!rpdb)
    {
        perror("Unable to create digest cache file: ");
        return(-1);
    }

    for (db_ent = dbm_firstkey(rpdb); db_ent.dptr != NULL; db_ent = dbm_nextkey(rpdb))
        db_count++;

    dbm_close(rpdb);

    return(db_count);
}

/* Take an fko context, pull the digest and use it as the key to check the
 * replay db (digest cache). Returns 1 if there was a match (a replay),
 * 0 for no match, and -1 on error.
*/
int
replay_check(fko_srv_options_t *opts, fko_ctx_t ctx)
{
    DBM    *rpdb;
    datum   db_key, db_ent;

    char    ipaddr[INET_ADDRSTRLEN+1] = {0};

    char   *digest;
    int     digest_len, res;

    res = fko_get_spa_digest(ctx, &digest);
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING|LOG_STDERR, "Error getting digest from SPA data: %s",
            fko_errstr(res));

        return(-1);
    }

    digest_len = strlen(digest);

    db_key.dptr = digest;
    db_key.dsize = digest_len;

    /* Check the db for the key
    */
    rpdb = dbm_open(opts->config[CONF_DIGEST_FILE], O_RDWR, 0);

    if(!rpdb)
    {
        log_msg(LOG_WARNING|LOG_STDERR, "Error opening digest_cache: %s",
            strerror(errno));

        return(-1);
    }

    db_ent = dbm_fetch(rpdb, db_key);

    /* If the datum is not null, we have a match.  Otherwise, we add
    * this entry to the cache.
    */
    if(db_ent.dptr != NULL)
    {
        /* Convert the IP to a human readable form
        */
        inet_ntop(AF_INET, &(opts->spa_pkt.packet_src_ip),
            ipaddr, INET_ADDRSTRLEN);
        
        log_msg(LOG_WARNING|LOG_STDERR,
            "Replay detected from source IP: %s", ipaddr);

        res = 1;
    } else {
        db_ent.dptr = (char*)&(opts->spa_pkt.packet_src_ip);
        db_ent.dsize = sizeof(opts->spa_pkt.packet_src_ip);

        if(dbm_store(rpdb, db_key, db_ent, DBM_INSERT) != 0)
        {
            log_msg(LOG_WARNING|LOG_STDERR, "Error adding entry digest_cache: %s",
                strerror(errno));

            res = -1;
        }

        res = 0;
    } 

    dbm_close(rpdb);

    return(res);
}

/***EOF***/
