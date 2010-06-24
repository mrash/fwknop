/* $Id$
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

#include <time.h>

#if HAVE_LIBGDBM
  #include <gdbm.h>

  #define MY_DBM_FETCH(d, k)        gdbm_fetch(d, k)
  #define MY_DBM_STORE(d, k, v, m)  gdbm_store(d, k, v, m)
  #define MY_DBM_STRERROR(x)        gdbm_strerror(x)
  #define MY_DBM_CLOSE(d)           gdbm_close(d)

#elif HAVE_LIBNDBM
  #include <ndbm.h>

  #define MY_DBM_FETCH(d, k)        dbm_fetch(d, k)
  #define MY_DBM_STORE(d, k, v, m)  dbm_store(d, k, v, m)
  #define MY_DBM_STRERROR(x)        strerror(x)
  #define MY_DBM_CLOSE(d)           dbm_close(d)
#else
  #error "No GDBM or NDBM header file found. WTF?"
#endif

#if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
#endif
#include <arpa/inet.h>

#include <fcntl.h>

#define MAX_DIGEST_SIZE 64

/* Rotate the digest file by simply renaming it.
*/
static void
rotate_digest_cache_file(fko_srv_options_t *opts)
{
    int         res;
    char       *new_file = NULL;

    log_msg(LOG_INFO, "Rotating digest cache file.");

    new_file = malloc(strlen(opts->config[CONF_DIGEST_FILE])+5);

    if(new_file == NULL)
    {
        log_msg(LOG_ERR, "rotate_digest_cache_file: Memory allocation error.");
        exit(EXIT_FAILURE);
    }

    /* The new filename is just the original with a trailing '-old'.
    */
    strcpy(new_file, opts->config[CONF_DIGEST_FILE]);
    strcat(new_file, "-old");

    res = rename(opts->config[CONF_DIGEST_FILE], new_file);

    if(res < 0)
        log_msg(LOG_ERR, "Unable to rename digest file: %s to %s: %s",
            opts->config[CONF_DIGEST_FILE], new_file, strerror(errno)
        );
}

/* Check for the existence of the replay dbm file, and create it if it does
 * not exist.  Returns the number of db entries or -1 on error.
*/
int
replay_db_init(fko_srv_options_t *opts)
{
#ifdef HAVE_LIBGDBM
    GDBM_FILE   rpdb;
#elif HAVE_LIBNDBM
    DBM        *rpdb;
#endif

    datum       db_key, db_next_key;
    int         db_count = 0;

    /* If rotation was specified, do it.
    */
    if(opts->rotate_digest_cache)
        rotate_digest_cache_file(opts);

#ifdef HAVE_LIBGDBM
    rpdb = gdbm_open(
        opts->config[CONF_DIGEST_FILE], 512, GDBM_WRCREAT, S_IRUSR|S_IWUSR, 0
    );
#elif HAVE_LIBNDBM
    rpdb = dbm_open(
        opts->config[CONF_DIGEST_FILE], O_RDWR|O_CREAT, S_IRUSR|S_IWUSR
    );
#endif

    if(!rpdb)
    {
        log_msg(LOG_ERR,
            "Unable to open digest cache file: '%s': %s",
            opts->config[CONF_DIGEST_FILE],
            MY_DBM_STRERROR(errno)
        );

        return(-1);
    }

#ifdef HAVE_LIBGDBM
    db_key = gdbm_firstkey(rpdb);

    while (db_key.dptr != NULL)
    {
        db_count++;
        db_next_key = gdbm_nextkey(rpdb, db_key);
        free(db_key.dptr);
        db_key = db_next_key;
    }
#elif HAVE_LIBNDBM
    for (db_key = dbm_firstkey(rpdb); db_ent.dptr != NULL; db_key = dbm_nextkey(rpdb))
        db_count++;
#endif

    MY_DBM_CLOSE(rpdb);

    return(db_count);
}

/* Take an fko context, pull the digest and use it as the key to check the
 * replay db (digest cache). Returns 1 if there was a match (a replay),
 * 0 for no match, and -1 on error.
*/
int
replay_check(fko_srv_options_t *opts, fko_ctx_t ctx)
{
#ifdef HAVE_LIBGDBM
    GDBM_FILE   rpdb;
#elif HAVE_LIBNDBM
    DBM        *rpdb;
#endif
    datum       db_key, db_ent;

    //struct tm   created, first, last;
    char        created[18], first[18], last[18];
    int         replay_count    = 0;

    char        curr_ip[INET_ADDRSTRLEN+1] = {0};
    char        last_ip[INET_ADDRSTRLEN+1] = {0};

    char       *digest;
    int         digest_len, res;

    digest_cache_info_t dc_info, *dci_p;

    res = fko_get_spa_digest(ctx, &digest);
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error getting digest from SPA data: %s",
            fko_errstr(res));

        return(SPA_MSG_DIGEST_ERROR);
    }

    digest_len = strlen(digest);

    db_key.dptr = digest;
    db_key.dsize = digest_len;

    /* Check the db for the key
    */
#ifdef HAVE_LIBGDBM
    rpdb = gdbm_open(
         opts->config[CONF_DIGEST_FILE], 512, GDBM_WRCREAT, S_IRUSR|S_IWUSR, 0
    );
#elif HAVE_LIBNDBM
    rpdb = dbm_open(opts->config[CONF_DIGEST_FILE], O_RDWR, 0);
#endif

    if(!rpdb)
    {
        log_msg(LOG_WARNING, "Error opening digest_cache: '%s': %s",
            opts->config[CONF_DIGEST_FILE],
            MY_DBM_STRERROR(errno)
        );

        return(SPA_MSG_DIGEST_CACHE_ERROR);
    }

    db_ent = MY_DBM_FETCH(rpdb, db_key);

    /* If the datum is not null, we have a match.  Otherwise, we add
    * this entry to the cache.
    */
    if(db_ent.dptr != NULL)
    {
        dci_p = (digest_cache_info_t *)db_ent.dptr;

        /* Convert the IPs to a human readable form
        */
        inet_ntop(AF_INET, &(opts->spa_pkt.packet_src_ip),
            curr_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(dci_p->src_ip), last_ip, INET_ADDRSTRLEN);
 
        /* Mark the last_replay time.
        */
        dci_p->last_replay = time(NULL);

        /* Increment the replay count and check to see if it is the first one.
        */
        if(++(dci_p->replay_count) == 1)
        {
            /* This is the first replay so make it the same as last_replay
            */
            dci_p->first_replay = dci_p->last_replay;
        }

        strftime(created, 18, "%D %H:%M:%S", localtime(&(dci_p->created)));
        strftime(first, 18, "%D %H:%M:%S", localtime(&(dci_p->first_replay)));
        strftime(last, 18, "%D %H:%M:%S", localtime(&(dci_p->last_replay)));

        log_msg(LOG_WARNING,
            "Replay detected from source IP: %s\n"
            "            Original source IP: %s\n"
            "                 Entry created: %s\n"
            "                  First replay: %s\n"
            "                   Last replay: %s\n"
            "                  Replay count: %i\n",
            curr_ip, last_ip,
            created,
            first,
            last,
            dci_p->replay_count
        );

        /* Save it back to the digest cache
        */
        if(MY_DBM_STORE(rpdb, db_key, db_ent, GDBM_REPLACE) != 0)
            log_msg(LOG_WARNING, "Error updating entry in digest_cache: '%s': %s",
                opts->config[CONF_DIGEST_FILE],
                MY_DBM_STRERROR(errno)
            );

#ifdef HAVE_LIBGDBM
        free(db_ent.dptr);
#endif

        res = SPA_MSG_REPLAY;
    } else {
        /* This is a new SPA packet that needs to be added to the cache.
        */
        dc_info.src_ip  = opts->spa_pkt.packet_src_ip;
        dc_info.created = time(NULL);
        dc_info.first_replay = dc_info.last_replay = dc_info.replay_count = 0;

        db_ent.dsize    = sizeof(digest_cache_info_t);
        db_ent.dptr     = (char*)&(dc_info);

        if(MY_DBM_STORE(rpdb, db_key, db_ent, GDBM_INSERT) != 0)
        {
            log_msg(LOG_WARNING, "Error adding entry digest_cache: %s",
                MY_DBM_STRERROR(errno)
            );

            res = SPA_MSG_DIGEST_CACHE_ERROR;
        }

        res = SPA_MSG_SUCCESS;
    } 

    MY_DBM_CLOSE(rpdb);

    return(res);
}

/***EOF***/
