/*
 *****************************************************************************
 *
 * File:    replay_cache.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Provides the functions to check for possible replay attacks
 *          by using a cache of previously seen digests.  This cache is a
 *          simple file by default, but can be made to use a dbm solution
 *          (ndbm or gdbm in ndbm compatibility mode) file to store the digest
 *          of a previously received SPA packets.
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
#include "replay_cache.h"
#include "log_msg.h"
#include "fwknopd_errors.h"
#include "utils.h"

#include <time.h>

#if USE_FILE_CACHE

#elif HAVE_LIBGDBM
  #include <gdbm.h>

  #define MY_DBM_FETCH(d, k)        gdbm_fetch(d, k)
  #define MY_DBM_STORE(d, k, v, m)  gdbm_store(d, k, v, m)
  #define MY_DBM_STRERROR(x)        gdbm_strerror(x)
  #define MY_DBM_CLOSE(d)           gdbm_close(d)

  #define MY_DBM_REPLACE            GDBM_REPLACE
  #define MY_DBM_INSERT             GDBM_INSERT

#elif HAVE_LIBNDBM
  #include <ndbm.h>

  #define MY_DBM_FETCH(d, k)        dbm_fetch(d, k)
  #define MY_DBM_STORE(d, k, v, m)  dbm_store(d, k, v, m)
  #define MY_DBM_STRERROR(x)        strerror(x)
  #define MY_DBM_CLOSE(d)           dbm_close(d)

  #define MY_DBM_REPLACE            DBM_REPLACE
  #define MY_DBM_INSERT             DBM_INSERT

#else
  #error "File cache method disabled, and No GDBM or NDBM header file found. WTF?"
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
#ifdef NO_DIGEST_CACHE
    log_msg(LOG_WARNING, "Digest cache not supported. Nothing to rotate.");
#else
    int         res;
    char       *new_file = NULL;

    log_msg(LOG_INFO, "Rotating digest cache file.");

#if USE_FILE_CACHE
    new_file = malloc(strlen(opts->config[CONF_DIGEST_FILE])+5);
#else
    new_file = malloc(strlen(opts->config[CONF_DIGEST_DB_FILE])+5);
#endif

    if(new_file == NULL)
    {
        log_msg(LOG_ERR, "rotate_digest_cache_file: Memory allocation error.");
        exit(EXIT_FAILURE);
    }

    /* The new filename is just the original with a trailing '-old'.
    */
#if USE_FILE_CACHE
    strcpy(new_file, opts->config[CONF_DIGEST_FILE]);
#else
    strcpy(new_file, opts->config[CONF_DIGEST_DB_FILE]);
#endif
    strcat(new_file, "-old");

#if USE_FILE_CACHE
    res = rename(opts->config[CONF_DIGEST_FILE], new_file);
#else
    res = rename(opts->config[CONF_DIGEST_DB_FILE], new_file);
#endif

    if(res < 0)
        log_msg(LOG_ERR, "Unable to rename digest file: %s to %s: %s",
#if USE_FILE_CACHE
            opts->config[CONF_DIGEST_FILE], new_file, strerror(errno)
#else
            opts->config[CONF_DIGEST_DB_FILE], new_file, strerror(errno)
#endif
        );
#endif /* NO_DIGEST_CACHE */
}

int
replay_cache_init(fko_srv_options_t *opts)
{
#ifdef NO_DIGEST_CACHE
    return 0;
#else

    /* If rotation was specified, do it.
    */
    if(opts->rotate_digest_cache)
        rotate_digest_cache_file(opts);

#if USE_FILE_CACHE
    return replay_file_cache_init(opts);
#else
    return replay_db_cache_init(opts);
#endif

#endif /* NO_DIGEST_CACHE */
}

#if USE_FILE_CACHE
int
replay_file_cache_init(fko_srv_options_t *opts)
{
    /* if the file exists, import the previous SPA digests into
     * the cache list
    */
    return 0;
}

#else /* USE_FILE_CACHE */

/* Check for the existence of the replay dbm file, and create it if it does
 * not exist.  Returns the number of db entries or -1 on error.
*/
int
replay_db_cache_init(fko_srv_options_t *opts)
{
#ifdef NO_DIGEST_CACHE
    return 0;
#else

#ifdef HAVE_LIBGDBM
    GDBM_FILE   rpdb;
#elif HAVE_LIBNDBM
    DBM        *rpdb;
#endif

    datum       db_key, db_ent, db_next_key;
    int         db_count = 0;

#ifdef HAVE_LIBGDBM
    rpdb = gdbm_open(
        opts->config[CONF_DIGEST_DB_FILE], 512, GDBM_WRCREAT, S_IRUSR|S_IWUSR, 0
    );
#elif HAVE_LIBNDBM
    rpdb = dbm_open(
        opts->config[CONF_DIGEST_DB_FILE], O_RDWR|O_CREAT, S_IRUSR|S_IWUSR
    );
#endif

    if(!rpdb)
    {
        log_msg(LOG_ERR,
            "Unable to open digest cache file: '%s': %s",
            opts->config[CONF_DIGEST_DB_FILE],
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
#endif /* NO_DIGEST_CACHE */
}
#endif /* USE_FILE_CACHE */

/* Take an fko context, pull the digest and use it as the key to check the
 * replay db (digest cache). Returns 1 if there was a match (a replay),
 * 0 for no match, and -1 on error.
*/
int
replay_check(fko_srv_options_t *opts, fko_ctx_t ctx)
{
#ifdef NO_DIGEST_CACHE
    return 0;
#else

#if USE_FILE_CACHE
    return replay_check_file_cache(opts, ctx);
#else
    return replay_check_dbm_cache(opts, ctx);
#endif
#endif /* NO_DIGEST_CACHE */
}

#if USE_FILE_CACHE
int
replay_check_file_cache(fko_srv_options_t *opts, fko_ctx_t ctx)
{
    char       *digest = NULL;
    char        src_ip[INET_ADDRSTRLEN+1] = {0};
    int         res = 0, digest_len = 0;
    FILE       *digest_file_cache_ptr = NULL;

    struct digest_cache_list *digest_list_ptr = NULL, *digest_elm = NULL;

    res = fko_get_spa_digest(ctx, &digest);
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error getting digest from SPA data: %s",
            fko_errstr(res));

        return(SPA_MSG_DIGEST_ERROR);
    }

    digest_len = strlen(digest);

    /* Check the cache for the SPA packet digest
    */
    for (digest_list_ptr = opts->digest_cache;
            digest_list_ptr != NULL;
            digest_list_ptr = digest_list_ptr->next) {
        if (strncmp(digest_list_ptr->cache_info.digest, digest, digest_len) == 0) {
            /* Detected a replay attack - bail
            */
            return(SPA_MSG_REPLAY);
        }
    }

    /* If we make it here, then this is a new SPA packet that needs to be
     * added to the cache.  We've already decrypted the data, so we know that
     * the contents are valid.
    */
    if ((digest_elm = calloc(1, sizeof(struct digest_cache_list))) == NULL)
    {
        log_msg(LOG_WARNING, "Error malloc() returned NULL for digest cache element",
            fko_errstr(SPA_MSG_ERROR));

        return(SPA_MSG_ERROR);
    }
    if ((digest_elm->cache_info.digest = calloc(1, digest_len+1)) == NULL)
    {
        log_msg(LOG_WARNING, "Error malloc() returned NULL for digest cache string",
            fko_errstr(SPA_MSG_ERROR));
        free(digest_elm);
        return(SPA_MSG_ERROR);
    }

    strlcpy(digest_elm->cache_info.digest, digest, digest_len+1);
    digest_elm->cache_info.src_ip = opts->spa_pkt.packet_src_ip;
    digest_elm->cache_info.created = time(NULL);

    /* First, add the digest at the head of the in-memory list
    */
    digest_elm->next = opts->digest_cache;
    opts->digest_cache = digest_elm;

    /* Now, write the digest to disk
    */
    if ((digest_file_cache_ptr = fopen(opts->config[CONF_DIGEST_FILE], "a")) == NULL)
    {
        log_msg(LOG_WARNING, "Could not open digest cache: %s",
            opts->config[CONF_DIGEST_FILE]);
        return(SPA_MSG_DIGEST_CACHE_ERROR);
    }

    inet_ntop(AF_INET, &(digest_elm->cache_info.src_ip),
        src_ip, INET_ADDRSTRLEN);
    fprintf(digest_file_cache_ptr, "%s %s %d\n",
        digest, src_ip, (int) digest_elm->cache_info.created);

    fclose(digest_file_cache_ptr);

    return(SPA_MSG_SUCCESS);
}
#endif /* USE_FILE_CACHE */

#if !USE_FILE_CACHE
int
replay_check_dbm_cache(fko_srv_options_t *opts, fko_ctx_t ctx)
{
#ifdef NO_DIGEST_CACHE
    return 0;
#else

#ifdef HAVE_LIBGDBM
    GDBM_FILE   rpdb;
#elif HAVE_LIBNDBM
    DBM        *rpdb;
#endif
    datum       db_key, db_ent;

    char        created[18], first[18], last[18];

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
         opts->config[CONF_DIGEST_DB_FILE], 512, GDBM_WRCREAT, S_IRUSR|S_IWUSR, 0
    );
#elif HAVE_LIBNDBM
    rpdb = dbm_open(opts->config[CONF_DIGEST_DB_FILE], O_RDWR, 0);
#endif

    if(!rpdb)
    {
        log_msg(LOG_WARNING, "Error opening digest_cache: '%s': %s",
            opts->config[CONF_DIGEST_DB_FILE],
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
        if(MY_DBM_STORE(rpdb, db_key, db_ent, MY_DBM_REPLACE) != 0)
            log_msg(LOG_WARNING, "Error updating entry in digest_cache: '%s': %s",
                opts->config[CONF_DIGEST_DB_FILE],
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

        if(MY_DBM_STORE(rpdb, db_key, db_ent, MY_DBM_INSERT) != 0)
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
#endif /* NO_DIGEST_CACHE */
}
#endif /* USE_FILE_CACHE */

/***EOF***/
