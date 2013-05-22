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

#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#if HAVE_LIBGDBM
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
  #if ! USE_FILE_CACHE
    #error "File cache method disabled, and No GDBM or NDBM header file found. WTF?"
  #endif
#endif

#if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
#endif
#include <arpa/inet.h>

#include <fcntl.h>

#define DATE_LEN 18
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
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* The new filename is just the original with a trailing '-old'.
    */
#if USE_FILE_CACHE
    strlcpy(new_file, opts->config[CONF_DIGEST_FILE],
        strlen(opts->config[CONF_DIGEST_FILE])+5);
    strlcat(new_file, "-old",
            strlen(opts->config[CONF_DIGEST_FILE])+5);
#else
    strlcpy(new_file, opts->config[CONF_DIGEST_DB_FILE],
        strlen(opts->config[CONF_DIGEST_DB_FILE])+5);
    strlcat(new_file, "-old",
            strlen(opts->config[CONF_DIGEST_DB_FILE])+5);
#endif

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

    if(new_file != NULL)
        free(new_file);
}

static void
replay_warning(fko_srv_options_t *opts, digest_cache_info_t *digest_info)
{
    char        src_ip[INET_ADDRSTRLEN+1] = {0};
    char        orig_src_ip[INET_ADDRSTRLEN+1] = {0};
    char        created[DATE_LEN] = {0};

#if ! USE_FILE_CACHE
    char        first[DATE_LEN] = {0}, last[DATE_LEN] = {0};
#endif

    /* Convert the IPs to a human readable form
    */
    inet_ntop(AF_INET, &(opts->spa_pkt.packet_src_ip),
        src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(digest_info->src_ip), orig_src_ip, INET_ADDRSTRLEN);

#if ! USE_FILE_CACHE
    /* Mark the last_replay time.
    */
    digest_info->last_replay = time(NULL);

    /* Increment the replay count and check to see if it is the first one.
    */
    if(++(digest_info->replay_count) == 1)
    {
        /* This is the first replay so make it the same as last_replay
        */
        digest_info->first_replay = digest_info->last_replay;
    }

    strftime(first, DATE_LEN, "%D %H:%M:%S", localtime(&(digest_info->first_replay)));
    strftime(last, DATE_LEN, "%D %H:%M:%S", localtime(&(digest_info->last_replay)));
#endif

    strftime(created, DATE_LEN, "%D %H:%M:%S", localtime(&(digest_info->created)));

    log_msg(LOG_WARNING,
        "Replay detected from source IP: %s, "
        "Destination proto/port: %d/%d, "
        "Original source IP: %s, "
        "Original dst proto/port: %d/%d, "
#if USE_FILE_CACHE
        "Entry created: %s",
#else
        "Entry created: %s, "
        "First replay: %s, "
        "Last replay: %s, "
        "Replay count: %i",
#endif
        src_ip,
        opts->spa_pkt.packet_proto,
        opts->spa_pkt.packet_dst_port,
        orig_src_ip,
        digest_info->proto,
        digest_info->dst_port,
#if USE_FILE_CACHE
        created
#else
        created,
        first,
        last,
        digest_info->replay_count
#endif
    );

    return;
}

int
replay_cache_init(fko_srv_options_t *opts)
{
#ifdef NO_DIGEST_CACHE
    return(-1);
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
    FILE           *digest_file_ptr = NULL;
    unsigned int    num_lines = 0, digest_ctr = 0;
    char            line_buf[MAX_LINE_LEN]    = {0};
    char            src_ip[INET_ADDRSTRLEN+1] = {0};
    char            dst_ip[INET_ADDRSTRLEN+1] = {0};
    long int        time_tmp;
    int             digest_file_fd = -1;
    char            digest_header[] = "# <digest> <proto> <src_ip> <src_port> <dst_ip> <dst_port> <time>\n";

    struct digest_cache_list *digest_elm = NULL;

    /* if the file exists, import the previous SPA digests into
     * the cache list
    */
    if (access(opts->config[CONF_DIGEST_FILE], F_OK) == 0)
    {
        /* Check permissions
        */
        if (access(opts->config[CONF_DIGEST_FILE], R_OK|W_OK) != 0)
        {
            log_msg(LOG_WARNING, "Digest file '%s' exists but: '%s'",
                opts->config[CONF_DIGEST_FILE], strerror(errno));
            return(-1);
        }
    }
    else
    {
        /* the file does not exist yet, so it will be created when the first
         * successful SPA packet digest is written to disk
        */
        digest_file_fd = open(opts->config[CONF_DIGEST_FILE], O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
        if (digest_file_fd == -1)
        {
            log_msg(LOG_WARNING, "Could not create digest cache: %s: %s",
                opts->config[CONF_DIGEST_FILE], strerror(errno));
            return(-1);
        }
        else
        {
            if(write(digest_file_fd, digest_header, strlen(digest_header))
                    != strlen(digest_header)) {
                log_msg(LOG_WARNING,
                    "Did not write expected number of bytes to digest cache: %s\n",
                    opts->config[CONF_DIGEST_FILE]);
            }
            close(digest_file_fd);

            return(0);
        }
    }

    verify_file_perms_ownership(opts->config[CONF_DIGEST_FILE]);

    /* File exists, and we have access - create in-memory digest cache
    */
    if ((digest_file_ptr = fopen(opts->config[CONF_DIGEST_FILE], "r")) == NULL)
    {
        log_msg(LOG_WARNING, "Could not open digest cache: %s",
            opts->config[CONF_DIGEST_FILE]);
        return(-1);
    }

    /* Line format:
     * <digest> <proto> <src_ip> <src_port> <dst_ip> <dst_port> <time>
     * Example:
     * 7XgadOyqv0tF5xG8uhg2iIrheeNKglCWKmxQDgYP1dY 17 127.0.0.1 40305 127.0.0.1 62201 1313283481
    */
    while ((fgets(line_buf, MAX_LINE_LEN, digest_file_ptr)) != NULL)
    {
        num_lines++;
        line_buf[MAX_LINE_LEN-1] = '\0';

        if(IS_EMPTY_LINE(line_buf[0]))
            continue;

        /* Initialize a digest cache list element, and add it into the list if
         * valid.
        */
        if ((digest_elm = calloc(1, sizeof(struct digest_cache_list))) == NULL)
        {
            fprintf(stderr, "Could not allocate digest list element\n");
            continue;
        }
        if ((digest_elm->cache_info.digest = calloc(1, MAX_DIGEST_SIZE+1)) == NULL)
        {
            free(digest_elm);
            fprintf(stderr, "Could not allocate digest string\n");
            continue;
        }
        src_ip[0] = '\0';
        dst_ip[0] = '\0';

        if(sscanf(line_buf, "%s %hhu %s %hu %s %hu %ld",
            digest_elm->cache_info.digest,
            &(digest_elm->cache_info.proto),
            src_ip,
            &(digest_elm->cache_info.src_port),
            dst_ip,
            &(digest_elm->cache_info.dst_port),
            &time_tmp) != 7)
        {
            if(opts->verbose)
                fprintf(stderr,
                    "*Skipping invalid digest file entry in %s at line %i.\n - %s",
                    opts->config[CONF_DIGEST_FILE], num_lines, line_buf
                );
            free(digest_elm->cache_info.digest);
            free(digest_elm);
            continue;
        }
        digest_elm->cache_info.created = time_tmp;


        if (inet_pton(AF_INET, src_ip, &(digest_elm->cache_info.src_ip)) != 1)
        {
            free(digest_elm->cache_info.digest);
            free(digest_elm);
            continue;
        }

        if (inet_pton(AF_INET, dst_ip, &(digest_elm->cache_info.dst_ip)) != 1)
        {
            free(digest_elm->cache_info.digest);
            free(digest_elm);
            continue;
        }

        digest_elm->next   = opts->digest_cache;
        opts->digest_cache = digest_elm;
        digest_ctr++;

        if(opts->verbose > 3)
            fprintf(stderr,
                "DIGEST FILE: %s, VALID LINE: %s",
                opts->config[CONF_DIGEST_FILE], line_buf
            );

    }

    fclose(digest_file_ptr);

    return(digest_ctr);
}

#else /* USE_FILE_CACHE */

/* Check for the existence of the replay dbm file, and create it if it does
 * not exist.  Returns the number of db entries or -1 on error.
*/
int
replay_db_cache_init(fko_srv_options_t *opts)
{
#ifdef NO_DIGEST_CACHE
    return(-1);
#else

#ifdef HAVE_LIBGDBM
    GDBM_FILE   rpdb;
#elif HAVE_LIBNDBM
    DBM        *rpdb;
    datum       db_ent;
#endif

    datum       db_key, db_next_key;
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
 * replay db (digest cache).
*/
int
is_replay(fko_srv_options_t *opts, char *digest)
{
#ifdef NO_DIGEST_CACHE
    return(-1);
#else

#if USE_FILE_CACHE
    return is_replay_file_cache(opts, digest);
#else
    return is_replay_dbm_cache(opts, digest);
#endif
#endif /* NO_DIGEST_CACHE */
}

int
add_replay(fko_srv_options_t *opts, char *digest)
{
#ifdef NO_DIGEST_CACHE
    return(-1);
#else

#if USE_FILE_CACHE
    return add_replay_file_cache(opts, digest);
#else
    return add_replay_dbm_cache(opts, digest);
#endif
#endif /* NO_DIGEST_CACHE */
}

#if USE_FILE_CACHE
int
is_replay_file_cache(fko_srv_options_t *opts, char *digest)
{
    int         digest_len = 0;

    struct digest_cache_list *digest_list_ptr = NULL;

    digest_len = strlen(digest);

    /* Check the cache for the SPA packet digest
    */
    for (digest_list_ptr = opts->digest_cache;
            digest_list_ptr != NULL;
            digest_list_ptr = digest_list_ptr->next) {

        if (strncmp(digest_list_ptr->cache_info.digest, digest, digest_len) == 0) {

            replay_warning(opts, &(digest_list_ptr->cache_info));

            return(SPA_MSG_REPLAY);
        }
    }
    return(SPA_MSG_SUCCESS);
}

int
add_replay_file_cache(fko_srv_options_t *opts, char *digest)
{
    FILE       *digest_file_ptr = NULL;
    int         digest_len = 0;
    char        src_ip[INET_ADDRSTRLEN+1] = {0};
    char        dst_ip[INET_ADDRSTRLEN+1] = {0};

    struct digest_cache_list *digest_elm = NULL;

    digest_len = strlen(digest);

    if ((digest_elm = calloc(1, sizeof(struct digest_cache_list))) == NULL)
    {
        log_msg(LOG_WARNING, "Error calloc() returned NULL for digest cache element",
            fko_errstr(SPA_MSG_ERROR));

        return(SPA_MSG_ERROR);
    }
    if ((digest_elm->cache_info.digest = calloc(1, digest_len+1)) == NULL)
    {
        log_msg(LOG_WARNING, "Error calloc() returned NULL for digest cache string",
            fko_errstr(SPA_MSG_ERROR));
        free(digest_elm);
        return(SPA_MSG_ERROR);
    }

    strlcpy(digest_elm->cache_info.digest, digest, digest_len+1);
    digest_elm->cache_info.proto    = opts->spa_pkt.packet_proto;
    digest_elm->cache_info.src_ip   = opts->spa_pkt.packet_src_ip;
    digest_elm->cache_info.dst_ip   = opts->spa_pkt.packet_dst_ip;
    digest_elm->cache_info.src_port = opts->spa_pkt.packet_src_port;
    digest_elm->cache_info.dst_port = opts->spa_pkt.packet_dst_port;
    digest_elm->cache_info.created = time(NULL);

    /* First, add the digest at the head of the in-memory list
    */
    digest_elm->next = opts->digest_cache;
    opts->digest_cache = digest_elm;

    /* Now, write the digest to disk
    */
    if ((digest_file_ptr = fopen(opts->config[CONF_DIGEST_FILE], "a")) == NULL)
    {
        log_msg(LOG_WARNING, "Could not open digest cache: %s",
            opts->config[CONF_DIGEST_FILE]);
        return(SPA_MSG_DIGEST_CACHE_ERROR);
    }

    inet_ntop(AF_INET, &(digest_elm->cache_info.src_ip),
        src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(digest_elm->cache_info.dst_ip),
        dst_ip, INET_ADDRSTRLEN);
    fprintf(digest_file_ptr, "%s %d %s %d %s %d %d\n",
        digest,
        digest_elm->cache_info.proto,
        src_ip,
        (int) digest_elm->cache_info.src_port,
        dst_ip,
        digest_elm->cache_info.dst_port,
        (int) digest_elm->cache_info.created);

    fclose(digest_file_ptr);

    return(SPA_MSG_SUCCESS);
}
#endif /* USE_FILE_CACHE */

#if !USE_FILE_CACHE
int
is_replay_dbm_cache(fko_srv_options_t *opts, char *digest)
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

    int         digest_len, res = SPA_MSG_SUCCESS;

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
        replay_warning(opts, (digest_cache_info_t *)db_ent.dptr);

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
    }

    MY_DBM_CLOSE(rpdb);

    return(res);
#endif /* NO_DIGEST_CACHE */
}

int
add_replay_dbm_cache(fko_srv_options_t *opts, char *digest)
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

    int         digest_len, res = SPA_MSG_SUCCESS;

    digest_cache_info_t dc_info;

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

    /* If the datum is null, we have a new entry.
    */
    if(db_ent.dptr == NULL)
    {
        /* This is a new SPA packet that needs to be added to the cache.
        */
        dc_info.src_ip   = opts->spa_pkt.packet_src_ip;
        dc_info.dst_ip   = opts->spa_pkt.packet_dst_ip;
        dc_info.src_port = opts->spa_pkt.packet_src_port;
        dc_info.dst_port = opts->spa_pkt.packet_dst_port;
        dc_info.proto    = opts->spa_pkt.packet_proto;
        dc_info.created  = time(NULL);
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
    else
        res = SPA_MSG_DIGEST_CACHE_ERROR;

    MY_DBM_CLOSE(rpdb);

    return(res);
#endif /* NO_DIGEST_CACHE */
}
#endif /* USE_FILE_CACHE */

#if USE_FILE_CACHE
/* Free replay list memory
*/
void
free_replay_list(fko_srv_options_t *opts)
{
#ifdef NO_DIGEST_CACHE
    return;
#endif
    struct digest_cache_list *digest_list_ptr = NULL, *digest_tmp = NULL;

    if (opts->digest_cache == NULL)
        return;

    digest_list_ptr = opts->digest_cache;
    while (digest_list_ptr != NULL)
    {
        digest_tmp = digest_list_ptr->next;
        if (digest_list_ptr->cache_info.digest != NULL
                && digest_list_ptr->cache_info.digest[0] != '\0')
        {
            free(digest_list_ptr->cache_info.digest);
        }
        free(digest_list_ptr);
        digest_list_ptr = digest_tmp;
    }

    return;
}
#endif


/***EOF***/
