/*
 *****************************************************************************
 *
 * File:    fko_rand_value.c
 *
 * Purpose: Generate a 16-byte random numeric value.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009–2014 fwknop developers and contributors. For a full
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
 *****************************************************************************
*/
#include "fko_common.h"
#include "fko.h"
#include "base64.h"

#ifdef WIN32
  #include <sys/timeb.h>
  #include <time.h>
#else
  #ifdef HAVE_SYS_TIME_H
    #include <sys/time.h>
    #ifdef TIME_WITH_SYS_TIME
      #include <time.h>
    #endif
  #endif

  #define RAND_FILE "/dev/urandom"
#endif


/* Get random data and place it into a buffer.
*/
void
get_random_data(unsigned char *buf, const size_t l, const int mode)
{
    uint32_t            i;
    int                 len = l;

    if(len > FKO_MAX_RAND_SIZE)
        len = FKO_MAX_RAND_SIZE;

#ifdef WIN32
	int				rnum;
	struct _timeb	tb;

	_ftime_s(&tb);

	srand((uint32_t)(tb.time*1000)+tb.millitm);

	for(i=0; i<len; i++)
	{
		rnum = rand();
		*(buf+i) = rnum % 0xff;
	}
#else

    FILE           *rfd;
    struct timeval  tv;
    int             do_time = 0;
    size_t          amt_read;
    unsigned long   seed;
    char            tmp_buf[FKO_MAX_RAND_SIZE+1] = {0};

    /* Attempt to read seed data from /dev/urandom.  If that does not
     * work, then fall back to a time-based method (less secure, but
     * probably more portable).
    */
    if((rfd = fopen(RAND_FILE, "r")) == NULL)
    {
        do_time = 1;
    }
    else
    {
        /* Read seed from /dev/urandom
        */
        amt_read = fread(&seed, 4, 1, rfd);
        fclose(rfd);

        if (amt_read != 1)
            do_time = 1;
    }

    if (do_time)
    {
        /* Seed based on time (current usecs).
        */
        gettimeofday(&tv, NULL);
        seed = tv.tv_usec;
    }

    /* Always seed random number generation
    */
    srand(seed);

    if(mode == FKO_RAND_MODE_LEGACY)
    {
        snprintf((char *)buf, len+1, "%u", rand());
        while(strnlen((char *)buf, len+1) < len)
        {
            snprintf(tmp_buf, len+1, "%u", rand());
            strlcat((char *)buf, tmp_buf, FKO_RAND_VAL_SIZE+1);
        }
    }
    else
    {
        for(i=0; i<len; i++)
            *(buf+i) = rand() % 0xff;
    }
#endif
}

/* Set the SPA randomization mode (use random length and style)
*/
int
fko_set_spa_rand_mode(fko_ctx_t ctx, const int rand_mode)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(rand_mode < 0 || rand_mode >= FKO_LAST_RAND_MODE)
        return(FKO_ERROR_INVALID_DATA_RAND_MODE_VALIDFAIL);

    ctx->rand_mode = rand_mode;

    ctx->state |= FKO_RAND_MODE_MODIFIED;

    return(FKO_SUCCESS);
}

/* Return the SPA randomization mode.
*/
int
fko_get_spa_rand_mode(fko_ctx_t ctx, int *rand_mode)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(rand_mode == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *rand_mode = ctx->rand_mode;

    return(FKO_SUCCESS);
}

/* Set/Generate the SPA data random value string.
*/
int
fko_set_rand_value(fko_ctx_t ctx, const char * const new_val)
{
    unsigned char           *tmp_buf;
    int                      b64_len = 0;

    /* Context must be initialized.
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* If a valid value was given, use it and return happy.
    */
    if(new_val != NULL)
    {
        /* Must have at least FKO_RAND_VAL_SIZE bytes
        */
        if(strnlen(new_val, FKO_RAND_VAL_B64_SIZE+1) < FKO_RAND_VAL_SIZE)
            return(FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL);

        if(ctx->rand_val != NULL)
            free(ctx->rand_val);

        ctx->rand_val = strdup(new_val);
        if(ctx->rand_val == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

        ctx->state |= FKO_DATA_MODIFIED;

        return(FKO_SUCCESS);
    }

    if(ctx->rand_val != NULL)
        free(ctx->rand_val);

    ctx->rand_val = malloc(FKO_RAND_VAL_B64_SIZE+1);
    if(ctx->rand_val == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);
    memset(ctx->rand_val, 0, FKO_RAND_VAL_B64_SIZE+1);

    tmp_buf = malloc(FKO_RAND_VAL_SIZE+1);
    if(tmp_buf == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);
    memset(tmp_buf, 0, FKO_RAND_VAL_SIZE+1);

    get_random_data(tmp_buf, FKO_RAND_VAL_SIZE, ctx->rand_mode);

    b64_len = b64_encode(tmp_buf, ctx->rand_val, FKO_RAND_VAL_SIZE);

    if(b64_len < FKO_RAND_VAL_SIZE)
    {
        free(tmp_buf);
        return(FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL);
    }

    strip_b64_eq(ctx->rand_val);

    free(tmp_buf);

    ctx->state |= FKO_DATA_MODIFIED;

    return(FKO_SUCCESS);
}

/* Return the current rand value.
*/
int
fko_get_rand_value(fko_ctx_t ctx, char **rand_value)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(rand_value == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *rand_value = ctx->rand_val;

    return(FKO_SUCCESS);
}

/***EOF***/
