#include "totp.h"

uint32_t 
dynamic_truncation(unsigned char* hmac_result)
{
    uint32_t bin_code, offset;

    /* RFC4226 p7-8 */  
    offset = hmac_result[HMAC_LENGTH - 1] & 0xf;

    bin_code = (hmac_result[offset] & 0x7f) << 24
    | (hmac_result[offset+1] & 0xff) << 16
    | (hmac_result[offset+2] & 0xff) << 8
    | (hmac_result[offset+3] & 0xff);

    return bin_code;
}

/* Used by the client to set the TOTP value inside the context
*/
int
fko_set_totp(fko_ctx_t ctx, const char * const totp_code)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* Clear previous buffer
    */
    if(ctx->totp != NULL)
        free(ctx->totp);

    /* TODO: need to verify the memory allocation */
    ctx->totp = calloc(1, DIGITS+1); 
    if(ctx->totp == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    ctx->totp = strdup(totp_code);
    return(FKO_SUCCESS);
}

/* Used by the server to get the TOTP value from the context
*/
int
fko_get_totp(fko_ctx_t ctx, char **totp_code)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* TODO: Is this necessary?*/
    // if(totp_code == NULL)
    //     return(FKO_ERROR_INVALID_DATA);

    *totp_code = ctx->totp;

    return(FKO_SUCCESS);
}

/* Calculate TOTP based on initial secret and current timestamp
*/
int 
fko_totp_from_secret(uint32_t *totp_code, const char * const secret, uint64_t *timestamp, char *time_step)
{
    // HMAC-SHA1 result buffer
    uint8_t hmac_result[HMAC_LENGTH] = {0};

    // configure timestamp (T)
    uint64_t T = (uint64_t)floor((*timestamp - T0) / X) - *time_step;
    char time_buf[TIME_LEN] = {0};

    for (char i = 1; i <= TIME_LEN; i++)
    {
        time_buf[TIME_LEN - i] = (char)(((T >> 4) % 0x10) << 4 | (T % 0x10));
        T >>= 8;
    }

    if(hmac_sha1((const char *)time_buf, TIME_LEN, hmac_result, secret, TOTP_SECRET_LEN) != FKO_SUCCESS)
        return 0;

	*totp_code = dynamic_truncation(hmac_result) % (int)floor(pow(10.0, DIGITS)); 
    return 1;
}
