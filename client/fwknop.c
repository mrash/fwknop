/**
 * @file    fwknop.c
 *
 * @author  Damien S. Stuart
 *
 * @brief   An implementation of an fwknop client.
 *
 * Copyright 2009-2013 Damien Stuart (dstuart@dstuart.org)
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
 */

#include "fwknop.h"
#include "config_init.h"
#include "spa_comm.h"
#include "utils.h"
#include "getpasswd.h"

#include <sys/stat.h>
#include <fcntl.h>


/* prototypes
*/
static void get_keys(fko_ctx_t ctx, fko_cli_options_t *options,
    char *key, int *key_len, char *hmac_key,
    int *hmac_key_len, const int crypt_op);
static void display_ctx(fko_ctx_t ctx);
static void errmsg(const char *msg, const int err);
static void prev_exec(fko_cli_options_t *options, int argc, char **argv);
static int get_save_file(char *args_save_file);
static void show_last_command(const char * const args_save_file);
static void save_args(int argc, char **argv, const char * const args_save_file);
static void run_last_args(fko_cli_options_t *options,
        const char * const args_save_file);
static int set_message_type(fko_ctx_t ctx, fko_cli_options_t *options);
static int set_nat_access(fko_ctx_t ctx, fko_cli_options_t *options,
        const char * const access_buf);
static void set_access_buf(fko_ctx_t ctx, fko_cli_options_t *options,
        char *access_buf);
static int get_rand_port(fko_ctx_t ctx);
int resolve_ip_http(fko_cli_options_t *options);
static void clean_exit(fko_ctx_t ctx, fko_cli_options_t *opts,
    unsigned int exit_status);
static int is_hostname_str_with_port(const char *str, char *hostname, size_t hostname_bufsize, int *port);

#define MAX_CMDLINE_ARGS            50                  /*!< should be way more than enough */
#define IPV4_STR_TEMPLATE           "%u.%u.%u.%u"       /*!< Template for a string as an ipv4 address with sscanf */
#define NAT_ACCESS_STR_TEMPLATE     "%s,%d"             /*!< Template for a nat access string ip,port with sscanf*/
#define HOSTNAME_BUFSIZE            64                  /*!< Maximum size of a hostname string */


/**
 * @brief Check whether a string is an ipv4 address or not
 *
 * @param str String to check for an ipv4 address.
 *
 * @return 1 if the string is an ipv4 address, 0 otherwise.
 */
static int
is_ipv4_str(char *str)
{
    int o1, o2, o3, o4;
    int valid_ipv4;

    /* Check format and values.
    */
    if((sscanf(str, IPV4_STR_TEMPLATE, &o1, &o2, &o3, &o4)) == 4
        && o1 >= 0 && o1 <= 255
        && o2 >= 0 && o2 <= 255
        && o3 >= 0 && o3 <= 255
        && o4 >= 0 && o4 <= 255)
    {
        valid_ipv4 = 1;
    }
    else
        valid_ipv4 = 0;

    return valid_ipv4;
}

/**
 * @brief Check whether a string is an ipv6 address or not
 *
 * @param str String to check for an ipv6 address.
 *
 * @return 1 if the string is an ipv6 address, 0 otherwise.
 */
static int
is_ipv6_str(char *str)
{
    return 0;
}

/**
 * @brief Check a string to find out if it is built as 'hostname,port'
 *
 * This function check if we can extract an hostname and a port from the string.
 * If yes, we return 1, and both the hostname buffer and the port number are set
 * accordingly.
 *
 * We could have used sscanf() here with a template "%[^,],%u", but this way we
 * do not limit the size of the value copy in the hostname destination buffer.
 * Limiting the string in the sscanf() can be done but would prevent any easy change
 * for the hostname buffer size.
 *
 * @param str String to parse.
 * @param hostname Buffer where to store the hostname value read from @str.
 * @param hostname_bufsize Hostname buffer size.
 * @param port Value of the port read from @str.
 *
 * @return 1 if the string is built as 'hostname,port', 0 otherwise.
 */
static int
is_hostname_str_with_port(const char *str, char *hostname, size_t hostname_bufsize, int *port)
{
    int     valid = 0;                /* Result of the function */
    char    buf[MAX_LINE_LEN] = {0};  /* Copy of the buffer eg. "hostname,port" */
    char   *h;                        /* Pointer on the hostname string */
    char   *p;                        /* Ponter on the port string */

    memset(hostname, 0, hostname_bufsize);
    *port = 0;

    /* Replace the comma in the string with a NULL char to split the
     * buffer in two strings (hostname and port) */
    strlcpy(buf, str, sizeof(buf));
    p = strchr(buf, ',');

    if(p != NULL)
    {
        *p++ = 0;
        h = buf;

        *port = atoi(p);

        /* If the string does not match an ipv4 or ipv6 address we assume this
         * is an hostname. We make sure the port is in the good range too */
        if (   (is_ipv4_str(buf) == 0)
            && (is_ipv6_str(buf) == 0)
            && ((*port > 0) && (*port < 65536)) )
        {
            strlcpy(hostname, h, hostname_bufsize);
            valid = 1;
        }

        /* The port is out of range or the ip is an ipv6 or ipv4 address */
        else;
    }

    /* No port found in the string, let's skip */
    else;

    return valid;
}

int
main(int argc, char **argv)
{
    fko_ctx_t           ctx  = NULL;
    fko_ctx_t           ctx2 = NULL;
    int                 res;
    char               *spa_data=NULL, *version=NULL;
    char                access_buf[MAX_LINE_LEN] = {0};
    char                key[MAX_KEY_LEN+1]       = {0};
    char                hmac_key[MAX_KEY_LEN+1]  = {0};
    int                 key_len = 0, hmac_key_len = 0, enc_mode;

    fko_cli_options_t   options;

    /* Initialize the log module */
    log_new();

    /* Handle command line
    */
    config_init(&options, argc, argv);

    /* Handle previous execution arguments if required
    */
    prev_exec(&options, argc, argv);

    /* Intialize the context
    */
    res = fko_new(&ctx);
    if(res != FKO_SUCCESS)
    {
        errmsg("fko_new", res);
        return(EXIT_FAILURE);
    }

    /* Display version info and exit.
    */
    if(options.version)
    {
        fko_get_version(ctx, &version);

        fprintf(stdout, "fwknop client %s, FKO protocol version %s\n",
            MY_VERSION, version);

        fko_destroy(ctx);
        ctx = NULL;
        return(EXIT_SUCCESS);
    }

    /* Set client timeout
    */
    if(options.fw_timeout >= 0)
    {
        res = fko_set_spa_client_timeout(ctx, options.fw_timeout);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_client_timeout", res);
            fko_destroy(ctx);
            ctx = NULL;
            return(EXIT_FAILURE);
        }
    }

    /* Set the SPA packet message type based on command line options
    */
    res = set_message_type(ctx, &options);
    if(res != FKO_SUCCESS)
    {
        errmsg("fko_set_spa_message_type", res);
        fko_destroy(ctx);
        ctx = NULL;
        return(EXIT_FAILURE);
    }

    /* Adjust the SPA timestamp if necessary
    */
    if(options.time_offset_plus > 0)
    {
        res = fko_set_timestamp(ctx, options.time_offset_plus);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_timestamp", res);
            fko_destroy(ctx);
            ctx = NULL;
            return(EXIT_FAILURE);
        }
    }
    if(options.time_offset_minus > 0)
    {
        res = fko_set_timestamp(ctx, -options.time_offset_minus);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_timestamp", res);
            fko_destroy(ctx);
            ctx = NULL;
            return(EXIT_FAILURE);
        }
    }

    if(options.server_command[0] != 0x0)
    {
        /* Set the access message to a command that the server will
         * execute
        */
        snprintf(access_buf, MAX_LINE_LEN, "%s%s%s",
                options.allow_ip_str, ",", options.server_command);
    }
    else
    {
        /* Resolve the client's public facing IP address if requestesd.
         * if this fails, consider it fatal.
        */
        if (options.resolve_ip_http)
        {
            if(resolve_ip_http(&options) < 0)
            {
                fko_destroy(ctx);
                ctx = NULL;
                return(EXIT_FAILURE);
            }
        }

        /* Set a message string by combining the allow IP and the
         * port/protocol.  The fwknopd server allows no port/protocol
         * to be specified as well, so in this case append the string
         * "none/0" to the allow IP.
        */
        set_access_buf(ctx, &options, access_buf);
    }
    res = fko_set_spa_message(ctx, access_buf);
    if(res != FKO_SUCCESS)
    {
        errmsg("fko_set_spa_message", res);
        fko_destroy(ctx);
        ctx = NULL;
        return(EXIT_FAILURE);
    }

    /* Set NAT access string
    */
    if (options.nat_local || options.nat_access_str[0] != 0x0)
    {
        res = set_nat_access(ctx, &options, access_buf);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_nat_access_str", res);
            fko_destroy(ctx);
            ctx = NULL;
            return(EXIT_FAILURE);
        }
    }

    /* Set username
    */
    if(options.spoof_user[0] != 0x0)
    {
        res = fko_set_username(ctx, options.spoof_user);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_username", res);
            fko_destroy(ctx);
            ctx = NULL;
            return(EXIT_FAILURE);
        }
    }

    /* Set up for using GPG if specified.
    */
    if(options.use_gpg)
    {
        /* If use-gpg-agent was not specified, then remove the GPG_AGENT_INFO
         * ENV variable if it exists.
        */
#ifndef WIN32
        if(!options.use_gpg_agent)
            unsetenv("GPG_AGENT_INFO");
#endif

        res = fko_set_spa_encryption_type(ctx, FKO_ENCRYPTION_GPG);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_encryption_type", res);
            fko_destroy(ctx);
            ctx = NULL;
            return(EXIT_FAILURE);
        }

        /* If a GPG home dir was specified, set it here.  Note: Setting
         * this has to occur before calling any of the other GPG-related
         * functions.
        */
        if(strlen(options.gpg_home_dir) > 0)
        {
            res = fko_set_gpg_home_dir(ctx, options.gpg_home_dir);
            if(res != FKO_SUCCESS)
            {
                errmsg("fko_set_gpg_home_dir", res);
                fko_destroy(ctx);
                ctx = NULL;
                return(EXIT_FAILURE);
            }
        }

        res = fko_set_gpg_recipient(ctx, options.gpg_recipient_key);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_gpg_recipient", res);

            if(IS_GPG_ERROR(res))
                log_msg(LOG_VERBOSITY_ERROR, "GPG ERR: %s", fko_gpg_errstr(ctx));
            fko_destroy(ctx);
            ctx = NULL;
            return(EXIT_FAILURE);
        }

        if(strlen(options.gpg_signer_key) > 0)
        {
            res = fko_set_gpg_signer(ctx, options.gpg_signer_key);
            if(res != FKO_SUCCESS)
            {
                errmsg("fko_set_gpg_signer", res);

                if(IS_GPG_ERROR(res))
                    log_msg(LOG_VERBOSITY_ERROR, "GPG ERR: %s", fko_gpg_errstr(ctx));

                fko_destroy(ctx);
                ctx = NULL;
                return(EXIT_FAILURE);
            }
        }

        res = fko_set_spa_encryption_mode(ctx, FKO_ENC_MODE_ASYMMETRIC);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_encryption_mode", res);
            return(EXIT_FAILURE);
        }
    }

    if(options.encryption_mode && !options.use_gpg)
    {
        res = fko_set_spa_encryption_mode(ctx, options.encryption_mode);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_encryption_mode", res);
            return(EXIT_FAILURE);
        }
    }

    /* Set Digest type.
    */
    if(options.digest_type)
    {
        res = fko_set_spa_digest_type(ctx, options.digest_type);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_digest_type", res);
            fko_destroy(ctx);
            ctx = NULL;
            return(EXIT_FAILURE);
        }
    }

    /* Acquire the necessary encryption/hmac keys
    */
    get_keys(ctx, &options, key, &key_len,
        hmac_key, &hmac_key_len, CRYPT_OP_ENCRYPT);

    /* Finalize the context data (encrypt and encode the SPA data)
    */
    res = fko_spa_data_final(ctx, key, key_len, hmac_key, hmac_key_len);
    if(res != FKO_SUCCESS)
    {
        errmsg("fko_spa_data_final", res);

        if(IS_GPG_ERROR(res))
            log_msg(LOG_VERBOSITY_ERROR, "GPG ERR: %s", fko_gpg_errstr(ctx));

        clean_exit(ctx, &options, EXIT_FAILURE);
    }

    /* Display the context data.
    */
    if (options.verbose || options.test)
        display_ctx(ctx);

    /* Save packet data payload if requested.
    */
    if (options.save_packet_file[0] != 0x0)
        write_spa_packet_data(ctx, &options);

    if (options.rand_port)
        options.spa_dst_port = get_rand_port(ctx);

    res = send_spa_packet(ctx, &options);
    if(res < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet: packet not sent.");
        fko_destroy(ctx);
        ctx = NULL;
        return(EXIT_FAILURE);
    }
    else
    {
        log_msg(LOG_VERBOSITY_INFO, "send_spa_packet: bytes sent: %i", res);
    }

    /* Run through a decode cycle in test mode (--DSS XXX: This test/decode
     * portion should be moved elsewhere).
    */
    if (options.test)
    {
        /************** Decoding now *****************/

        /* Now we create a new context based on data from the first one.
        */
        res = fko_get_spa_data(ctx, &spa_data);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_get_spa_data", res);
            fko_destroy(ctx);
            ctx = NULL;
            return(EXIT_FAILURE);
        }

        /* Pull the encryption mode.
        */
        res = fko_get_spa_encryption_mode(ctx, &enc_mode);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_get_spa_encryption_mode", res);
            fko_destroy(ctx);
            fko_destroy(ctx2);
            ctx = ctx2 = NULL;
            return(EXIT_FAILURE);
        }

        /* If gpg-home-dir is specified, we have to defer decrypting if we
         * use the fko_new_with_data() function because we need to set the
         * gpg home dir after the context is created, but before we attempt
         * to decrypt the data.  Therefore we either pass NULL for the
         * decryption key to fko_new_with_data() or use fko_new() to create
         * an empty context, populate it with the encrypted data, set our
         * options, then decode it.
         *
         * This also verifies the HMAC and truncates it if there are no
         * problems.
        */
        res = fko_new_with_data(&ctx2, spa_data, NULL,
            0, enc_mode, hmac_key, hmac_key_len, options.hmac_type);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_new_with_data", res);
            fko_destroy(ctx);
            fko_destroy(ctx2);
            ctx = ctx2 = NULL;
            return(EXIT_FAILURE);
        }

        res = fko_set_spa_encryption_mode(ctx2, enc_mode);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_encryption_mode", res);
            fko_destroy(ctx);
            fko_destroy(ctx2);
            ctx = ctx2 = NULL;
            return(EXIT_FAILURE);
        }

        /* See if we are using gpg and if we need to set the GPG home dir.
        */
        if(options.use_gpg)
        {
            if(strlen(options.gpg_home_dir) > 0)
            {
                res = fko_set_gpg_home_dir(ctx2, options.gpg_home_dir);
                if(res != FKO_SUCCESS)
                {
                    errmsg("fko_set_gpg_home_dir", res);
                    fko_destroy(ctx);
                    fko_destroy(ctx2);
                    ctx = ctx2 = NULL;
                    return(EXIT_FAILURE);
                }
            }
        }

        get_keys(ctx2, &options, key, &key_len,
            hmac_key, &hmac_key_len, CRYPT_OP_DECRYPT);

        /* Decrypt
        */
        res = fko_decrypt_spa_data(ctx2, key, key_len);

        if(res != FKO_SUCCESS)
        {
            errmsg("fko_decrypt_spa_data", res);

            if(IS_GPG_ERROR(res)) {
                /* we most likely could not decrypt the gpg-encrypted data
                 * because we don't have access to the private key associated
                 * with the public key we used for encryption.  Since this is
                 * expected, return 0 instead of an error condition (so calling
                 * programs like the fwknop test suite don't interpret this as
                 * an unrecoverable error), but print the error string for
                 debugging purposes. */
                log_msg(LOG_VERBOSITY_ERROR, "GPG ERR: %s\n%s\n", fko_gpg_errstr(ctx2),
                    "No access to recipient private key?");
                fko_destroy(ctx);
                fko_destroy(ctx2);
                ctx = ctx2 = NULL;
                return(EXIT_SUCCESS);
            }

            fko_destroy(ctx);
            fko_destroy(ctx2);
            ctx = ctx2 = NULL;
            return(EXIT_FAILURE);
        }

        log_msg(LOG_VERBOSITY_NORMAL,"\nDump of the Decoded Data");
        display_ctx(ctx2);

        fko_destroy(ctx2);
        ctx2 = NULL;
    }

    clean_exit(ctx, &options, EXIT_SUCCESS);

    return(EXIT_SUCCESS);
}

void
free_configs(fko_cli_options_t *opts)
{
    if (opts->resolve_url != NULL)
        free(opts->resolve_url);
}

static int
get_rand_port(fko_ctx_t ctx)
{
    char *rand_val = NULL;
    char  port_str[MAX_PORT_STR_LEN+1] = {0};
    int   tmpint, is_err;
    int   port     = 0;
    int   res      = 0;

    res = fko_get_rand_value(ctx, &rand_val);
    if(res != FKO_SUCCESS)
    {
        errmsg("get_rand_port(), fko_get_rand_value", res);
        fko_destroy(ctx);
        ctx = NULL;
        exit(EXIT_FAILURE);
    }

    strlcpy(port_str, rand_val, sizeof(port_str));

    tmpint = strtol_wrapper(port_str, 0, -1, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_VERBOSITY_ERROR,
            "[*] get_rand_port(), could not convert rand_val str '%s', to integer",
            rand_val);
        fko_destroy(ctx);
        ctx = NULL;
        exit(EXIT_FAILURE);
    }

    /* Convert to a random value between 1024 and 65535
    */
    port = (MIN_HIGH_PORT + (tmpint % (MAX_PORT - MIN_HIGH_PORT)));

    /* Force libfko to calculate a new random value since we don't want to
     * give anyone a hint (via the port value) about the contents of the
     * encrypted SPA data.
    */
    res = fko_set_rand_value(ctx, NULL);
    if(res != FKO_SUCCESS)
    {
        errmsg("get_rand_port(), fko_get_rand_value", res);
        fko_destroy(ctx);
        ctx = NULL;
        exit(EXIT_FAILURE);
    }

    return port;
}

/* See if the string is of the format "<ipv4 addr>:<port>",
 */
static int
ipv4_str_has_port(char *str)
{
    int o1, o2, o3, o4, p;

    /* Force the ':' (if any) to a ','
    */
    char *ndx = strchr(str, ':');
    if(ndx != NULL)
        *ndx = ',';

    /* Check format and values.
    */
    if((sscanf(str, "%u.%u.%u.%u,%u", &o1, &o2, &o3, &o4, &p)) == 5
        && o1 >= 0 && o1 <= 255
        && o2 >= 0 && o2 <= 255
        && o3 >= 0 && o3 <= 255
        && o4 >= 0 && o4 <= 255
        && p  >  0 && p  <  65536)
    {
        return 1;
    }

    return 0;
}

/* Set access buf
*/
static void
set_access_buf(fko_ctx_t ctx, fko_cli_options_t *options, char *access_buf)
{
    char   *ndx = NULL, tmp_nat_port[MAX_PORT_STR_LEN+1] = {0};
    int     nat_port = 0;

    if(options->access_str[0] != 0x0)
    {
        if (options->nat_rand_port)
        {
            nat_port = get_rand_port(ctx);
            options->nat_port = nat_port;
        }
        else if (options->nat_port)
            nat_port = options->nat_port;

        if(nat_port > 0 && nat_port <= MAX_PORT)
        {
            /* Replace the access string port with the NAT port since the
             * NAT port is manually specified (--nat-port) or derived from
             * random data (--nat-rand-port).  In the NAT modes, the fwknopd
             * server uses the port in the access string as the one to NAT,
             * and access is granted via this translated port to whatever is
             * specified with --nat-access <IP:port> (so this service is the
             * utlimate target of the incoming connection after the SPA
             * packet is sent).
            */
            ndx = strchr(options->access_str, '/');
            if(ndx == NULL)
            {
                log_msg(LOG_VERBOSITY_ERROR, "[*] Expecting <proto>/<port> for -A arg.");
                clean_exit(ctx, options, EXIT_FAILURE);
            }
            snprintf(access_buf, MAX_LINE_LEN, "%s%s",
                    options->allow_ip_str, ",");

            /* This adds in the protocol + '/' char
            */
            strlcat(access_buf, options->access_str,
                    strlen(access_buf) + (ndx - options->access_str) + 2);

            if (strchr(ndx+1, '/') != NULL)
            {
                log_msg(LOG_VERBOSITY_ERROR,
                        "[*] NAT for multiple ports/protocols not yet supported.");
                clean_exit(ctx, options, EXIT_FAILURE);
            }

            /* Now add the NAT port
            */
            snprintf(tmp_nat_port, MAX_PORT_STR_LEN+1, "%d", nat_port);
            strlcat(access_buf, tmp_nat_port,
                    strlen(access_buf)+MAX_PORT_STR_LEN+1);
        }
        else
        {
            snprintf(access_buf, MAX_LINE_LEN, "%s%s%s",
                    options->allow_ip_str, ",", options->access_str);
        }
    }
    else
    {
        snprintf(access_buf, MAX_LINE_LEN, "%s%s%s",
                options->allow_ip_str, ",", "none/0");
    }
    return;
}

/* Set NAT access string
*/
static int
set_nat_access(fko_ctx_t ctx, fko_cli_options_t *options, const char * const access_buf)
{
    char                nat_access_buf[MAX_LINE_LEN] = {0};
    char                tmp_access_port[MAX_PORT_STR_LEN+1] = {0}, *ndx = NULL;
    int                 access_port = 0, i = 0, is_err = 0;
    char                dst_ip_str[INET_ADDRSTRLEN] = {0};
    char                hostname[HOSTNAME_BUFSIZE] = {0};
    int                 port = 0;
    struct addrinfo     hints;

    memset(&hints, 0 , sizeof(hints));

    ndx = strchr(options->access_str, '/');
    if(ndx == NULL)
    {
        log_msg(LOG_VERBOSITY_ERROR, "[*] Expecting <proto>/<port> for -A arg.");
        clean_exit(ctx, options, EXIT_FAILURE);
    }
    ndx++;

    while(*ndx != '\0' && isdigit(*ndx) && i < MAX_PORT_STR_LEN)
    {
        tmp_access_port[i] = *ndx;
        ndx++;
        i++;
    }
    tmp_access_port[i] = '\0';

    access_port = strtol_wrapper(tmp_access_port, 1,
            MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_VERBOSITY_ERROR, "[*] Invalid port value '%d' for -A arg.",
                access_port);
        clean_exit(ctx, options, EXIT_FAILURE);
    }

    if (options->nat_local && options->nat_access_str[0] == 0x0)
    {
        snprintf(nat_access_buf, MAX_LINE_LEN, NAT_ACCESS_STR_TEMPLATE,
            options->spa_server_str, access_port);
    }

    if (nat_access_buf[0] == 0x0 && options->nat_access_str[0] != 0x0)
    {
        if (ipv4_str_has_port(options->nat_access_str))
        {
            snprintf(nat_access_buf, MAX_LINE_LEN, "%s",
                options->nat_access_str);
        }
        else
        {
            snprintf(nat_access_buf, MAX_LINE_LEN, NAT_ACCESS_STR_TEMPLATE,
                options->nat_access_str, access_port);
        }
    }

    /* Check if there is a hostname to resolve as an ip address in the NAT access buffer */
    if (is_hostname_str_with_port(nat_access_buf, hostname, sizeof(hostname), &port))
    {
        /* Speed up the name resolution by forcing ipv4 (AF_INET).
         * A NULL pointer could be used instead if there is no constraint.
         * Maybe when ipv6 support will be enable the structure could initialize the
         * family to either AF_INET or AF_INET6 */
        hints.ai_family = AF_INET;

        if (resolve_dest_adr(hostname, &hints, dst_ip_str, sizeof(dst_ip_str)) != 0)
        {
            log_msg(LOG_VERBOSITY_ERROR, "[*] Unable to resolve %s as an ip address",
                    hostname);
            clean_exit(ctx, options, EXIT_FAILURE);
        }

        snprintf(nat_access_buf, MAX_LINE_LEN, NAT_ACCESS_STR_TEMPLATE,
                dst_ip_str, port);
    }

    /* Nothing to resolve */
    else;

    if(options->nat_rand_port)
    {
        /* Must print to stdout what the random port is since
         * if not then the user will not which port will be
         * opened/NAT'd on the fwknopd side
        */
        log_msg(LOG_VERBOSITY_NORMAL,
                "[+] Randomly assigned port '%d' on: '%s' will grant access to: '%s'",
                options->nat_port, access_buf, nat_access_buf);
    }

    return fko_set_spa_nat_access(ctx, nat_access_buf);
}

static void
prev_exec(fko_cli_options_t *options, int argc, char **argv)
{
    char       args_save_file[MAX_PATH_LEN] = {0};

    if(options->args_save_file[0] != 0x0)
    {
        strlcpy(args_save_file, options->args_save_file, sizeof(args_save_file));
    }
    else
    {
        if (get_save_file(args_save_file) != 1)
        {
            log_msg(LOG_VERBOSITY_ERROR, "Unable to determine args save file");
            exit(EXIT_FAILURE);
        }
    }

    if(options->run_last_command)
        run_last_args(options, args_save_file);
    else if(options->show_last_command)
        show_last_command(args_save_file);
    else if (!options->no_save_args)
        save_args(argc, argv, args_save_file);

    return;
}

/* Show the last command that was executed
*/
static void
show_last_command(const char * const args_save_file)
{
    char args_str[MAX_LINE_LEN] = {0};
    FILE *args_file_ptr = NULL;

    verify_file_perms_ownership(args_save_file);
    if ((args_file_ptr = fopen(args_save_file, "r")) == NULL) {
        log_msg(LOG_VERBOSITY_ERROR, "Could not open args file: %s",
            args_save_file);
        exit(EXIT_FAILURE);
    }

    if ((fgets(args_str, MAX_LINE_LEN, args_file_ptr)) != NULL) {
        log_msg(LOG_VERBOSITY_NORMAL, "Last fwknop client command line: %s", args_str);
    } else {
        log_msg(LOG_VERBOSITY_NORMAL, "Could not read line from file: %s", args_save_file);
    }
    fclose(args_file_ptr);

    exit(EXIT_SUCCESS);
}

/* Get the command line arguments from the previous invocation
*/
static void
run_last_args(fko_cli_options_t *options, const char * const args_save_file)
{
    FILE           *args_file_ptr = NULL;

    int             current_arg_ctr = 0;
    int             argc_new = 0;
    int             i = 0;

    char            args_str[MAX_LINE_LEN] = {0};
    char            arg_tmp[MAX_LINE_LEN]  = {0};
    char           *argv_new[MAX_CMDLINE_ARGS];  /* should be way more than enough */

    verify_file_perms_ownership(args_save_file);
    if ((args_file_ptr = fopen(args_save_file, "r")) == NULL)
    {
        log_msg(LOG_VERBOSITY_ERROR, "Could not open args file: %s",
                args_save_file);
        exit(EXIT_FAILURE);
    }
    if ((fgets(args_str, MAX_LINE_LEN, args_file_ptr)) != NULL)
    {
        args_str[MAX_LINE_LEN-1] = '\0';
        if (options->verbose)
            log_msg(LOG_VERBOSITY_NORMAL, "Executing: %s", args_str);
        for (i=0; i < (int)strlen(args_str); i++)
        {
            if (!isspace(args_str[i]))
            {
                arg_tmp[current_arg_ctr] = args_str[i];
                current_arg_ctr++;
            }
            else
            {
                arg_tmp[current_arg_ctr] = '\0';
                argv_new[argc_new] = malloc(strlen(arg_tmp)+1);
                if (argv_new[argc_new] == NULL)
                {
                    log_msg(LOG_VERBOSITY_ERROR, "[*] malloc failure for cmd line arg.");
                    exit(EXIT_FAILURE);
                }
                strlcpy(argv_new[argc_new], arg_tmp, strlen(arg_tmp)+1);
                current_arg_ctr = 0;
                argc_new++;
                if(argc_new >= MAX_CMDLINE_ARGS)
                {
                    log_msg(LOG_VERBOSITY_ERROR, "[*] max command line args exceeded.");
                    exit(EXIT_FAILURE);
                }
            }
        }
    }
    fclose(args_file_ptr);

    /* Reset the options index so we can run through them again.
    */
    optind = 0;

    config_init(options, argc_new, argv_new);

    /* Since we passed in our own copies, free up malloc'd memory
    */
    for (i=0; i < argc_new; i++)
    {
        if(argv_new[i] == NULL)
            break;
        else
            free(argv_new[i]);
    }

    return;
}

static int
get_save_file(char *args_save_file)
{
    char *homedir = NULL;
    int rv = 0;

#ifdef WIN32
    homedir = getenv("USERPROFILE");
#else
    homedir = getenv("HOME");
#endif
    if (homedir != NULL) {
        snprintf(args_save_file, MAX_PATH_LEN, "%s%c%s",
            homedir, PATH_SEP, ".fwknop.run");
        rv = 1;
    }

    return rv;
}

/* Save our command line arguments
*/
static void
save_args(int argc, char **argv, const char * const args_save_file)
{
    char args_str[MAX_LINE_LEN] = {0};
    int i = 0, args_str_len = 0, args_file_fd = -1;

    args_file_fd = open(args_save_file, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
    if (args_file_fd == -1) {
        log_msg(LOG_VERBOSITY_ERROR, "Could not open args file: %s",
            args_save_file);
        exit(EXIT_FAILURE);
    }
    else {
        for (i=0; i < argc; i++) {
            args_str_len += strlen(argv[i]);
            if (args_str_len >= MAX_PATH_LEN) {
                log_msg(LOG_VERBOSITY_ERROR, "argument string too long, exiting.");
                exit(EXIT_FAILURE);
            }
            strlcat(args_str, argv[i], sizeof(args_str));
            strlcat(args_str, " ", sizeof(args_str));
        }
        strlcat(args_str, "\n", sizeof(args_str));
        if(write(args_file_fd, args_str, strlen(args_str))
                != strlen(args_str)) {
            log_msg(LOG_VERBOSITY_WARNING,
                "warning, did not write expected number of bytes to args save file");
        }
        close(args_file_fd);
    }
    return;
}

/* Set the SPA packet message type
*/
static int
set_message_type(fko_ctx_t ctx, fko_cli_options_t *options)
{
    short message_type;

    if(options->server_command[0] != 0x0)
    {
        message_type = FKO_COMMAND_MSG;
    }
    else if(options->nat_local)
    {
        if (options->fw_timeout >= 0)
            message_type = FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG;
        else
            message_type = FKO_LOCAL_NAT_ACCESS_MSG;
    }
    else if(options->nat_access_str[0] != 0x0)
    {
        if (options->fw_timeout >= 0)
            message_type = FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG;
        else
            message_type = FKO_NAT_ACCESS_MSG;
    }
    else
    {
        if (options->fw_timeout >= 0)
            message_type = FKO_CLIENT_TIMEOUT_ACCESS_MSG;
        else
            message_type = FKO_ACCESS_MSG;
    }

    return fko_set_spa_message_type(ctx, message_type);
}

/* Prompt for and receive a user password.
*/
static void
get_keys(fko_ctx_t ctx, fko_cli_options_t *options,
    char *key, int *key_len, char *hmac_key,
    int *hmac_key_len, const int crypt_op)
{
    char   *key_tmp = NULL, *hmac_key_tmp = NULL;
    int     use_hmac = 0, res = 0;

    memset(key, 0x0, MAX_KEY_LEN+1);
    memset(hmac_key, 0x0, MAX_KEY_LEN+1);

    if (options->have_key)
    {
        strlcpy(key, options->key, MAX_KEY_LEN+1);
        *key_len = strlen(key);
    }
    else if (options->have_base64_key)
    {
        *key_len = fko_base64_decode(options->key_base64,
                (unsigned char *) options->key);
        if(*key_len > 0 && *key_len < MAX_KEY_LEN)
        {
            memcpy(key, options->key, *key_len);
        }
        else
        {
            log_msg(LOG_VERBOSITY_ERROR, "[*] Invalid key length: '%d', must be in [1,%d]",
                    *key_len, MAX_KEY_LEN);
            clean_exit(ctx, options, EXIT_FAILURE);
        }
    }
    else
    {
        /* If --get-key file was specified grab the key/password from it.
        */
        if (options->get_key_file[0] != 0x0)
        {
            get_key_file(key, key_len, options->get_key_file, ctx, options);
        }
        else if (options->use_gpg)
        {
            if(options->use_gpg_agent)
                log_msg(LOG_VERBOSITY_NORMAL,
                    "[+] GPG mode set, signing passphrase acquired via gpg-agent");
            else if(options->gpg_no_signing_pw)
                log_msg(LOG_VERBOSITY_NORMAL,
                    "[+] GPG mode set, signing passphrase not required");
            else if(crypt_op == CRYPT_OP_ENCRYPT)
                log_msg(LOG_VERBOSITY_NORMAL,
                    "[+] GPG mode set, encrypt instead of decrypt operation");
            else if(crypt_op == CRYPT_OP_DECRYPT)
            {
                key_tmp = getpasswd("Enter passphrase for secret key: ", options->input_fd);
                if(key_tmp == NULL)
                {
                    log_msg(LOG_VERBOSITY_ERROR, "[*] getpasswd() key error.");
                    clean_exit(ctx, options, EXIT_FAILURE);
                }
                strlcpy(key, key_tmp, MAX_KEY_LEN+1);
                *key_len = strlen(key);
            }
            else if(strlen(options->gpg_signer_key))
            {
                key_tmp = getpasswd("Enter passphrase for signing: ", options->input_fd);
                if(key_tmp == NULL)
                {
                    log_msg(LOG_VERBOSITY_ERROR, "[*] getpasswd() key error.");
                    clean_exit(ctx, options, EXIT_FAILURE);
                }
                strlcpy(key, key_tmp, MAX_KEY_LEN+1);
                *key_len = strlen(key);
            }
        }
        else
        {
            if(crypt_op == CRYPT_OP_ENCRYPT)
                key_tmp = getpasswd("Enter encryption key: ", options->input_fd);
            else if(crypt_op == CRYPT_OP_DECRYPT)
                key_tmp = getpasswd("Enter decryption key: ", options->input_fd);
            else
                key_tmp = getpasswd("Enter key: ", options->input_fd);

            if(key_tmp == NULL)
            {
                log_msg(LOG_VERBOSITY_ERROR, "[*] getpasswd() key error.");
                clean_exit(ctx, options, EXIT_FAILURE);
            }
            strlcpy(key, key_tmp, MAX_KEY_LEN+1);
            *key_len = strlen(key);
        }
    }

    if(options->have_hmac_key)
    {
        strlcpy(hmac_key, options->hmac_key, MAX_KEY_LEN+1);
        *hmac_key_len = strlen(hmac_key);
        use_hmac = 1;
    }
    else if(options->have_hmac_base64_key)
    {
        *hmac_key_len = fko_base64_decode(options->hmac_key_base64,
            (unsigned char *) options->hmac_key);
        if(*hmac_key_len > MAX_KEY_LEN || *hmac_key_len < 0)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                    "[*] Invalid decoded key length: '%d', must be in [0,%d]",
                    *hmac_key_len, MAX_KEY_LEN);
            clean_exit(ctx, options, EXIT_FAILURE);
        }
        memcpy(hmac_key, options->hmac_key, *hmac_key_len);
        use_hmac = 1;
    }
    else if (options->use_hmac)
    {
        /* If --get-key file was specified grab the key/password from it.
        */
        if(options->get_hmac_key_file[0] != 0x0)
        {
            get_key_file(hmac_key, hmac_key_len,
                options->get_hmac_key_file, ctx, options);
            use_hmac = 1;
        }
        else
        {
            hmac_key_tmp = getpasswd("Enter HMAC key: ", options->input_fd);

            if(hmac_key_tmp == NULL)
            {
                log_msg(LOG_VERBOSITY_ERROR, "[*] getpasswd() key error.");
                clean_exit(ctx, options, EXIT_FAILURE);
            }

            strlcpy(hmac_key, hmac_key_tmp, MAX_KEY_LEN+1);
            *hmac_key_len = strlen(hmac_key);
            use_hmac = 1;
        }
    }

    if (use_hmac)
    {
        if(*hmac_key_len < 0 || *hmac_key_len > MAX_KEY_LEN)
        {
            log_msg(LOG_VERBOSITY_ERROR, "[*] Invalid HMAC key length: '%d', must be in [0,%d]",
                    *hmac_key_len, MAX_KEY_LEN);
            clean_exit(ctx, options, EXIT_FAILURE);
        }

        /* Make sure the same key is not used for both encryption and the HMAC
        */
        if(*hmac_key_len == *key_len)
        {
            if(memcmp(hmac_key, key, *key_len) == 0)
            {
                log_msg(LOG_VERBOSITY_ERROR,
                    "[*] The encryption passphrase and HMAC key should not be identical, no SPA packet sent. Exiting.");
                clean_exit(ctx, options, EXIT_FAILURE);
            }
        }

        res = fko_set_spa_hmac_type(ctx, options->hmac_type);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_hmac_type", res);
            exit(EXIT_FAILURE);
        }
    }

    return;
}

/* Display an FKO error message.
*/
void
errmsg(const char *msg, const int err) {
    log_msg(LOG_VERBOSITY_ERROR, "%s: %s: Error %i - %s",
        MY_NAME, msg, err, fko_errstr(err));
}

/* free up memory and exit
*/
static void
clean_exit(fko_ctx_t ctx, fko_cli_options_t *opts, unsigned int exit_status)
{
    free_configs(opts);
    fko_destroy(ctx);
    ctx = NULL;
    exit(exit_status);
}

/* Show the fields of the FKO context.
*/
static void
display_ctx(fko_ctx_t ctx)
{
    char       *rand_val        = NULL;
    char       *username        = NULL;
    char       *version         = NULL;
    char       *spa_message     = NULL;
    char       *nat_access      = NULL;
    char       *server_auth     = NULL;
    char       *enc_data        = NULL;
    char       *hmac_data       = NULL;
    char       *spa_digest      = NULL;
    char       *spa_data        = NULL;
    char        digest_str[MAX_LINE_LEN]   = {0};
    char        hmac_str[MAX_LINE_LEN]     = {0};
    char        enc_mode_str[MAX_LINE_LEN] = {0};

    time_t      timestamp       = 0;
    short       msg_type        = -1;
    short       digest_type     = -1;
    short       hmac_type       = -1;
    short       encryption_type = -1;
    int         encryption_mode = -1;
    int         client_timeout  = -1;

    /* Should be checking return values, but this is temp code. --DSS
    */
    fko_get_rand_value(ctx, &rand_val);
    fko_get_username(ctx, &username);
    fko_get_timestamp(ctx, &timestamp);
    fko_get_version(ctx, &version);
    fko_get_spa_message_type(ctx, &msg_type);
    fko_get_spa_message(ctx, &spa_message);
    fko_get_spa_nat_access(ctx, &nat_access);
    fko_get_spa_server_auth(ctx, &server_auth);
    fko_get_spa_client_timeout(ctx, &client_timeout);
    fko_get_spa_digest_type(ctx, &digest_type);
    fko_get_spa_hmac_type(ctx, &hmac_type);
    fko_get_spa_encryption_type(ctx, &encryption_type);
    fko_get_spa_encryption_mode(ctx, &encryption_mode);
    fko_get_encoded_data(ctx, &enc_data);
    fko_get_spa_hmac(ctx, &hmac_data);
    fko_get_spa_digest(ctx, &spa_digest);
    fko_get_spa_data(ctx, &spa_data);

    digest_inttostr(digest_type, digest_str, sizeof(digest_str));
    hmac_digest_inttostr(hmac_type, hmac_str, sizeof(hmac_str));
    enc_mode_inttostr(encryption_mode, enc_mode_str, sizeof(enc_mode_str));

    log_msg(LOG_VERBOSITY_NORMAL, "\nFKO Field Values:\n=================\n");
    log_msg(LOG_VERBOSITY_NORMAL, "   Random Value: %s", rand_val == NULL ? "<NULL>" : rand_val);
    log_msg(LOG_VERBOSITY_NORMAL, "       Username: %s", username == NULL ? "<NULL>" : username);
    log_msg(LOG_VERBOSITY_NORMAL, "      Timestamp: %u", (unsigned int) timestamp);
    log_msg(LOG_VERBOSITY_NORMAL, "    FKO Version: %s", version == NULL ? "<NULL>" : version);
    log_msg(LOG_VERBOSITY_NORMAL, "   Message Type: %i (%s)", msg_type, msg_type_inttostr(msg_type));
    log_msg(LOG_VERBOSITY_NORMAL, " Message String: %s", spa_message == NULL ? "<NULL>" : spa_message);
    log_msg(LOG_VERBOSITY_NORMAL, "     Nat Access: %s", nat_access == NULL ? "<NULL>" : nat_access);
    log_msg(LOG_VERBOSITY_NORMAL, "    Server Auth: %s", server_auth == NULL ? "<NULL>" : server_auth);
    log_msg(LOG_VERBOSITY_NORMAL, " Client Timeout: %u (seconds)", client_timeout);
    log_msg(LOG_VERBOSITY_NORMAL, "    Digest Type: %d (%s)", digest_type, digest_str);
    log_msg(LOG_VERBOSITY_NORMAL, "      HMAC Type: %d (%s)", hmac_type, hmac_str);
    log_msg(LOG_VERBOSITY_NORMAL, "Encryption Type: %d (%s)", encryption_type, enc_type_inttostr(encryption_type));
    log_msg(LOG_VERBOSITY_NORMAL, "Encryption Mode: %d (%s)", encryption_mode, enc_mode_str);
    log_msg(LOG_VERBOSITY_NORMAL, "\n   Encoded Data: %s", enc_data == NULL ? "<NULL>" : enc_data);
    log_msg(LOG_VERBOSITY_NORMAL, "SPA Data Digest: %s", spa_digest == NULL ? "<NULL>" : spa_digest);
    log_msg(LOG_VERBOSITY_NORMAL, "           HMAC: %s", hmac_data == NULL ? "<NULL>" : hmac_data);

    if (enc_data != NULL && spa_digest != NULL)
        log_msg(LOG_VERBOSITY_NORMAL, "      Plaintext: %s:%s\n", enc_data, spa_digest);

    log_msg(LOG_VERBOSITY_NORMAL, "\nFinal Packed/Encrypted/Encoded Data:\n\n%s\n", spa_data);
}

/***EOF***/
