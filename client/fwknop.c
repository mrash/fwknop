/*
 *****************************************************************************
 *
 * File:    fwknop.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: An implementation of an fwknop client.
 *
 * Copyright 2009-2010 Damien Stuart (dstuart@dstuart.org)
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
static int set_nat_access(fko_ctx_t ctx, fko_cli_options_t *options);
static int get_rand_port(fko_ctx_t ctx);
int resolve_ip_http(fko_cli_options_t *options);
static void clean_exit(fko_ctx_t ctx, fko_cli_options_t *opts,
    unsigned int exit_status);

#define MAX_CMDLINE_ARGS    50  /* should be way more than enough */

int
main(int argc, char **argv)
{
    fko_ctx_t           ctx = NULL;
    fko_ctx_t           ctx2 = NULL;
    int                 res;
    char               *spa_data=NULL, *version=NULL;
    char                access_buf[MAX_LINE_LEN] = {0};
    char                key[MAX_KEY_LEN+1]       = {0};
    char                hmac_key[MAX_KEY_LEN+1]  = {0};
    int                 key_len = 0, hmac_key_len = 0, enc_mode;
    FILE               *key_gen_file_ptr = NULL;

    fko_cli_options_t   options;

    memset(key, 0x00, MAX_KEY_LEN+1);
    memset(hmac_key, 0x00, MAX_KEY_LEN+1);
    memset(access_buf, 0x00, MAX_LINE_LEN);
    memset(hmac_key, 0x00, MAX_KEY_LEN);

    /* Handle command line
    */
    config_init(&options, argc, argv);

    /* Handle previous execution arguments if required
    */
    prev_exec(&options, argc, argv);

    /* Generate Rijndael + HMAC keys from /dev/random (base64
     * encoded) and exit.
    */
    if(options.key_gen)
    {
        fko_key_gen(options.key_base64, options.key_len,
                options.hmac_key_base64, options.hmac_key_len,
                options.hmac_type);

        if(options.key_gen_file != NULL && options.key_gen_file[0] != '\0')
        {
            if ((key_gen_file_ptr = fopen(options.key_gen_file, "w")) == NULL)
            {
                fprintf(stderr, "Unable to create key gen file: %s: %s\n",
                    options.key_gen_file, strerror(errno));
                return(EXIT_FAILURE);
            }
            fprintf(key_gen_file_ptr, "KEY_BASE64: %s\nHMAC_KEY_BASE64: %s\n",
                options.key_base64, options.hmac_key_base64);
            fclose(key_gen_file_ptr);
            printf("[+] Wrote Rijndael and HMAC keys to: %s\n",
                options.key_gen_file);
        }
        else
        {
            printf("KEY_BASE64: %s\nHMAC_KEY_BASE64: %s\n",
                    options.key_base64, options.hmac_key_base64);
        }
        return(EXIT_SUCCESS);
    }

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
                return(EXIT_FAILURE);
            }
        }

        /* Set a message string by combining the allow IP and the
         * port/protocol.  The fwknopd server allows no port/protocol
         * to be specified as well, so in this case append the string
         * "none/0" to the allow IP.
        */
        if(options.access_str[0] != 0x0)
        {
            snprintf(access_buf, MAX_LINE_LEN, "%s%s%s",
                    options.allow_ip_str, ",", options.access_str);
        }
        else
        {
            snprintf(access_buf, MAX_LINE_LEN, "%s%s%s",
                    options.allow_ip_str, ",", "none/0");
        }
    }
    res = fko_set_spa_message(ctx, access_buf);
    if(res != FKO_SUCCESS)
    {
        errmsg("fko_set_spa_message", res);
        fko_destroy(ctx);
        return(EXIT_FAILURE);
    }

    /* Set NAT access string
    */
    if (options.nat_local || options.nat_access_str[0] != 0x0)
    {
        res = set_nat_access(ctx, &options);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_nat_access_str", res);
            fko_destroy(ctx);
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
            return(EXIT_FAILURE);
        }

        /* If a GPG home dir was specified, set it here.  Note: Setting
         * this has to occur before calling any of the other GPG-related
         * functions.
        */
        if(options.gpg_home_dir != NULL && strlen(options.gpg_home_dir) > 0)
        {
            res = fko_set_gpg_home_dir(ctx, options.gpg_home_dir);
            if(res != FKO_SUCCESS)
            {
                errmsg("fko_set_gpg_home_dir", res);
                fko_destroy(ctx);
                return(EXIT_FAILURE);
            }
        }

        res = fko_set_gpg_recipient(ctx, options.gpg_recipient_key);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_gpg_recipient", res);

            if(IS_GPG_ERROR(res))
                fprintf(stderr, "GPG ERR: %s\n", fko_gpg_errstr(ctx));
            fko_destroy(ctx);
            return(EXIT_FAILURE);
        }

        if(options.gpg_signer_key != NULL && strlen(options.gpg_signer_key))
        {
            res = fko_set_gpg_signer(ctx, options.gpg_signer_key);
            if(res != FKO_SUCCESS)
            {
                errmsg("fko_set_gpg_signer", res);

                if(IS_GPG_ERROR(res))
                    fprintf(stderr, "GPG ERR: %s\n", fko_gpg_errstr(ctx));

                fko_destroy(ctx);
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
        fko_set_spa_digest_type(ctx, options.digest_type);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_digest_type", res);
            fko_destroy(ctx);
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
            fprintf(stderr, "GPG ERR: %s\n", fko_gpg_errstr(ctx));

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
        fprintf(stderr, "send_spa_packet: packet not sent.\n");
        fko_destroy(ctx);
        return(EXIT_FAILURE);
    }
    else
    {
        if(options.verbose)
            fprintf(stderr, "send_spa_packet: bytes sent: %i\n", res);
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
            return(EXIT_FAILURE);
        }

        /* If gpg-home-dir is specified, we have to defer decrypting if we
         * use the fko_new_with_data() function because we need to set the
         * gpg home dir after the context is created, but before we attempt
         * to decrypt the data.  Therefore we either pass NULL for the
         * decryption key to fko_new_with_data() or use fko_new() to create
         * an empty context, populate it with the encrypted data, set our
         * options, then decode it.
        */
        res = fko_new_with_data(&ctx2, spa_data, NULL,
            0, enc_mode, hmac_key, hmac_key_len, options.hmac_type);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_new_with_data", res);
            fko_destroy(ctx);
            fko_destroy(ctx2);
            return(EXIT_FAILURE);
        }

        res = fko_set_spa_encryption_mode(ctx2, enc_mode);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_encryption_mode", res);
            fko_destroy(ctx);
            fko_destroy(ctx2);
            return(EXIT_FAILURE);
        }

        /* See if we are using gpg and if we need to set the GPG home dir.
        */
        if(options.use_gpg)
        {
            if(options.gpg_home_dir != NULL && strlen(options.gpg_home_dir) > 0)
            {
                res = fko_set_gpg_home_dir(ctx2, options.gpg_home_dir);
                if(res != FKO_SUCCESS)
                {
                    errmsg("fko_set_gpg_home_dir", res);
                    fko_destroy(ctx);
                    fko_destroy(ctx2);
                    return(EXIT_FAILURE);
                }
            }
        }

        get_keys(ctx2, &options, key, &key_len,
            hmac_key, &hmac_key_len, CRYPT_OP_DECRYPT);

        /* Verify HMAC first
        */
        if(options.use_hmac)
            res = fko_verify_hmac(ctx2, hmac_key, hmac_key_len);

        /* Decrypt
        */
        if(options.use_hmac)
        {
            /* check fko_verify_hmac() return value */
        }
        else
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
                fprintf(stderr, "GPG ERR: %s\n%s\n", fko_gpg_errstr(ctx2),
                    "No access to recipient private key?\n");
                fko_destroy(ctx);
                fko_destroy(ctx2);
                return(EXIT_SUCCESS);
            }

            fko_destroy(ctx);
            fko_destroy(ctx2);
            return(EXIT_FAILURE);
        }

        printf("\nDump of the Decoded Data\n");
        display_ctx(ctx2);

        fko_destroy(ctx2);
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
    char  port_str[6];
    int   tmpint, is_err;
    int   port     = 0;
    int   res      = 0;

    res = fko_get_rand_value(ctx, &rand_val);
    if(res != FKO_SUCCESS)
    {
        errmsg("get_rand_port(), fko_get_rand_value", res);
        fko_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    strlcpy(port_str, rand_val, 6);

    tmpint = strtol_wrapper(port_str, 0, -1, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        fprintf(stderr,
            "[*] get_rand_port(), could not convert rand_val str '%s', to integer",
            rand_val);
        fko_destroy(ctx);
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

/* Set NAT access string
*/
static int
set_nat_access(fko_ctx_t ctx, fko_cli_options_t *options)
{
    char nat_access_buf[MAX_LINE_LEN] = "";
    int nat_port = 0;

    if (options->nat_rand_port)
        nat_port = get_rand_port(ctx);
    else if (options->nat_port)
        nat_port = options->nat_port;
    else
        nat_port = DEFAULT_NAT_PORT;

    if (options->nat_local && options->nat_access_str[0] == 0x0)
    {
        snprintf(nat_access_buf, MAX_LINE_LEN, "%s,%d",
            options->spa_server_str, nat_port);
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
            snprintf(nat_access_buf, MAX_LINE_LEN, "%s,%d",
                options->nat_access_str, nat_port);
        }
    }

    return fko_set_spa_nat_access(ctx, nat_access_buf);
}

static void
prev_exec(fko_cli_options_t *options, int argc, char **argv)
{
    char       args_save_file[MAX_PATH_LEN] = {0};

    if(options->args_save_file != NULL && options->args_save_file[0] != 0x0)
    {
        strlcpy(args_save_file, options->args_save_file, MAX_PATH_LEN);
    }
    else
    {
        if (get_save_file(args_save_file) != 1)
        {
            fprintf(stderr, "Unable to determine args save file\n");
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
    char args_str[MAX_LINE_LEN] = "";
    FILE *args_file_ptr = NULL;

    verify_file_perms_ownership(args_save_file);
    if ((args_file_ptr = fopen(args_save_file, "r")) == NULL) {
        fprintf(stderr, "Could not open args file: %s\n",
            args_save_file);
        exit(EXIT_FAILURE);
    }

    if ((fgets(args_str, MAX_LINE_LEN, args_file_ptr)) != NULL) {
        printf("Last fwknop client command line: %s", args_str);
    } else {
        printf("Could not read line from file: %s\n", args_save_file);
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
        fprintf(stderr, "Could not open args file: %s\n",
                args_save_file);
        exit(EXIT_FAILURE);
    }
    if ((fgets(args_str, MAX_LINE_LEN, args_file_ptr)) != NULL)
    {
        args_str[MAX_LINE_LEN-1] = '\0';
        if (options->verbose)
            printf("Executing: %s\n", args_str);
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
                    fprintf(stderr, "[*] malloc failure for cmd line arg.\n");
                    exit(EXIT_FAILURE);
                }
                strlcpy(argv_new[argc_new], arg_tmp, strlen(arg_tmp)+1);
                current_arg_ctr = 0;
                argc_new++;
                if(argc_new >= MAX_CMDLINE_ARGS)
                {
                    fprintf(stderr, "[*] max command line args exceeded.\n");
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
    char args_str[MAX_LINE_LEN] = "";
    int i = 0, args_str_len = 0, args_file_fd = -1;

    args_file_fd = open(args_save_file, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
    if (args_file_fd == -1) {
        fprintf(stderr, "Could not open args file: %s\n",
            args_save_file);
        exit(EXIT_FAILURE);
    }
    else {
        for (i=0; i < argc; i++) {
            args_str_len += strlen(argv[i]);
            if (args_str_len >= MAX_PATH_LEN) {
                fprintf(stderr, "argument string too long, exiting.\n");
                exit(EXIT_FAILURE);
            }
            strlcat(args_str, argv[i], MAX_PATH_LEN);
            strlcat(args_str, " ", MAX_PATH_LEN);
        }
        strlcat(args_str, "\n", MAX_PATH_LEN);
        if(write(args_file_fd, args_str, strlen(args_str))
                != strlen(args_str)) {
            fprintf(stderr,
            "warning, did not write expected number of bytes to args save file\n");
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
    int use_hmac = 0, res = 0;

    memset(key, 0x0, MAX_KEY_LEN+1);
    memset(hmac_key, 0x0, MAX_KEY_LEN+1);

    /* First of all if we are using GPG and GPG_AGENT
     * then there is no password to return.
    */
    if(options->use_gpg
      && (options->use_gpg_agent
           || (crypt_op == CRYPT_OP_ENCRYPT && options->gpg_signer_key == NULL)))
        return;

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
            fprintf(stderr, "[*] Invalid base64 decoded key length.");
            clean_exit(ctx, options, EXIT_FAILURE);
        }
    }
    else
    {
        /* If --get-key file was specified grab the key/password from it.
        */
        if (options->get_key_file[0] != 0x0)
        {
            strlcpy(key, getpasswd_file(ctx, options), MAX_KEY_LEN+1);
            *key_len = strlen(key);
        }
        else if (options->use_gpg)
        {
            if(crypt_op == CRYPT_OP_DECRYPT)
            {
                strlcpy(key, getpasswd("Enter passphrase for secret key: "),
                    MAX_KEY_LEN+1);
                *key_len = strlen(key);
            }
            else if(options->gpg_signer_key && strlen(options->gpg_signer_key))
            {
                strlcpy(key, getpasswd("Enter passphrase for signing: "),
                    MAX_KEY_LEN+1);
                *key_len = strlen(key);
            }
        }
        else
        {
            if(crypt_op == CRYPT_OP_ENCRYPT)
                strlcpy(key, getpasswd("Enter encryption key: "),
                    MAX_KEY_LEN+1);
            else if(crypt_op == CRYPT_OP_DECRYPT)
                strlcpy(key, getpasswd("Enter decryption key: "),
                    MAX_KEY_LEN+1);
            else
                strlcpy(key, getpasswd("Enter key: "),
                    MAX_KEY_LEN+1);
            *key_len = strlen(key);
        }
    }


    if (options->have_hmac_key)
    {
        strlcpy(hmac_key, options->hmac_key, MAX_KEY_LEN+1);
        *hmac_key_len = strlen(hmac_key);
        use_hmac = 1;
    }
    else if (options->have_hmac_base64_key)
    {
        *hmac_key_len = fko_base64_decode(options->hmac_key_base64,
            (unsigned char *) options->hmac_key);
        memcpy(hmac_key, options->hmac_key, *hmac_key_len);
        use_hmac = 1;
    }
    else if (options->use_hmac)
    {
        /* If --get-key file was specified grab the key/password from it.
        */
#if 0
        if (options->get_key_file[0] != 0x0)
        {
            key = getpasswd_file(options->get_key_file, options->spa_server_str);
        }
        else
        {
#endif
        strlcpy(hmac_key, getpasswd("Enter HMAC key: "), MAX_KEY_LEN+1);
        *hmac_key_len = strlen(hmac_key);
        use_hmac = 1;
    }

    if (use_hmac)
    {
        res = fko_set_hmac_type(ctx, options->hmac_type);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_hmac_type", res);
            exit(EXIT_FAILURE);
        }
    }

    return;
}

/* Display an FKO error message.
*/
void
errmsg(const char *msg, const int err) {
    fprintf(stderr, "%s: %s: Error %i - %s\n",
        MY_NAME, msg, err, fko_errstr(err));
}

/* free up memory and exit
*/
static void
clean_exit(fko_ctx_t ctx, fko_cli_options_t *opts, unsigned int exit_status)
{
    free_configs(opts);
    fko_destroy(ctx);
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

    time_t      timestamp       = 0;
    short       msg_type        = -1;
    short       digest_type     = -1;
    short       hmac_type       = -1;
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
    fko_get_spa_encryption_mode(ctx, &encryption_mode);
    fko_get_encoded_data(ctx, &enc_data);
    fko_get_hmac_data(ctx, &hmac_data);
    fko_get_spa_digest(ctx, &spa_digest);
    fko_get_spa_data(ctx, &spa_data);

    printf("\nFKO Field Values:\n=================\n\n");
    printf("   Random Value: %s\n", rand_val == NULL ? "<NULL>" : rand_val);
    printf("       Username: %s\n", username == NULL ? "<NULL>" : username);
    printf("      Timestamp: %u\n", (unsigned int) timestamp);
    printf("    FKO Version: %s\n", version == NULL ? "<NULL>" : version);
    printf("   Message Type: %i\n", msg_type);
    printf(" Message String: %s\n", spa_message == NULL ? "<NULL>" : spa_message);
    printf("     Nat Access: %s\n", nat_access == NULL ? "<NULL>" : nat_access);
    printf("    Server Auth: %s\n", server_auth == NULL ? "<NULL>" : server_auth);
    printf(" Client Timeout: %u\n", client_timeout);
    printf("    Digest Type: %d (%s)\n", digest_type, digest_inttostr(digest_type));
    printf("      HMAC Type: %d (%s)\n", hmac_type, digest_inttostr(hmac_type));
    printf("Encryption Mode: %d\n", encryption_mode);
    printf("\n   Encoded Data: %s\n", enc_data == NULL ? "<NULL>" : enc_data);
    printf("SPA Data Digest: %s\n", spa_digest == NULL ? "<NULL>" : spa_digest);
    printf("           HMAC: %s\n", hmac_data == NULL ? "<NULL>" : hmac_data);

    if (enc_data != NULL && spa_digest != NULL)
        printf("      Plaintext: %s:%s\n", enc_data, spa_digest);

    printf("\nFinal Packed/Encrypted/Encoded Data:\n\n%s\n\n", spa_data);
}

/***EOF***/
