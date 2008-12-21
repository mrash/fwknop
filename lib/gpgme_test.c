/* GPGME test program
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gpgme.h>


void hex_dump(unsigned char *data, int size)
{
    int ln, i, j = 0;
    char ascii_str[17] = {0};

    for(i=0; i<size; i++)
    {
        if((i % 16) == 0)
        {
            printf(" %s\n  0x%.4x:  ", ascii_str, i);
            memset(ascii_str, 0x0, 17);
            j = 0;
        }

        printf("%.2x ", data[i]);

        ascii_str[j++] = (data[i] < 0x20 || data[i] > 0x7e) ? '.' : data[i];

        if(j == 8)
            printf(" ");
    }

    /* Remainder...
    */
    ln = strlen(ascii_str);
    if(ln > 0)
    {
        for(i=0; i < 16-ln; i++)
            printf("   ");

        printf(" %s\n\n", ascii_str);
    }
}

err_out(const char *msg, gpgme_error_t err)
{
    fprintf(stderr, "*Error from %s (%s): %s.\n",
        msg, gpgme_strsource(err), gpgme_strerror(err));

    exit(-1);
}

int main(int argc, char **argv)
{
    gpgme_ctx_t     ctx;
    gpgme_error_t   err;
    gpgme_key_t     key[2] = {0};
    gpgme_key_t     mykey = NULL;
    gpgme_data_t    data;
    gpgme_data_t    plaintext;
    gpgme_engine_info_t enginfo;

    const char *indata = "This is a DSS test. 1234567890.";

    /* Because the manual says you should.  */
    char *tp = (char*) gpgme_check_version(NULL);

    printf("GPGME Version: %s\n", tp);

    /* Check for OpenPGP support */
    err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
        err_out("gpgme_engine_check_version", err);

    tp = (char*) gpgme_get_protocol_name(GPGME_PROTOCOL_OpenPGP);

    printf("Protocol: %s\n", tp);

    /* Retrieve engine information */
    err = gpgme_get_engine_info(&enginfo);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
        err_out("gpgme_get_engine_info", err);

    printf("File: %s, Home: %s\n", enginfo->file_name, enginfo->home_dir);

    /* Create our context */
    err = gpgme_new(&ctx);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
        err_out("gpgme_new", err);

    /* Initialize the plaintext data (place into gpgme_data object) */
    err = gpgme_data_new_from_mem(&plaintext, indata, strlen(indata), 1);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
        err_out("gpgme_data_new_from_mem", err);

    fprintf(stderr, "+Created GPGME context+\n");

    /* Set protocol */
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);

    /* Set engine for this context. */
    err = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP,
            enginfo->file_name, enginfo->home_dir);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
        err_out("gpgme_set_engin_info", err);

    /* Set ascii-armor */
    gpgme_set_armor(ctx, 0);

    /* Key to use for encrypting and signing */
    err = gpgme_op_keylist_start(ctx, "dstuart", 0);

    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
        err_out("gpgme_op_keylist_start", err);
    //while(!err)
    //{
        err = gpgme_op_keylist_next(ctx, &mykey);

    //    if(err)
    //        break;
    //
        //gpgme_key_release(mykey);
        
        gpgme_op_keylist_end(ctx);

        //hex_dump(&mykey, 1024);

        printf("Got Key:\n%s: %s <%s>\n", mykey->subkeys->keyid, mykey->uids->name, mykey->uids->email);
    //}

    //err = gpgme_get_key(ctx, mykey->uids->uid, &key[0], 0);
    //if(gpg_err_code("gpgme_get_key", err) != GPG_ERR_NO_ERROR)
    //    err_out(err);


    key[0] = mykey;

    //if(gpg_err_code(err) != GPG_ERR_EOF)
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
        err_out("gpgme_op_keylist_next", err);

    err = gpgme_data_new(&data);

    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
        err_out("gpgme_data_new(#2)", err);

    //err = gpgme_data_set_encoding(data, GPGME_DATA_ENCODING_BASE64);
    //if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    //    err_out("gpgme_data_set_encoding", err);

    err = gpgme_op_encrypt(ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, plaintext, data);

    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
        err_out("gpgme_op_encrypt", err);


    size_t ilen, olen;
    
    //char* in = gpgme_data_release_and_get_mem(plaintext, &ilen);
    char* out = gpgme_data_release_and_get_mem(data, &olen);

    char tmp_buf[4096] = {0};
    //printf("ILEN: %i\n", ilen);
    //hex_dump((unsigned char*)in, ilen);
    printf("OLEN: %i\n", olen);
    //strncpy(tmp_buf, out, olen);
    hex_dump((unsigned char*)out, olen);
    //printf("\n%s\n\n", tmp_buf);


    //char buf[1024];
    //size_t nread = 0;
    //while((nread = gpgme_data_read(data, buf, sizeof(buf))))
    //{
    //    printf("NREAD: %i\n", nread);
    //    hex_dump((unsigned char*)buf, nread);
   // }


    gpgme_release(ctx);

    return(0);
}

/***EOF***/
