/*
 *****************************************************************************
 *
 * File:    fwknop_client.c
 *
 * Purpose: An implementation of an fwknop client for Android.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
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
#include <jni.h>

#include "fwknop_client.h"
#include "fko.h"

/* Format error message.
 */
char *
fko_errmsg(char *msg, int res) {
    static char err_msg[MSG_BUFSIZE+1] = {0};
    snprintf(err_msg, MSG_BUFSIZE, "Error: %s: %s", msg, fko_errstr(res));
    return(err_msg);
}

/* JNI interface: constructs arguments and calls main function
*/
jstring Java_com_max2idea_android_fwknop_Fwknop_sendSPAPacket(JNIEnv* env,
        jobject thiz)
{
    fko_ctx_t ctx;
    fwknop_options_t opts;

    int res, hmac_str_len = 0;
    char res_msg[MSG_BUFSIZE+1] = {0};
    char spa_msg[MSG_BUFSIZE+1] = {0};

    LOGV("**** Init fwknop ****");

    memset(&opts, 0, sizeof(fwknop_options_t));

    /* Read the member values from the Java Object that called sendSPAPacket() method
    */
    jclass c = (*env)->GetObjectClass(env, thiz);
    jfieldID fid = (*env)->GetFieldID(env, c, "access_str", "Ljava/lang/String;");
    jstring jaccess = (*env)->GetObjectField(env, thiz, fid);
    const char *access_str = (*env)->GetStringUTFChars(env, jaccess, 0);

    fid = (*env)->GetFieldID(env, c, "allowip_str", "Ljava/lang/String;");
    jstring jallowip = (*env)->GetObjectField(env, thiz, fid);
    const char *allowip_str = (*env)->GetStringUTFChars(env, jallowip, 0);

    fid = (*env)->GetFieldID(env, c, "destip_str", "Ljava/lang/String;");
    jstring jdestip = (*env)->GetObjectField(env, thiz, fid);
    const char *destip_str = (*env)->GetStringUTFChars(env, jdestip, 0);

    fid = (*env)->GetFieldID(env, c, "passwd_str", "Ljava/lang/String;");
    jstring jpasswd = (*env)->GetObjectField(env, thiz, fid);
    const char *passwd_str = (*env)->GetStringUTFChars(env, jpasswd, 0);

    fid = (*env)->GetFieldID(env, c, "hmac_str", "Ljava/lang/String;");
    jstring jhmac = (*env)->GetObjectField(env, thiz, fid);
    const char *hmac_str = (*env)->GetStringUTFChars(env, jhmac, 0);

    fid = (*env)->GetFieldID(env, c, "fw_timeout_str", "Ljava/lang/String;");
    jstring jfwtimeout = (*env)->GetObjectField(env, thiz, fid);
    const char *fw_timeout_str = (*env)->GetStringUTFChars(env, jfwtimeout, 0);

    /* Sanity checks
    */
    if(access_str == NULL) {
        sprintf(res_msg, "Error: Invalid or missing access string");
        goto cleanup2;
    }
    if(allowip_str == NULL) {
        sprintf(res_msg, "Error: Invalid or missing allow IP");
        goto cleanup2;
    }
    if(destip_str == NULL) {
        sprintf(res_msg, "Error: Invalid or missing destination IP");
        goto cleanup2;
    }
    if(passwd_str == NULL) {
        sprintf(res_msg, "Error: Invalid or missing password");
        goto cleanup2;
    }
    if(fw_timeout_str == NULL) {
        sprintf(res_msg, "Error: Invalid or missing firewall timeout value");
        goto cleanup2;
    }

    /* Using an HMAC is optional (currently)
    */
    if(hmac_str != NULL) {
        hmac_str_len = (int)strlen(hmac_str);
    }

    /* Set our spa server info
    */
    opts.spa_server_str = (char*)destip_str;
    opts.spa_dst_port   = FKO_DEFAULT_PORT; /* Until we make this settable. */

    /* Intialize the context
    */
    res = fko_new(&ctx);
    if (res != FKO_SUCCESS) {
        strcpy(res_msg, fko_errmsg("Unable to create FKO context", res));
        goto cleanup2;
    }

    /* Set client timeout
    */
    res = fko_set_spa_client_timeout(ctx, atoi(fw_timeout_str));
    if (res != FKO_SUCCESS) {
        strcpy(res_msg, fko_errmsg("Error setting FW timeout", res));
        goto cleanup;
    }

    /* Set the spa message string
    */
    snprintf(spa_msg, MSG_BUFSIZE, "%s,%s", allowip_str, access_str);

    res = fko_set_spa_message(ctx, spa_msg);
    if (res != FKO_SUCCESS) {
        strcpy(res_msg, fko_errmsg("Error setting SPA request message", res));
        goto cleanup;
    }

    /* Set the HMAC mode if necessary
    */
    if (hmac_str_len > 0) {
        res = fko_set_spa_hmac_type(ctx, FKO_DEFAULT_HMAC_MODE);
        if (res != FKO_SUCCESS) {
            strcpy(res_msg, fko_errmsg("Error setting SPA HMAC type", res));
            goto cleanup;
        }
    }

    /* Finalize the context data (Encrypt and encode).
    */
    res = fko_spa_data_final(ctx, (char*)passwd_str,
            (int)strlen(passwd_str), (char *)hmac_str, hmac_str_len);
    if (res != FKO_SUCCESS) {
        strcpy(res_msg, fko_errmsg("Error generating SPA data", res));
        goto cleanup;
    }

    res = fko_get_spa_data(ctx, &opts.spa_data);
    if (res != FKO_SUCCESS) {
        strcpy(res_msg, fko_errmsg("Error getting SPA data", res));
        goto cleanup;
    }

    /* --DSS NOTE:  At this point, we could just return the SPA data
     *              to the caller and use the Java network libs to send
     *              the packet and eliminate the spa_comm code altogether.
    */

    /* Send the spa data packet
    */
    res = send_spa_packet(&opts);

    if (res < 0) {
        sprintf(res_msg, "Error: send_spa_packet: packet not sent.");
    } else if (res == 0) {
        sprintf(res_msg, "Error: send_spa_packet: Empty packet sent.");
    } else {
        sprintf(res_msg, "SPA Packet sent successfully.");
    }

cleanup:
    /* Release the resources used by the fko context.
    */
    fko_destroy(ctx);

cleanup2:
    /* Release mem
    */
    (*env)->ReleaseStringUTFChars(env, jaccess, access_str);
    (*env)->ReleaseStringUTFChars(env, jallowip, allowip_str);
    (*env)->ReleaseStringUTFChars(env, jdestip, destip_str);
    (*env)->ReleaseStringUTFChars(env, jpasswd, passwd_str);
    (*env)->ReleaseStringUTFChars(env, jhmac, hmac_str);
    (*env)->ReleaseStringUTFChars(env, jfwtimeout, fw_timeout_str);

    /* Log and return a string of success or error message.
     * This can be enhanced semantically with codes.
    */
    LOGV("%s", res_msg);

    return (*env)->NewStringUTF(env, res_msg);
}

/***EOF***/
