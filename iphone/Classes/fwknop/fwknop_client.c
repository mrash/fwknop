/*
 *****************************************************************************
 *
 * File:    fwknop_client.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: An implementation of an fwknop client for Android.
 *
 * Copyright (C) 2010 Damien Stuart (dstuart@dstuart.org)
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
//#include <jni.h>

#include "fwknop_client.h"
#include "fko.h"

/* Format error message.
 */
char *
fko_errmsg(char *msg, int res) {
    static char err_msg[MSG_BUFSIZE+1] = {0};
    snprintf(err_msg, MSG_BUFSIZE, "Error: %s: %i", msg, fko_errstr(res));
    return(err_msg);
}

/* JNI interface: constructs arguments and calls main function
*/
int fwknop_sendSPAPacket(
const char *allowip_str,
const char *access_str,						 
const char *destip_str,
const char *passwd_str,
const char *fw_timeout_str					 
)
{
    fko_ctx_t ctx;
    fwknop_options_t opts;

    int res;
    char res_msg[MSG_BUFSIZE+1] = {0};
    char spa_msg[MSG_BUFSIZE+1] = {0};

    printf("**** Init fwknop ****\n");

    memset(&opts, 0, sizeof(fwknop_options_t));
    

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

    /* Finalize the context data (Encrypt and encode).
    */
    res = fko_spa_data_final(ctx, (char*)passwd_str);
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

    /* Log and return a string of success or error message.
     * This can be enhanced semantically with codes.
    */
	printf("%s\n", res_msg);
	
	printf("**** Closing fwknop ****\n");
    return res; // (*env)->NewStringUTF(env, res_msg);
}

/***EOF***/
