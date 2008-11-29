/* $Id$
 *****************************************************************************
 *
 * File:    fwknop.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Header for the fwknop source files
 *
 * Copyright (C) 2008 Damien Stuart (dstuart@dstuart.org)
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
#ifndef _FWKNOP_H_
#define _FWKNOP_H_

#define _XOPEN_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

/* General params
*/
#define FWKNOP_VERSION      "1.9.10-pre1"   /* The fwknop client version # */
#define VERSION_LENGTH      11              /* Length of the version string */

#define MIN_PORT            10000
#define MAX_PORT            65535

#define ENC_KEYSIZE         16              /* RIJNDAEL Key Size */

/* For random string generation.
*/
#define RAND_VAL_SIZE       16
#define RAND_FILE           "/dev/urandom"
#define RAND_MASK           0xFFFF

#define TIMESTAMP_SIZE      10

#define MAX_USER_SIZE           32
#define MAX_MESSAGE_SIZE        128
#define MAX_NAT_ACCESS_SIZE     128
#define MAX_SERVER_AUTH_SIZE    128
#define MAX_DIGEST_SIZE         128

/* SPA Message types...
*/
enum {
    SPA_COMMAND_MODE,
    SPA_ACCESS_MODE,
    SPA_NAT_ACCESS_MODE,
    SPA_CLIENT_TIMEOUT_ACCESS_MODE,
    SPA_CLIENT_TIMEOUT_NAT_ACCESS_MODE,
    SPA_LOCAL_NAT_ACCESS_MODE,
    SPA_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MODE
};

/* Digest types...
*/
enum {
    MD5_DIGEST,
    SHA1_DIGEST,
    SHA256_DIGEST
};

/* General Defaults
*/
#define DEFAULT_USER    "root"
#define DEFAULT_PORT    62201
#define DEFAULT_DIGEST  SHA256_DIGEST
#define KNOCK_INTERVAL  60

/* The pieces we need to make a SPA packet.
*/
typedef struct _spa_message {
    unsigned short  digest_type;
    unsigned short  enc_pcap_port;
    char            rand_val[RAND_VAL_SIZE+1];
    char            user[MAX_USER_SIZE];
    unsigned int    timestamp;
    char            version[VERSION_LENGTH+1];
    unsigned short  message_type;
    char            message[MAX_MESSAGE_SIZE];
    char            nat_access[MAX_NAT_ACCESS_SIZE];
    char            server_auth[MAX_SERVER_AUTH_SIZE];
    unsigned int    client_timeout;
    char            digest[MAX_DIGEST_SIZE];
} spa_message_t;

/* Function prototypes
*/
char* spa_random_number(spa_message_t *sm);
char* spa_user(spa_message_t *sm, char *spoof_user);
unsigned int spa_timestamp(spa_message_t *sm, int offset);
char* spa_version(spa_message_t *sm);
unsigned short spa_message_type(spa_message_t *sm);
char* spa_message(spa_message_t *sm);
char* spa_nat_access(spa_message_t *sm);
char* spa_server_auth(spa_message_t *sm);
unsigned int spa_client_timeout(spa_message_t *sm);
char* spa_digest(spa_message_t *sm);

size_t strlcat(char *dst, const char *src, size_t siz);
size_t strlcpy(char *dst, const char *src, size_t siz);

#endif /* _FWKNOP_H_ */

/***EOF***/
