/* $Id$
 *****************************************************************************
 *
 * File:    base64.c
 *
 * Purpose: Implementation of the Base64 encode/decode algorithim.
 *
 * This code was derived from the base64.c part of FFmpeg written
 * by Ryan Martell. (rdm4@martellventures.com).
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
#include "base64.h"

static uchar map2[] =
{
    0x3e, 0xff, 0xff, 0xff, 0x3f, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
    0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33
};

int
b64_decode(char *in, uchar *out, int out_len)
{
    int i, v;
    uchar *dst = out;

    v = 0;
    for (i = 0; in[i] && in[i] != '='; i++) {
        unsigned int index= in[i]-43;

        if (index>=(sizeof(map2)/sizeof(map2[0])) || map2[index] == 0xff)
            return(-1);

        v = (v << 6) + map2[index];

        if (i & 3)
            *dst++ = v >> (6 - 2 * (i & 3));
    }

    *dst = '\0';

    return(dst - out);
}

/*****************************************************************************
 * b64_encode: Stolen from VLC's http.c
 * Simplified by michael
 * fixed edge cases and made it work from data (vs. strings) by ryan.
 *****************************************************************************
*/
int
b64_encode(uchar *in, char *out, int in_len)
{
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned i_bits = 0;
    int i_shift = 0;
    int bytes_remaining = in_len;

    char *dst = out;

    if (in_len) { /* Special edge case, what should we really do here? */
        while (bytes_remaining) {
            i_bits = (i_bits << 8) + *in++;
            bytes_remaining--;
            i_shift += 8;

            do {
                *dst++ = b64[(i_bits << 6 >> i_shift) & 0x3f];
                i_shift -= 6;
            } while (i_shift > 6 || (bytes_remaining == 0 && i_shift > 0));
        }
        while ((dst - out) & 3)
            *dst++ = '=';
    }
    *dst = '\0';

    return(dst - out);
}

/* Strip trailing equals ("=") charcters from a base64-encode
 * message digest.
*/
void
strip_b64_eq(char *data)
{
    char *ndx;

    if((ndx = strchr(data, '=')) != NULL)
        *ndx = '\0';
}

/***EOF***/
