#ifndef __TOTP_H__
#define __TOTP_H__

// libfko imports
#include "fko.h"
#include "fko_common.h"
#include "hmac.h"

// others
#include <math.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define TOTP_SECRET_LEN 20
#define HMAC_LENGTH 20
#define TIME_LEN 8
#define DIGITS 6 // OTP digits
#define X 30 // default time step
#define T0 0 // default value

#endif /* __TOTP_H__ */