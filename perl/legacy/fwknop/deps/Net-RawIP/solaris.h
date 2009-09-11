/*
 * Some stuff to make Solaris look a little like Linux for compiling
 */

/*
 * Setup __LITTLE_ENDIAN, __BIG_ENDIAN, and __BYTE_ORDER
 */

#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN    4321

#if defined(_BIG_ENDIAN)
   #define __BYTE_ORDER __BIG_ENDIAN
#else
   #define __BYTE_ORDER __LITTLE_ENDIAN
#endif


#include <sys/int_types.h>

/*
 * Some types
 */

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

