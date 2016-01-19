/**
 * \file lib/sha3.h
 *
 * \brief header file for SHA3 routines
 */



#define SHA3_256_DIGEST_LEN 32
#define SHA3_512_DIGEST_LEN 64
#define SHA3_256_BLOCK_LEN 136
#define SHA3_512_BLOCK_LEN 72
#define SHA3_256_B64_LEN      43
#define SHA3_512_B64_LEN      86
#define SHA3_256_DIGEST_STR_LEN   (SHA3_256_DIGEST_LEN * 2 + 1)
#define SHA3_512_DIGEST_STR_LEN   (SHA3_512_DIGEST_LEN * 2 + 1)

void Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen);

/**
  * \brief Function to compute SHAKE128 on the input message with any output length.
  *
  *  Not currently in use
void FIPS202_SHAKE128(const unsigned char *input, unsigned int inputByteLen, unsigned char *output, int outputByteLen);
*/

/**
  * \brief Function to compute SHAKE256 on the input message with any output length.
  *
  *  Not currently in use
void FIPS202_SHAKE256(const unsigned char *input, unsigned int inputByteLen, unsigned char *output, int outputByteLen);
*/

/**
  * \brief Function to compute SHA3-224 on the input message. The output length is fixed to 28 bytes.
void FIPS202_SHA3_224(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);
*/

/**
  * \brief Function to compute SHA3-256 on the input message. The output length is fixed to 32 bytes.
  */
void FIPS202_SHA3_256(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);

/**
  * \brief Function to compute SHA3-384 on the input message. The output length is fixed to 48 bytes.
void FIPS202_SHA3_384(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);
*/

/**
  * \brief Function to compute SHA3-512 on the input message. The output length is fixed to 64 bytes.
  */
void FIPS202_SHA3_512(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);
