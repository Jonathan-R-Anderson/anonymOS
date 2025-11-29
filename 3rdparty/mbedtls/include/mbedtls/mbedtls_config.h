/* Minimal mbedTLS configuration for freestanding kernel */

/* System support */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS

/* Crypto primitives */
#define MBEDTLS_AES_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_MD_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C

/* Public key crypto */
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C

/* X.509 */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

/* TLS */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2

/* Ciphersuites */
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_PKCS1_V15

/* Disable filesystem */
#undef MBEDTLS_FS_IO

/* Disable threading */
#undef MBEDTLS_THREADING_C

/* Disable time */
#undef MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME_DATE

/* Disable dynamic allocation (we'll provide custom allocator) */
#define MBEDTLS_PLATFORM_STD_CALLOC   kernel_calloc
#define MBEDTLS_PLATFORM_STD_FREE     kernel_free

