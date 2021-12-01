#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <mbedtls/net_sockets.h>
#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>

// ----------------------------------------------------------------------

MODULE = Net::mbedTLS        PACKAGE = Net::mbedTLS

PROTOTYPES: DISABLE

UV
mbedtls_version_get_number()
    CODE:
        RETVAL = (UV) mbedtls_version_get_number();

    OUTPUT:
        RETVAL

char*
mbedtls_version_get_string()
    CODE:
        // Per docs, this should be at least 9 bytes:
        char versionstr[20] = { NULL };
        (UV) mbedtls_version_get_string(versionstr);

        RETVAL = versionstr;
    OUTPUT:
        RETVAL
