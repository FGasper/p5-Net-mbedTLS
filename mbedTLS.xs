#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <stdbool.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>

#define _MBEDTLS_PREFIX_LEN strlen("MBEDTLS_")

#define _MBEDTLS_XS_CONSTANT(name) \
    newCONSTSUB(gv_stashpv("$Package", FALSE), _MBEDTLS_PREFIX_LEN + #name, newSViv(name))

typedef struct {
#ifdef MULTIPLICITY
    pTHX;
#endif
    pid_t pid;

    mbedtls_net_context net_context;

    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;

    bool notify_closed;

    SV* perl_mbedtls;
    SV* perl_filehandle;
} xs_peer;

typedef struct {
    pid_t pid;

    mbedtls_x509_crt cacert;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
} xs_config;

#define _MBEDTLS_ERR_CROAK(msg, ret) STMT_START { \
    char err[200];                                      \
    mbedtls_strerror(ret, err, sizeof(err));            \
    SV* errsv = newSVpvf("mbedTLS error (%s): %s", msg, err); \
    croak_sv(errsv);                                    \
} STMT_END

// ----------------------------------------------------------------------

static inline void _verify_io_retval(pTHX_ int retval, const char* msg) {
    if (retval < 0) {
        switch (retval) {
            case MBEDTLS_ERR_SSL_WANT_READ:
            case MBEDTLS_ERR_SSL_WANT_WRITE:
            case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
            case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
            case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
                break;

            default: {
                dTHX;
                _MBEDTLS_ERR_CROAK(msg, retval);
            }
        }
    }
}

// ----------------------------------------------------------------------

MODULE = Net::mbedTLS        PACKAGE = Net::mbedTLS

PROTOTYPES: DISABLE

BOOT:
    _MBEDTLS_XS_CONSTANT(MBEDTLS_ERR_SSL_WANT_READ);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_ERR_SSL_WANT_WRITE);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_ERR_SSL_CLIENT_RECONNECT);

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

SV*
_new(SV* classname, SV* chain_path = NULL)
    CODE:
        mbedtls_debug_set_threshold(4);
        int ret;

        SV* referent = newSV(sizeof( xs_config));
        sv_2mortal(referent);

        xs_config* myconfig = (xs_config*) SvPVX(referent);

        mbedtls_x509_crt_init( &myconfig->cacert );

        ret = mbedtls_x509_crt_parse_file(&myconfig->cacert, SvPVbyte_nolen(chain_path));

        if (ret) {
            mbedtls_x509_crt_free( &myconfig->cacert );

            _MBEDTLS_ERR_CROAK("Failed to read CA chain file", ret);
        }

        mbedtls_ctr_drbg_init( &myconfig->ctr_drbg );
        mbedtls_entropy_init( &myconfig->entropy );

        // At this point myconfig is all set up. Any further failures
        // require cleanup identical to the normal object DESTROY, so
        // we might as well reuse that logic.
        RETVAL = newRV_inc(referent);
        sv_bless(RETVAL, gv_stashpv(SvPVbyte_nolen(classname), FALSE));

        ret = mbedtls_ctr_drbg_seed(
            &myconfig->ctr_drbg,
            mbedtls_entropy_func,
            &myconfig->entropy,
            NULL, 0
        );

        if (ret) {
            _MBEDTLS_ERR_CROAK("Failed to seed random-number generator", ret);
        }

    OUTPUT:
        RETVAL

void
DESTROY(SV* self_obj)
    CODE:
        xs_config* myconfig = (xs_config*) SvPVX( SvRV(self_obj) );

        mbedtls_x509_crt_free( &myconfig->cacert );
        mbedtls_ctr_drbg_free( &myconfig->ctr_drbg );
        mbedtls_entropy_free( &myconfig->entropy );

        //fprintf(stderr, "DESTROY Net::mbedTLS %" SVf "\n", self_obj);

# ----------------------------------------------------------------------

MODULE = Net::mbedTLS   PACKAGE = Net::mbedTLS::Peer

int
shake_hands(SV* peer_obj)
    CODE:
        xs_peer* mypeer = (xs_peer*) SvPVX( SvRV(peer_obj) );

        RETVAL = mbedtls_ssl_handshake( &mypeer->ssl );

        _verify_io_retval(aTHX_ RETVAL, "handshake");

    OUTPUT:
        RETVAL

int
write(SV* peer_obj, SV* bytes_sv)
    CODE:
        xs_peer* mypeer = (xs_peer*) SvPVX( SvRV(peer_obj) );

        STRLEN outputlen;
        const char* output = SvPVbyte(bytes_sv, outputlen);

        RETVAL = mbedtls_ssl_write(
            &mypeer->ssl,
            output,
            outputlen
        );

        _verify_io_retval(aTHX_ RETVAL, "write");

    OUTPUT:
        RETVAL

int
read(SV* peer_obj, SV* output_sv)
    CODE:
        xs_peer* mypeer = (xs_peer*) SvPVX( SvRV(peer_obj) );

        const char* output = SvPVX(output_sv);

        STRLEN outputlen = SvCUR(output_sv);

        RETVAL = mbedtls_ssl_read(
            &mypeer->ssl,
            output,
            outputlen
        );

        if (RETVAL == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            mypeer->notify_closed = true;

            RETVAL = 0;
        }
        else {
            _verify_io_retval(aTHX_ RETVAL, "read");
        }

    OUTPUT:
        RETVAL

bool
closed(SV* peer_obj)
    CODE:
        xs_peer* mypeer = (xs_peer*) SvPVX( SvRV(peer_obj) );

        RETVAL = mypeer->notify_closed;

    OUTPUT:
        RETVAL

void
DESTROY(SV* peer_obj)
    CODE:
        xs_peer* mypeer = (xs_peer*) SvPVX( SvRV(peer_obj) );

        mbedtls_ssl_config_free( &mypeer->conf );
        mbedtls_ssl_free( &mypeer->ssl );

        SvREFCNT_dec(mypeer->perl_mbedtls);
        SvREFCNT_dec(mypeer->perl_filehandle);

# ----------------------------------------------------------------------

MODULE = Net::mbedTLS   PACKAGE = Net::mbedTLS::Client

SV*
_new(const char* classname, SV* mbedtls_obj, SV* filehandle, int fd, SV* servername_sv = NULL)
    CODE:
        int ret;

        const char* servername = servername_sv ? SvPVbyte_nolen(servername_sv) : "";

        xs_config* myconfig = (xs_config*) SvPVX( SvRV(mbedtls_obj) );

        SV* referent = newSV(sizeof(xs_peer));
        sv_2mortal(referent);

        xs_peer* mypeer = (xs_peer*) SvPVX(referent);
        *mypeer = (xs_peer) {
            .net_context = {
                .fd = fd,
            },
#ifdef MULTIPLICITY
            .aTHX = aTHX,
#endif
        };

        mbedtls_ssl_config_init( &mypeer->conf );

        ret = mbedtls_ssl_config_defaults(
            &mypeer->conf,
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT
        );

        if (ret) {
            mbedtls_ssl_config_free( &mypeer->conf );

            _MBEDTLS_ERR_CROAK("Failed to set up config", ret);
        }

        mbedtls_ssl_conf_ca_chain( &mypeer->conf, &myconfig->cacert, NULL );
        mbedtls_ssl_conf_rng( &mypeer->conf, mbedtls_ctr_drbg_random, &myconfig->ctr_drbg );

        mbedtls_ssl_init( &mypeer->ssl );

        ret = mbedtls_ssl_setup( &mypeer->ssl, &mypeer->conf );

        if (ret) {
            mbedtls_ssl_config_free( &mypeer->conf );
            mbedtls_ssl_free( &mypeer->ssl );

            _MBEDTLS_ERR_CROAK("Failed to set up config", ret);
        }

        // Beyond here cleanup is identical to normal DESTROY:
        RETVAL = newRV_inc(referent);
        sv_bless(RETVAL, gv_stashpv(classname, FALSE));

        mypeer->perl_mbedtls = SvREFCNT_inc(mbedtls_obj);
        mypeer->perl_filehandle = SvREFCNT_inc(filehandle);

        ret = mbedtls_ssl_set_hostname(&mypeer->ssl, servername);

        if (ret) {
            _MBEDTLS_ERR_CROAK("Failed to set server hostname", ret);
        }

        mbedtls_ssl_set_bio(
            &mypeer->ssl,
            &mypeer->net_context,
            mbedtls_net_send,
            mbedtls_net_recv,
            mbedtls_net_recv_timeout
        );

    OUTPUT:
        RETVAL
