#pragma clang diagnostic ignored "-Wcompound-token-split-by-macro"

#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <stdbool.h>
#include <assert.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>
#include <mbedtls/x509.h>

#ifdef NET_CONTEXT_FD_IS_PUBLIC
#define NET_CONTEXT_FD_MEMBER fd
#else
#include <mbedtls/private_access.h>
#define NET_CONTEXT_FD_MEMBER MBEDTLS_PRIVATE(fd)
#endif

#ifdef X509_CRT_RAW_IS_PUBLIC
#define X509_CRT_RAW_MEMBER raw
#else
#include <mbedtls/private_access.h>
#define X509_CRT_RAW_MEMBER MBEDTLS_PRIVATE(raw)
#endif

#ifdef X509_ASN1_P_IS_PUBLIC
#define X509_ASN1_P_MEMBER p
#else
#include <mbedtls/private_access.h>
#define X509_ASN1_P_MEMBER MBEDTLS_PRIVATE(p)
#endif

#ifdef X509_ASN1_LEN_IS_PUBLIC
#define X509_ASN1_LEN_MEMBER len
#else
#include <mbedtls/private_access.h>
#define X509_ASN1_LEN_MEMBER MBEDTLS_PRIVATE(len)
#endif

#define CERT_PEM_STRING 1
#define CERT_PEM_PATH 2

#define _MBEDTLS_PREFIX_LEN strlen("MBEDTLS_")

#define _XS_CONSTANT(name, value) \
    newCONSTSUB(gv_stashpv("$Package", FALSE), name, value)

#define _MBEDTLS_XS_CONSTANT(name) \
    _XS_CONSTANT(&#name[_MBEDTLS_PREFIX_LEN], newSViv(name))

#define _NET_MBEDTLS_XS_CONSTANT(name) \
    _XS_CONSTANT(#name, newSViv(name))

// ----------------------------------------------------------------------
#define _XS_CONNECTION_PARTS \
    pid_t pid;                          \
                                        \
    mbedtls_net_context net_context;    \
                                        \
    mbedtls_ssl_config conf;            \
    mbedtls_ssl_context ssl;            \
                                        \
    bool notify_closed;                 \
                                        \
    SV* perl_mbedtls;                   \
    SV* perl_filehandle;                \
                                        \
    int error;

// ----------------------------------------------------------------------

typedef struct {
    pTHX;
    _XS_CONNECTION_PARTS
} xs_connection;

typedef xs_connection xs_client;

typedef struct {
    pTHX;
    _XS_CONNECTION_PARTS

    SV* sni_cb;

    mbedtls_pk_context  pkey;
    mbedtls_x509_crt    crt;
} xs_server;

typedef struct {
    pid_t pid;

    mbedtls_x509_crt cacert;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    SV* trust_store_path_sv;
    bool trust_store_loaded;
} xs_mbedtls;

#define _warn_if_global_destruct(self_obj, mystruct) \
    if (PL_dirty && (mystruct->pid == getpid())) \
        warn("%s survived until global destruction!", SvPV_nolen(self_obj));

#define _ERROR_FACTORY_CLASS "Net::mbedTLS" "::X"

#define TRUST_STORE_MODULE "Mozilla::CA"
#define TRUST_STORE_PATH_FUNCTION (TRUST_STORE_MODULE "::SSL_ca_file")

// ----------------------------------------------------------------------

static inline void _mbedtls_err_croak( pTHX_ const char* action, int errnum ) {
    dSP;

    char errstr[200];
    mbedtls_strerror(errnum, errstr, sizeof(errstr));

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    EXTEND(SP, 5);

    mPUSHs( newSVpvs(_ERROR_FACTORY_CLASS) );
    mPUSHs( newSVpvs("mbedTLS") );
    mPUSHs( newSVpv(action, 0) );
    mPUSHi(errnum);
    mPUSHs( newSVpv(errstr, 0) );
    PUTBACK;

    int retcount = call_method("create", G_SCALAR);

    SPAGAIN;

    SV* err = retcount ? SvREFCNT_inc(POPs) : NULL;

    FREETMPS;
    LEAVE;

    if (err) croak_sv(err);

    croak("Huh?? %s->%s() didn’t give anything?", _ERROR_FACTORY_CLASS, "create");
}

SV* _set_up_connection_object(pTHX_ xs_mbedtls* myconfig, size_t struct_size, const char* classname, int endpoint_type, SV* mbedtls_obj, SV* filehandle, int fd) {
    SV* referent = newSV(struct_size);
    sv_2mortal(referent);

    xs_connection* myconn = (xs_connection*) SvPVX(referent);

    *myconn = (xs_connection) {
        .net_context = {
            .NET_CONTEXT_FD_MEMBER = fd,
        },

        .pid = getpid(),
        .error = 0,

#ifdef MULTIPLICITY
        .aTHX = aTHX,
#endif
    };

    mbedtls_ssl_config_init( &myconn->conf );

    int result = mbedtls_ssl_config_defaults(
        &myconn->conf,
        endpoint_type,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );

    if (result) {
        mbedtls_ssl_config_free( &myconn->conf );

        _mbedtls_err_croak(aTHX_ "set up config", result);
    }

    mbedtls_ssl_conf_rng( &myconn->conf, mbedtls_ctr_drbg_random, &myconfig->ctr_drbg );

    mbedtls_ssl_init( &myconn->ssl );

    result = mbedtls_ssl_setup( &myconn->ssl, &myconn->conf );

    if (result) {
        mbedtls_ssl_config_free( &myconn->conf );
        mbedtls_ssl_free( &myconn->ssl );

        _mbedtls_err_croak(aTHX_ "set up TLS", result);
    }

    // Beyond here cleanup is identical to normal DESTROY:
    SV* ret = newRV_inc(referent);
    sv_bless(ret, gv_stashpv(classname, FALSE));

    myconn->perl_mbedtls = SvREFCNT_inc(mbedtls_obj);
    myconn->perl_filehandle = SvREFCNT_inc(filehandle);

    return ret;
}

static inline void _verify_io_retval(pTHX_ int retval, xs_connection* myconn, const char* msg) {
    if (retval < 0) {
        myconn->error = retval;

        switch (retval) {
            case MBEDTLS_ERR_SSL_WANT_READ:
            case MBEDTLS_ERR_SSL_WANT_WRITE:
            case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
            case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
            case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
                break;

            default: {
                dTHX;
                _mbedtls_err_croak(aTHX_ msg, retval);
            }
        }
    }
}

// Returns a MORTAL SV to the default trust store path.
static inline SV* _get_default_trust_store_path_sv(pTHX) {
    dSP;

    load_module(
        PERL_LOADMOD_NOIMPORT,
        newSVpvs_flags(TRUST_STORE_MODULE, SVs_TEMP),
        NULL
    );

    ENTER;
    SAVETMPS;

    int got = call_pv(TRUST_STORE_PATH_FUNCTION, G_SCALAR);

    if (!got) croak("%s() returned nothing?!?", TRUST_STORE_PATH_FUNCTION);

    SPAGAIN;

    SV* ret = SvREFCNT_inc(POPs);

    FREETMPS;
    LEAVE;

    return sv_2mortal(ret);
}

static inline void _load_trust_store_if_needed(pTHX_ xs_mbedtls* myconfig) {
    if (!myconfig->trust_store_loaded) {
        assert(myconfig->trust_store_path_sv);

        if (!SvOK(myconfig->trust_store_path_sv)) {
            sv_setsv(myconfig->trust_store_path_sv, _get_default_trust_store_path_sv(aTHX));
        }

        mbedtls_x509_crt_init( &myconfig->cacert );

        char *path = SvPVbyte_nolen(myconfig->trust_store_path_sv);

        int ret = mbedtls_x509_crt_parse_file(&myconfig->cacert, path);

        if (ret) {
            mbedtls_x509_crt_free( &myconfig->cacert );

            char *msg = form("Read trust store (%s)", path);
            _mbedtls_err_croak(aTHX_ msg, ret);
        }

        myconfig->trust_store_loaded = true;
    }
}

// ----------------------------------------------------------------------

// Returns:
//  0 if no error
//  1 if error was for key
//  2 if error was for cert chain
//
static unsigned _parse_key_and_cert_chain(pTHX_ xs_mbedtls* myconfig, SV** given, mbedtls_pk_context* pkey, mbedtls_x509_crt* crt, int *result) {

    SV* cur = given[0];
    assert(cur);

    mbedtls_pk_init(pkey);

    STRLEN pv_length;
    const char* pv = SvPVbyte(cur, pv_length);

    *result = mbedtls_pk_parse_key(
        pkey,
        (const unsigned char*) pv,
        1 + pv_length,
        NULL, 0, // passphrase
        mbedtls_ctr_drbg_random,
        &myconfig->ctr_drbg
    );

    if (*result) {
        mbedtls_pk_free(pkey);

        return 1;
    }

    U8 g = given[1] ? 1 : 0;

    mbedtls_x509_crt_init(crt);

    while ( (cur = given[g++]) ) {
        pv = SvPVbyte(cur, pv_length);

        *result = mbedtls_x509_crt_parse(
            crt,
            (const unsigned char*) pv,
            1 + pv_length
        );

        if (*result) {
            mbedtls_x509_crt_free(crt);
            mbedtls_pk_free(pkey);

            return 2;
        }
    }

    // Success!
    return 0;
}

static int net_mbedtls_sni_callback(void *ctx, mbedtls_ssl_context *ssl, const unsigned char* sni, size_t snilen) {
    xs_server* myconn = ctx;

    SV* mbedtls_obj = myconn->perl_mbedtls;
    xs_mbedtls* myconfig = (xs_mbedtls*) SvPVX(mbedtls_obj);

#ifdef MULTIPLICITY
    pTHX = myconn->aTHX;
#endif

    SV* cb = myconn->sni_cb;

    dSP;

    ENTER;
    SAVETMPS;

    EXTEND(SP, 1);
    mPUSHp((const char *) sni, snilen);
    PUTBACK;

    int count = call_sv(cb, G_ARRAY | G_EVAL);

    SPAGAIN;

    bool failed = true;

    if (SvTRUE(ERRSV)) {
        POPs;   // cf. perldoc perlcall
        warn("SNI callback failed: %" SVf, ERRSV);
        goto end_sni_callback;
    }

    if (count) {

        // cf. perldoc perlcall:
        SP -= count;
        I32 ax = SP - PL_stack_base + 1;

        SV* key_and_chain[1 + count];
        key_and_chain[count] = NULL;
        Copy(&ST(0), key_and_chain, 1, SV*);

        // These will be re-allocated below:
        mbedtls_pk_free(&myconn->pkey);
        mbedtls_x509_crt_free(&myconn->crt);

        int result;

        unsigned errtype = _parse_key_and_cert_chain(
            aTHX_
            myconfig,
            key_and_chain,
            &myconn->pkey,
            &myconn->crt,
            &result
        );

        if (errtype) {
            char errstr[200];
            mbedtls_strerror(result, errstr, sizeof(errstr));

            warn(
                "SNI callback (%.*s) %s parse failure: %s",
                (int) snilen, sni,
                (errtype == 1) ? "key" : "certificate chain",
                errstr
            );
            goto end_sni_callback;
        }

        result = mbedtls_ssl_set_hs_own_cert(ssl, &myconn->crt, &myconn->pkey);
        if (result) {
            mbedtls_x509_crt_free(&myconn->crt);
            mbedtls_pk_free(&myconn->pkey);

            char errstr[200];
            mbedtls_strerror(result, errstr, sizeof(errstr));

            warn("SNI callback (%.*s): failed to assign key & certificate (%s)", (int) snilen, sni, errstr);
            goto end_sni_callback;
        }

        failed = false;
    }

  end_sni_callback:
    FREETMPS;
    LEAVE;

    return failed;
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

    _MBEDTLS_XS_CONSTANT(MBEDTLS_SSL_VERIFY_NONE);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_SSL_VERIFY_OPTIONAL);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_SSL_VERIFY_REQUIRED);

    _MBEDTLS_XS_CONSTANT(MBEDTLS_X509_BADCERT_EXPIRED);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_X509_BADCERT_REVOKED);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_X509_BADCERT_CN_MISMATCH);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_X509_BADCERT_NOT_TRUSTED);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_X509_BADCERT_MISSING);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_X509_BADCERT_SKIP_VERIFY);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_X509_BADCERT_OTHER);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_X509_BADCERT_FUTURE);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_X509_BADCERT_KEY_USAGE);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_X509_BADCERT_EXT_KEY_USAGE);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_X509_BADCERT_NS_CERT_TYPE);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_X509_BADCERT_BAD_MD);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_X509_BADCERT_BAD_PK);
    _MBEDTLS_XS_CONSTANT(MBEDTLS_X509_BADCERT_BAD_KEY);

    _NET_MBEDTLS_XS_CONSTANT(CERT_PEM_STRING);
    _NET_MBEDTLS_XS_CONSTANT(CERT_PEM_PATH);

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
        char versionstr[20] = { 0 };
        mbedtls_version_get_string(versionstr);

        RETVAL = versionstr;

    OUTPUT:
        RETVAL

SV*
_new(SV* classname, SV* trust_store_path_sv = NULL)
    CODE:
        mbedtls_debug_set_threshold(4);
        int ret;

        SV* referent = newSV(sizeof( xs_mbedtls));
        sv_2mortal(referent);

        xs_mbedtls* myconfig = (xs_mbedtls*) SvPVX(referent);

        *myconfig = (xs_mbedtls) {
            .pid = getpid(),
            .trust_store_path_sv = trust_store_path_sv ? newSVsv(trust_store_path_sv) : NULL,
        };

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
            _mbedtls_err_croak(aTHX_ "Failed to seed random-number generator", ret);
        }

    OUTPUT:
        RETVAL

void
DESTROY(SV* self_obj)
    CODE:
        xs_mbedtls* myconfig = (xs_mbedtls*) SvPVX( SvRV(self_obj) );

        _warn_if_global_destruct(self_obj, myconfig);

        if (myconfig->trust_store_path_sv) {
            SvREFCNT_dec(myconfig->trust_store_path_sv);
        }

        if (myconfig->trust_store_loaded) {
            mbedtls_x509_crt_free( &myconfig->cacert );
        }

        mbedtls_ctr_drbg_free( &myconfig->ctr_drbg );
        mbedtls_entropy_free( &myconfig->entropy );

# ----------------------------------------------------------------------

MODULE = Net::mbedTLS   PACKAGE = Net::mbedTLS::Connection

bool
shake_hands(SV* peer_obj)
    CODE:
        xs_connection* myconn = (xs_connection*) SvPVX( SvRV(peer_obj) );

        int result = mbedtls_ssl_handshake( &myconn->ssl );

        _verify_io_retval(aTHX_ result, myconn, "handshake");

        RETVAL = !result;

    OUTPUT:
        RETVAL

# Named differently in client vs. server end classes because the
# actual work is different, but the call to mbedTLS is identical:
#
bool
_renegotiate(SV* peer_obj)
    CODE:
        xs_connection* myconn = (xs_connection*) SvPVX( SvRV(peer_obj) );

        int result = mbedtls_ssl_renegotiate( &myconn->ssl );

        _verify_io_retval(aTHX_ result, myconn, "renegotiate");

        RETVAL = !result;

    OUTPUT:
        RETVAL

SV*
write(SV* peer_obj, SV* bytes_sv)
    CODE:
        xs_connection* myconn = (xs_connection*) SvPVX( SvRV(peer_obj) );

        STRLEN outputlen;
        const char* output = SvPVbyte(bytes_sv, outputlen);

        int result = mbedtls_ssl_write(
            &myconn->ssl,
            (unsigned char*) output,
            outputlen
        );

        _verify_io_retval(aTHX_ result, myconn, "write");

        RETVAL = (result < 0) ? &PL_sv_undef : newSViv(result);

    OUTPUT:
        RETVAL

SV*
read(SV* peer_obj, SV* output_sv)
    CODE:
        if (!SvOK(output_sv)) croak("Undef is nonsense!");
        if (SvROK(output_sv)) croak("read() needs a plain scalar, not %s!", SvPVbyte_nolen(output_sv));

        xs_connection* myconn = (xs_connection*) SvPVX( SvRV(peer_obj) );

        STRLEN outputlen;
        const char* output = SvPVbyte(output_sv, outputlen);
        if (!outputlen) croak("Empty string is nonsense!");

        int result = mbedtls_ssl_read(
            &myconn->ssl,
            (unsigned char*) output,
            outputlen
        );

        if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            myconn->notify_closed = true;

            result = 0;
        }
        else {
            _verify_io_retval(aTHX_ result, myconn, "read");
        }

        SvUTF8_off(output_sv);

        RETVAL = (result < 0) ? &PL_sv_undef : newSViv(result);

    OUTPUT:
        RETVAL

bool
closed(SV* peer_obj)
    CODE:
        xs_connection* myconn = (xs_connection*) SvPVX( SvRV(peer_obj) );

        RETVAL = myconn->notify_closed;

    OUTPUT:
        RETVAL

SV*
ciphersuite (SV* peer_obj)
    CODE:
        xs_connection* myconn = (xs_connection*) SvPVX( SvRV(peer_obj) );

        const char* name = mbedtls_ssl_get_ciphersuite(&myconn->ssl);

        RETVAL = name ? newSVpv(name, 0) : &PL_sv_undef;

    OUTPUT:
        RETVAL

int
max_out_record_payload  (SV* peer_obj)
    CODE:
        xs_connection* myconn = (xs_connection*) SvPVX( SvRV(peer_obj) );

        RETVAL = mbedtls_ssl_get_max_out_record_payload(&myconn->ssl);

    OUTPUT:
        RETVAL

SV*
tls_version_name (SV* peer_obj)
    CODE:
        xs_connection* myconn = (xs_connection*) SvPVX( SvRV(peer_obj) );

        const char *name = mbedtls_ssl_get_version(&myconn->ssl);

        RETVAL = name ? newSVpv(name, 0) : &PL_sv_undef;

    OUTPUT:
        RETVAL

SV*
peer_certificate (SV* peer_obj)
    CODE:
        xs_connection* myconn = (xs_connection*) SvPVX( SvRV(peer_obj) );

        const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&myconn->ssl);

        RETVAL = crt ? newSVpv((const char*) crt->X509_CRT_RAW_MEMBER.X509_ASN1_P_MEMBER, crt->X509_CRT_RAW_MEMBER.X509_ASN1_LEN_MEMBER) : &PL_sv_undef;

    OUTPUT:
        RETVAL

U32
verification_result (SV* peer_obj)
    CODE:
        xs_connection* myconn = (xs_connection*) SvPVX( SvRV(peer_obj) );

        RETVAL = mbedtls_ssl_get_verify_result(&myconn->ssl);

    OUTPUT:
        RETVAL

bool
close_notify (SV* peer_obj)
    CODE:
        xs_connection* myconn = (xs_connection*) SvPVX( SvRV(peer_obj) );

        int result = mbedtls_ssl_close_notify(&myconn->ssl);
        _verify_io_retval(aTHX_ result, myconn, "close_notify");

        RETVAL = !result;

    OUTPUT:
        RETVAL

IV
error (SV* peer_obj)
    CODE:
        xs_connection* myconn = (xs_connection*) SvPVX( SvRV(peer_obj) );

        RETVAL = myconn->error;

    OUTPUT:
        RETVAL

void
DESTROY(SV* peer_obj)
    CODE:
        xs_connection* myconn = (xs_connection*) SvPVX( SvRV(peer_obj) );

        _warn_if_global_destruct(peer_obj, myconn);

        mbedtls_ssl_config_free( &myconn->conf );
        mbedtls_ssl_free( &myconn->ssl );

        SvREFCNT_dec(myconn->perl_mbedtls);
        SvREFCNT_dec(myconn->perl_filehandle);

# ----------------------------------------------------------------------

MODULE = Net::mbedTLS   PACKAGE = Net::mbedTLS::Client

SV*
_new(const char* classname, SV* mbedtls_obj, SV* filehandle, int fd, SV* servername_sv)
    CODE:
        const char* servername = SvOK(servername_sv) ? SvPVbyte_nolen(servername_sv) : "";

        xs_mbedtls* myconfig = (xs_mbedtls*) SvPVX( SvRV(mbedtls_obj) );

        _load_trust_store_if_needed(aTHX_ myconfig);

        RETVAL = _set_up_connection_object(aTHX_ myconfig, sizeof(xs_client), classname, MBEDTLS_SSL_IS_CLIENT, mbedtls_obj, filehandle, fd);

        SV* referent = SvRV(RETVAL);

        xs_client* myconn = (xs_client*) SvPVX(referent);

        int result = mbedtls_ssl_set_hostname(&myconn->ssl, servername);

        if (result) {
            _mbedtls_err_croak(aTHX_ "set SNI string", result);
        }

        mbedtls_ssl_conf_ca_chain( &myconn->conf, &myconfig->cacert, NULL );

        mbedtls_ssl_set_bio(
            &myconn->ssl,
            &myconn->net_context,
            mbedtls_net_send,
            mbedtls_net_recv,
            mbedtls_net_recv_timeout
        );

    OUTPUT:
        RETVAL

# ----------------------------------------------------------------------

MODULE = Net::mbedTLS   PACKAGE = Net::mbedTLS::Server

SV*
_new(const char* classname, SV* mbedtls_obj, SV* filehandle, int fd, SV* own_cert_sv, SV* sni_cb)
    CODE:
        xs_mbedtls* myconfig = (xs_mbedtls*) SvPVX( SvRV(mbedtls_obj) );

        _load_trust_store_if_needed(aTHX_ myconfig);

        RETVAL = _set_up_connection_object(aTHX_ myconfig, sizeof(xs_server), classname, MBEDTLS_SSL_IS_SERVER, mbedtls_obj, filehandle, fd);

        SV* referent = SvRV(RETVAL);

        xs_server* myconn = (xs_server*) SvPVX(referent);

        AV* own_cert_av = (AV*) SvRV(own_cert_sv);
        unsigned own_cert_len = 1 + av_len(own_cert_av);
        SV* own_cert[ 1 + own_cert_len ];
        own_cert[own_cert_len] = NULL;
        Copy(AvARRAY(own_cert_av), own_cert, own_cert_len, SV*);

        mbedtls_x509_crt_init(&myconn->crt);
        mbedtls_pk_init(&myconn->pkey);

        int result;

        int parse_err = _parse_key_and_cert_chain(aTHX_
            myconfig,
            own_cert,
            &myconn->pkey,
            &myconn->crt,
            &result
        );

        if (parse_err) {
            _mbedtls_err_croak(aTHX_
                (parse_err == 1) ? "parse key" : "parse certificate chain",
                result
            );
        }

        result = mbedtls_ssl_conf_own_cert (&myconn->conf, &myconn->crt, &myconn->pkey);
        if (result) {
            _mbedtls_err_croak(aTHX_ "assign key & certificate", result);
        }

        if (SvOK(sni_cb)) {
            myconn->sni_cb = SvREFCNT_inc(sni_cb);

            mbedtls_ssl_conf_sni(
                &myconn->conf,
                net_mbedtls_sni_callback,
                myconn
            );
        }

        mbedtls_ssl_set_bio(
            &myconn->ssl,
            &myconn->net_context,
            mbedtls_net_send,
            mbedtls_net_recv,
            mbedtls_net_recv_timeout
        );

    OUTPUT:
        RETVAL

void
_DESTROY (SV* self_sv)
    CODE:
        SV* referent = SvRV(self_sv);

        xs_server* myconn = (xs_server*) SvPVX(referent);

        mbedtls_x509_crt_free(&myconn->crt);
        mbedtls_pk_free(&myconn->pkey);
