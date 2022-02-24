package Net::mbedTLS;

use strict;
use warnings;

our $VERSION;

use XSLoader ();

BEGIN {
    $VERSION = '0.01_01';
    XSLoader::load( __PACKAGE__, $VERSION );
}

=encoding utf-8

=head1 NAME

Net::mbedTLS - L<mbedTLS|https://tls.mbed.org/> in Perl

=head1 SYNOPSIS

    my $fh = IO::Socket::INET->new("example.com:12345");

    my $mbedtls = Net::mbedTLS->new();

    my $client = $mbedtls->create_client($fh);

    # Optional, but useful to do separately if, e.g., you want
    # to report a successful handshake.
    $client->shake_hands();

    # Throws if the error is an “unexpected” one:
    my $input = "\0" x 23;
    my $got = $client->read($input) // do {

        # We get here if, e.g., the socket is non-blocking and we
        # weren’t ready to read.
    };

    # Similar to read(); throws on “unexpected” errors:
    my $wrote = $tls->write($byte_string) // do {
        # ...
    };

=head1 DESCRIPTION

L<OpenSSL|https://openssl.org> is great, and so is L<Net::SSLeay>,
its Perl binding. Both are rather large, though.

This distribution allows use of mbedTLS, a smaller, simpler TLS library,
from Perl.

=head1 BENEFITS & LIABILITIES

This library, like mbedTLS itself, minimizes memory usage at
the cost of performance. After a simple TLS handshake with this library
Perl’s memory usage is about 6.5 MiB lower than when using
L<IO::Socket::SSL> for the same. On the other hand, OpenSSL does the
handshake about 18 times faster.

=head1 AVAILABLE FUNCTIONALITY

For now this module largely just exposes the ability to do TLS. mbedTLS
itself exposes a good deal more functionality (e.g., raw crypto,
configurable ciphers); if you want that stuff, file a feature request.
(Ideally send a patch.)

=head1 BUILDING/LINKING

This library can link to mbedTLS in several ways:

=over

=item * Dynamic, to system library (default): This assumes that
mbedTLS is available from some system-default location (e.g.,
F</usr>).

=item * Dynamic, to a specific path: To do this set
C<NET_MBEDTLS_MBEDTLS_BASE> in your environment to whatever directory
contains mbedTLS’s F<include> and F<lib> (or F<library>) directories.

=item * Static, to a specific path: Like the previous one, but
also set C<NET_MBEDTLS_LINKING> to C<static> in your environment.

=back

Dynamic linking allows Net::mbedTLS to use the most recent
(compatible) mbedTLS but requires you to have a shared mbedTLS
available, whereas static linking alleviates that dependency at the
cost of always using the same library version.

mbedTLS, alas, as of this writing does not support
L<pkg-config|https://www.freedesktop.org/wiki/Software/pkg-config/>.
(L<GitHub issue|https://github.com/ARMmbed/mbedtls/issues/228>) If that
changes then dynamic linking may become more reliable.

=cut

#----------------------------------------------------------------------

use Net::mbedTLS::X ();

our $DEBUG;

#----------------------------------------------------------------------

=head1 METHODS

=head2 $obj = I<CLASS>->new( %OPTS )

Instantiates this class. %OPTS are:

=over

=item * C<trust_store_path> (optional) - Filesystem path to the trust
store (i.e., root certificates). If not given this module will use
L<Mozilla::CA>’s trust store.

The trust store isn’t loaded until it’s needed, so if you don’t need
to verify certificate chains (e.g., you’re only serving without
TLS client authentication) you can safely omit this.

=back

=cut

sub new {
    my ($classname, %opts) = @_;

    return _new($classname, $opts{'trust_store_path'});
}

=head2 $client = I<OBJ>->create_client( $SOCKET, %OPTS )

Initializes a client session on $SOCKET. Returns a
L<Net::mbedTLS::Client> instance.

%OPTS are:

=over

=item * C<servername> (optional) - The SNI string to send in the handshake.

=item * C<authmode> (optional) - One of this module’s C<SSL_VERIFY_*> constants. Defaults as in mbedTLS.

=back

=cut

sub create_client {
    my ($self, $socket, %opts) = @_;

    require Net::mbedTLS::Client;

    return Net::mbedTLS::Client->_new($self, $socket, fileno($socket), @opts{'servername', 'authmode'});
}

=head2 $client = I<OBJ>->create_server( $SOCKET, %OPTS )

Initializes a server session on $SOCKET. Returns a
L<Net::mbedTLS::Server> instance.

%OPTS are:

=over

=item * C<servername_cb> (optional) - The callback to run once the
client’s SNI string is received. It will receive a
L<Net::mbedTLS::Server::SNICallbackCtx> instance, which you can use
to set the necessary parameters for the new TLS session.

If an exception is thrown, a warning is created, and the TLS session
is aborted.

To abort the session without a warning, return -1.

All other outcomes of this callback tell mbedTLS to continue the
TLS handshake.

=cut

sub create_server {
    my ($self, $socket, %opts) = @_;

    my @missing = grep { !$opts{$_} } (
        'key_and_certs',
    );

    die "Missing: @missing" if @missing;

    if ('ARRAY' ne ref $opts{'key_and_certs'}) {
        require Carp;
        Carp::croak("“key_and_certs” must be an ARRAY reference, not $opts{'key_and_certs'}");
    }
    if (!@{ $opts{'key_and_certs'} }) {
        require Carp;
        Carp::croak("“key_and_certs” must be nonempty");
    }

    require Net::mbedTLS::Server;

    return Net::mbedTLS::Server->_new(
        $self,
        $socket, fileno($socket),
        @opts{'key_and_certs', 'servername_cb'},
    );
}

#----------------------------------------------------------------------

=head1 CONSTANTS

These come from mbedTLS:

=over

=item * Error states: C<ERR_SSL_WANT_READ>, C<ERR_SSL_WANT_WRITE>,
C<ERR_SSL_ASYNC_IN_PROGRESS>, C<ERR_SSL_CRYPTO_IN_PROGRESS>,
C<MBEDTLS_ERR_SSL_CLIENT_RECONNECT>

=item * Verify modes: C<SSL_VERIFY_NONE>, C<SSL_VERIFY_OPTIONAL>,
C<SSL_VERIFY_REQUIRED>

=back

=cut

#----------------------------------------------------------------------

=head1 AUTHOR & COPYRIGHT

Copyright 2021 Gasper Software Consulting.

=cut

1;
