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

    my $tls = Net::mbedTLS::Client->new($fh);

    # Optional, but useful to do separately if, e.g., you want
    # to report a successful handshake.
    $tls->handshake();

    # Throws if the error is an “unexpected” one:
    my $got = $tls->read(23) // do {

        # We get here if, e.g., the socket is non-blocking and we
        # weren’t ready to read.
    };

    # Similar to read(); throws on “unexpected” errors:
    $wrote = $tls->write($byte_string) // do {
        # ...
    };

=cut

#----------------------------------------------------------------------

use Net::mbedTLS::X ();

#----------------------------------------------------------------------

=head1 METHODS

=head2 $obj = I<CLASS>->new( %OPTS )

Instantiates this class. %OPTS are:

=over

=item * C<trust_store_path> (optional) - Filesystem path to the trust store
(i.e., root certificates). If not given this module will use
L<Mozilla::CA>’s trust store.

=back

=cut

sub new {
    my ($classname, %opts) = @_;

    return _new($classname, $opts{'trust_store_path'});
}

=head2 $client = I<OBJ>->create_client( $SOCKET, %OPTS )

Initializes a client session on $SOCKET. %OPTS are:

=over

=item * C<servername> (optional) - The SNI string to send in the handshake.

=back

=cut

sub create_client {
    my ($self, $socket, %opts) = @_;

    require Net::mbedTLS::Client;

    return Net::mbedTLS::Client->_new($self, $socket, fileno($socket), $opts{'servername'});
}

=head2 $client = I<OBJ>->create_client( $SOCKET, %OPTS )

Initializes a server session on $SOCKET. %OPTS are:

=over

=item * C<servername_cb> (optional) - The callback to run once the
client’s SNI string is received.

=back

=cut

sub create_server {
    my ($self, $socket, %opts) = @_;

    require Net::mbedTLS::Server;
}

1;
