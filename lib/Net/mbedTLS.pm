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

sub new {
    my ($classname, $chain_path) = @_;

    $chain_path ||= do {
        require Mozilla::CA;
        Mozilla::CA::SSL_ca_file();
    };

    return _new($classname, $chain_path);
}

sub create_client {
    my ($self, $socket, $servername) = @_;

    require Net::mbedTLS::Client;

    return Net::mbedTLS::Client->_new($self, $socket, fileno($socket), $servername || ());
}

1;
