package Net::mbedTLS::Client;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Net::mbedTLS::Client - Class representing a TLS client

=head1 SYNOPSIS

    my $socket = IO::Socket::INET->new('perl.com:443');

    my $tls = Net::mbedTLS->new()->create_client($socket, 'perl.com');

=cut

=head1 DESCRIPTION

Subclass of L<Net::mbedTLS::Peer>.

=cut

#----------------------------------------------------------------------

use parent 'Net::mbedTLS::Peer';

1;
