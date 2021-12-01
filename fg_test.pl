use strict;
use warnings;

use blib;

use Net::mbedTLS;
use IO::Socket::INET;

my $tls = Net::mbedTLS->new();

my $socket = IO::Socket::INET->new('cpanel.net:443');

my $tlsclient = $tls->client($socket, 'cpanel.net');

$tlsclient->shake_hands();

$tlsclient->write("GET / HTTP/1.0\r\n\r\n");

my $output = "\0" x 1024;

my $got;
while ($got = $tlsclient->read($output)) {
    print substr($output, 0, $got);
}
