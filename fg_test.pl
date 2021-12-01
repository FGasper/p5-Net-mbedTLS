use strict;
use warnings;

use blib;

use Net::mbedTLS;
use IO::Socket::INET;

my $tls = Net::mbedTLS->new();

my $peername = 'cpanel.net';

my $socket = IO::Socket::INET->new("$peername:443") or die;

my $tlsclient = $tls->create_client($socket, $peername);

#use Data::Dumper;
#$Data::Dumper::Useqq = 1;
#
#print Dumper(
#    $tlsclient->ciphersuite(),
#    $tlsclient->max_out_record_payload(),
#    $tlsclient->tls_version_name(),
#    $tlsclient->peer_certificate(),
#);
#
#$tlsclient->shake_hands();
#
#print Dumper(
#    $tlsclient->ciphersuite(),
#    $tlsclient->max_out_record_payload(),
#    $tlsclient->tls_version_name(),
#);
#
#use Crypt::Format;
#print Crypt::Format::der2pem($tlsclient->peer_certificate(), 'CERTIFICATE') . $/;

$tlsclient->write("GET / HTTP/1.1\r\nHost: $peername\r\n\r\n");

my $output = "\0" x 1024;

my $got;
while ($got = $tlsclient->read($output)) {
    print substr($output, 0, $got);
}
