#!perl

use strict;
use warnings;

use Test::More;
use Test::FailWarnings;

use Net::mbedTLS;

use IO::Socket::INET ();

my $socket = IO::Socket::INET->new('example.com:443') or do {
    plan skip_all => "Connect failed: $!";
};

my $tls = Net::mbedTLS->new()->create_client(
    $socket,
    authmode => Net::mbedTLS::SSL_VERIFY_NONE,
);

my $fh = $tls->tied_fh();

printf {$fh} "%s", "GET / HTTP/1.0\r\n\r\n";

my $buf;

print getc $fh;

while (sysread $fh, $buf, 512) {
    print $buf;
}

close $fh;
