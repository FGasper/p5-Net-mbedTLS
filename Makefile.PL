use strict;
use warnings;

use Config;
use ExtUtils::MakeMaker::CPANfile;

my $mbedtls_build_dir = "mbedtls/build";

WriteMakefile(
    NAME              => 'Net::mbedTLS',
    VERSION_FROM      => 'lib/Net/mbedTLS.pm', # finds $VERSION
    ABSTRACT_FROM  => 'lib/Net/mbedTLS.pm', # retrieve abstract from module
    AUTHOR         => [
        'Felipe Gasper (FELIPE)',
    ],
    LICENSE           => "perl_5",

    INC => "-Wall -I. -I$mbedtls_build_dir/include",

    LIBS => "-Wl,-rpath,$mbedtls_build_dir/library -L$mbedtls_build_dir/library -lmbedcrypto -lmbedtls -lmbedx509",

    PMLIBDIRS => ['lib'],

    META_MERGE => {
        'meta-spec' => { version => 2 },
        resources => {
            repository => {
                type => 'git',
                url => 'git://github.com/FGasper/p5-Net-mbedTLS.git',
                web => 'https://github.com/FGasper/p5-Net-mbedTLS',
            },
            bugtracker => {
                web => 'https://github.com/FGasper/p5-Net-mbedTLS/issues',
            },
        },
    },
);
