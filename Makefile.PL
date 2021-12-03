use strict;
use warnings;
use autodie;

use Config;
use Cwd;
use ExtUtils::CBuilder;
use ExtUtils::MakeMaker::CPANfile;
use File::Temp;

my @MBEDTLS_LIBS = qw(crypto tls x509);

my $dynamic_base = $ENV{'NET_MBEDTLS_DYNAMIC_BASEDIR'};

my @mbedtls_writemakefile_args;

my @incdirs;

if ($dynamic_base) {
    @incdirs = "$dynamic_base/include";

    # “library” is for mbedTLS’s source.
    my ($libdir) = grep { "$dynamic_base/$_" } qw(lib library);
    die "No libdir under $dynamic_base found!";

    my @dash_l = map { "-lmbed$_" } @MBEDTLS_LIBS;

    @mbedtls_writemakefile_args = (
        LIBS => "-Wl,-rpath,$libdir -L$libdir @dash_l",
    );
}
else {
    my $mbedtls_build_dir = "mbedtls";

    _make_mbedtls($mbedtls_build_dir);

    @incdirs = "$mbedtls_build_dir/include";

    @mbedtls_writemakefile_args = (
        OBJECT => [
            '$(BASEEXT)$(OBJ_EXT)',
            map { "$mbedtls_build_dir/library/libmbed$_.a" } @MBEDTLS_LIBS,
        ],
    );
}

my @defines = _determine_defines(@incdirs);

substr($_, 0, 0, '-I') for @incdirs;

WriteMakefile(
    NAME              => 'Net::mbedTLS',
    VERSION_FROM      => 'lib/Net/mbedTLS.pm', # finds $VERSION
    ABSTRACT_FROM  => 'lib/Net/mbedTLS.pm', # retrieve abstract from module
    AUTHOR         => [
        'Felipe Gasper (FELIPE)',
    ],
    LICENSE           => "perl_5",

    CCFLAGS => join(
        q< >,
        $Config{'ccflags'},
        '-Wall',
        @defines,
    ),

    INC => "-I. @incdirs",

    @mbedtls_writemakefile_args,

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

sub _determine_defines {
    my @include_dirs = @_;

    my $builder = ExtUtils::CBuilder->new();

    my @defines;

    my @checks = (
        {
            label => 'public net_socket.fd',
            define => 'NET_CONTEXT_FD_IS_PUBLIC',
            c => q[
                #include <mbedtls/net_sockets.h>
                int main() {
                    mbedtls_net_context foo = { .fd = 5 };
                    return 0;
                }
            ],
        },

        {
            label => 'public x509_crt.raw',
            define => 'X509_CRT_RAW_IS_PUBLIC',
            c => q[
                #include <mbedtls/x509_crt.h>
                int main() {
                    mbedtls_x509_crt foo;

                    void *ptr = &foo.raw;

                    return 0;
                }
            ],
        },

        {
            label => 'public asn1_buf.p',
            define => 'X509_ASN1_P_IS_PUBLIC',
            c => q[
                #include <mbedtls/asn1.h>
                int main() {
                    mbedtls_asn1_buf foo;

                    void *ptr = &foo.p;

                    return 0;
                }
            ],
        },

        {
            label => 'public asn1_buf.len',
            define => 'X509_ASN1_LEN_IS_PUBLIC',
            c => q[
                #include <mbedtls/asn1.h>
                int main() {
                    mbedtls_asn1_buf foo;

                    void *ptr = &foo.len;

                    return 0;
                }
            ],
        },
    );

    my $dir = File::Temp::tempdir( CLEANUP => 1 );
    my $i = 0;

    for my $check_hr (@checks) {
        ++$i;

        _note("Checking: $check_hr->{'label'}");

        my $path = "$dir/source-$i.c";
        open my $fh, '>', $path;
        syswrite($fh, $check_hr->{'c'});
        close $fh;

        my $obj_file = eval {
            $builder->compile(
                source => $path,
                include_dirs => \@include_dirs,
            );
        };

        if ($obj_file) {
            push @defines, $check_hr->{'define'};
        }

        my $result = ($obj_file ? q<> : 'NOT ') . 'supported';
        _note("\t$check_hr->{'label'}: $result");
    }

    return map { "-D$_" } @defines;
}

sub _make_mbedtls {
    _note("Building mbedTLS …");

    my $make_bin = $Config{'gmake'} || $Config{'make'} or do {
        die "Cannot build static without either gmake or make!";
    };

    my $mbedtls_build_dir = shift;

    my $cwd = Cwd::getcwd();

    chdir $mbedtls_build_dir;
    system { $make_bin } $make_bin, 'lib' and die;
    chdir $cwd;

    _note("Done building mbedTLS!");
}

sub _note {
    print "===== @_$/";
}
