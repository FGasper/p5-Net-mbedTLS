package Net::mbedTLS::Connection::Tied;

use strict;
use warnings;

use Errno ();
use Symbol ();

sub new {
    my ($class, $tls) = @_;

    my $sym = Symbol::gensym();

    return tie *$sym, $class, $sym, $tls;
}

our $TLS_ERROR;

sub TIEHANDLE {
    my ($class, $symref, $tls) = @_;

    ${*$symref}{'tls'} = $tls;

    return bless $symref, $class;
}

#sub FILENO {
#    my ($self) = @_;
#
#    return fileno( ${$self}->fh() );
#}

sub READ {
    my ($self, undef, $length, $offset) = @_;

    my $tls = ${*$self}{'tls'};

    my $buf_sr = \$_[1];
    if (!defined $$buf_sr) {
        $$buf_sr = q<>;
    }

    $offset ||= 0;

    if ($offset < 0) {
        $offset = length($$buf_sr) + $offset;
    }

    my $buf = "\0" x ($length - $offset);

    my $got = $tls->read($buf);

    if ($got) {
        substr $$buf_sr, 0, length $buf, $buf;
        return $got;
    }

    return 0 if $tls->closed();

    $! = Errno::EAGAIN();

    $TLS_ERROR = $tls->error();

    return undef;
}

sub WRITE {
    my ($self, $src, $length, $offset) = @_;

    my $tls = ${*$self}{'tls'};

    my $sent;

    if (defined $length) {
        $offset ||= 0;

        $sent = $tls->write( substr($src, $offset, $length) );
    }
    else {
        $sent = $tls->write($src);
    }

    return $sent if $sent;

    return 0 if $tls->closed();

    $! = Errno::EAGAIN();

    $TLS_ERROR = $tls->error();

    return undef;
}

1;
