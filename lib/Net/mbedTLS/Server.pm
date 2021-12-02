package Net::mbedTLS::Server;

use strict;
use warnings;

use parent 'Net::mbedTLS::Connection';

sub DESTROY {
    my $self = shift;

    $self->_DESTROY();

    $self->SUPER::DESTROY();
}

1;
