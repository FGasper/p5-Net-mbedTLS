package Net::mbedTLS::X::mbedTLS;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Net::mbedTLS::X::mbedTLS

=head1 DESCRIPTION

This class represents fatal errors from mbedTLS.

It subclasses L<X::Tiny::Base> and exposes two C<get()>table
attributes:

=over

=item * C<number> - mbedTLS’s error number

=item * C<string> - string from mbedTLS that describes the error

=back

=cut

#----------------------------------------------------------------------

use parent qw( Net::mbedTLS::X::Base );

sub _new {
    my ($class, $action, $num, $str) = @_;

    return $class->SUPER::_new("mbedTLS failure ($action) $num: $str", number => $num, string => $str);
}

1;
