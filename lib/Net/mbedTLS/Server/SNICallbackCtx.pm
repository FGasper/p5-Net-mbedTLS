package Net::mbedTLS::Server::SNICallbackCtx;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Net::mbedTLS::Server::SNICallbackCtx - SNI callback context

=head1 SYNOPSIS

    my $tls_server = $mbedtls->create_server(
        servername_cb => sub {

            # This our class instance:
            #
            my ($sni_cb_ctx) = @_;

            # The SNI string that the client sent:
            #
            my $servername = $sni_cb_ctx->servername();

            # Inform the TLS session accordingly:
            #
            $sni_cb_ctx->set_own_key_and_certs( .. );
            $sni_cb_ctx->set_ca_chain( .. );
            $sni_cb_ctx->set_authmode( .. );
        },
    );

=head1 DESCRIPTION

This class defines an object given to C<servername_cb> coderefs
(cf. L<Net::mbedTLS::Server>).

=head1 METHODS

=head2 $name = I<OBJ>->servername()

Returns the servername the client gave in the TLS handshake.

=head2 I<OBJ>->set_own_key_and_certs( @KEY_AND_CERTIFICATES )

Sets the key and certificate chain that the TLS server will send
to the client.

@KEY_AND_CERTIFICATES may be:

=over

=item * 1 item: Concatenated PEM documents.

=item * 2+ items: The key, then certificates. Any item may be in
PEM or DER format, and any non-initial items (i.e., certificate items)
may contain multiple certifictes.

=back

A L<Net::mbedTLS::X::mbedTLS> instance is thrown on failure.

=head2 I<OBJ>->set_authmode( $AUTHMODE )

Unneeded unless you’re verifying the client via a TLS certificate.

Configures verification of the client’s certificate.
One of the C<SSL_VERIFY_*> constants.

=cut

#----------------------------------------------------------------------

use Carp ();

#----------------------------------------------------------------------

sub new {
    my ($class, $tls_server, $servername) = @_;

    return bless( [ $tls_server, $servername ], $_[0] );
}

sub servername { $_[0][1] }

sub set_own_key_and_certs {
    my ($self, @key_and_certs) = @_;

    Carp::croak "Need key and certificates!" if !@key_and_certs;

    $self->[0]->_set_hs_own_cert(@key_and_certs);
}

1;
