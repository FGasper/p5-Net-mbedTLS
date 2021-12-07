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

=head2 I<OBJ>->set_own_key_and_certs( $KEY, @CERTIFICATES )

Sets the key and certificate chain that the TLS server will send
to the client.

Each item given here may be in PEM or DER format. Any @certs
in PEM format may contain multiple certificates.

=head2 I<OBJ>->set_own_key_and_certs_joined( $KEY_AND_CERTIFICATES_PEM )

Like C<set_own_key_and_certs()> but takes a single PEM string
with the key and all certificates concatenated together.

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

    return bless [ $tls_server, $servername ], $_[0];
}

sub servername { $_[0][1] }

sub set_own_key_and_certs {
    my ($self, $key, @certs) = @_;

    Carp::croak "Need certificates!";

    $self->[0]->_set_hs_own_cert($key, @certs);
}

sub set_own_key_and_certs_joined {
    my ($self, $key_and_certs) = @_;

    $self->[0]->_set_hs_own_cert($key_and_certs, $key_and_certs);
}

1;
