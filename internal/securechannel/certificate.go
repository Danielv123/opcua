// Package securechannel contains validation helpers that are shared by the client and
// server implementations of the UA Secure Conversation protocol (OPC UA Part 6, 6.7).
package securechannel

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/awcullen/opcua/ua"
)

// MinRSAKeySize is the minimum size, in bytes, of the RSA key of a remote certificate (1024 bits).
// It is the smallest key length allowed by any of the RSA based security policies.
const MinRSAKeySize = 128

// RSAPublicKey returns the public key of a certificate received from the remote peer.
// It returns an error if the key is not an RSA key that is supported by the RSA based
// security policies, so the returned key is safe to use for RSA operations.
func RSAPublicKey(certificate *x509.Certificate) (*rsa.PublicKey, error) {
	if certificate == nil {
		return nil, ua.BadCertificateInvalid
	}
	key, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || key == nil || key.N == nil || key.Size() < MinRSAKeySize {
		return nil, ua.BadCertificatePolicyCheckFailed
	}
	return key, nil
}

// ParseRSAPublicKey parses a DER encoded certificate, or certificate chain, received from the
// remote peer and returns the RSA public key of the leaf certificate. See RSAPublicKey.
func ParseRSAPublicKey(certificate []byte) (*rsa.PublicKey, error) {
	certs, err := x509.ParseCertificates(certificate)
	if err != nil || len(certs) == 0 {
		return nil, ua.BadCertificateInvalid
	}
	return RSAPublicKey(certs[0])
}
