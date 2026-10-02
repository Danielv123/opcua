// Package securechannel contains validation helpers that are shared by the client and
// server implementations of the UA Secure Conversation protocol (OPC UA Part 6, 6.7).
package securechannel

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/awcullen/opcua/ua"
)

// MinRSAKeyLength returns the minimum length, in bits, of the RSA keys allowed by a security policy,
// i.e. the minimum AsymmetricKeyLength of the policy (OPC UA Part 7): 1024 bits for the deprecated
// Basic128Rsa15 and Basic256 policies, and 2048 bits for Basic256Sha256, Aes128_Sha256_RsaOaep and
// Aes256_Sha256_RsaPss. For SecurityPolicy None, where a key may still encrypt user identity tokens,
// it returns the minimum of all RSA based policies.
//
// The maximum AsymmetricKeyLength of the policies (2048 or 4096 bits) is not enforced: a longer key
// does not weaken the channel, the chunk sizes are validated separately, and rejecting longer keys
// would break peers that work today, e.g. with 4096 bit certificates for Basic256.
func MinRSAKeyLength(securityPolicyURI string) int {
	switch securityPolicyURI {
	case ua.SecurityPolicyURIBasic256Sha256, ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.SecurityPolicyURIAes256Sha256RsaPss:
		return 2048
	default:
		return 1024
	}
}

// CheckRSAKey returns ua.BadCertificatePolicyCheckFailed if the RSA key is shorter than the security
// policy allows (see MinRSAKeyLength).
func CheckRSAKey(key *rsa.PublicKey, securityPolicyURI string) error {
	if key == nil || key.N == nil || key.N.BitLen() < MinRSAKeyLength(securityPolicyURI) {
		return ua.BadCertificatePolicyCheckFailed
	}
	return nil
}

// RSAPublicKey returns the public key of a certificate received from the remote peer, for use with
// the given security policy. It returns an error if the key is not an RSA key, or is shorter than
// the security policy allows, so the returned key is safe to use for RSA operations.
func RSAPublicKey(certificate *x509.Certificate, securityPolicyURI string) (*rsa.PublicKey, error) {
	if certificate == nil {
		return nil, ua.BadCertificateInvalid
	}
	key, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ua.BadCertificatePolicyCheckFailed
	}
	if err := CheckRSAKey(key, securityPolicyURI); err != nil {
		return nil, err
	}
	return key, nil
}

// ParseRSAPublicKey parses a DER encoded certificate, or certificate chain, received from the
// remote peer and returns the RSA public key of the leaf certificate. See RSAPublicKey.
func ParseRSAPublicKey(certificate []byte, securityPolicyURI string) (*rsa.PublicKey, error) {
	certs, err := x509.ParseCertificates(certificate)
	if err != nil || len(certs) == 0 {
		return nil, ua.BadCertificateInvalid
	}
	return RSAPublicKey(certs[0], securityPolicyURI)
}
