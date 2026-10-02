// Package securechannel contains validation helpers that are shared by the client and
// server implementations of the UA Secure Conversation protocol (OPC UA Part 6, 6.7).
package securechannel

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/awcullen/opcua/ua"
)

// MaxRSAKeyLength is the maximum length, in bits, of the RSA keys allowed by any security policy.
//
// It is enforced for all policies. It bounds the cost of the RSA operations made with a peer key
// before the peer certificate is validated: without it, a peer could send a certificate with a very
// long modulus (and a large public exponent) to make every OpenSecureChannel attempt expensive.
// The deprecated Basic128Rsa15 and Basic256 policies specify a maximum of 2048 bits; longer keys up
// to MaxRSAKeyLength are accepted for them, since a longer key does not weaken these policies, and
// rejecting them would break deployments that use 4096 bit certificates with these policies.
const MaxRSAKeyLength = 4096

// MinRSAKeyLength returns the minimum length, in bits, of the RSA keys allowed by a security policy,
// i.e. the minimum AsymmetricKeyLength of the policy (OPC UA Part 7): 1024 bits for the deprecated
// Basic128Rsa15 and Basic256 policies, and 2048 bits for Basic256Sha256, Aes128_Sha256_RsaOaep and
// Aes256_Sha256_RsaPss. For SecurityPolicy None, where a key may still encrypt user identity tokens,
// it returns the minimum of all RSA based policies.
func MinRSAKeyLength(securityPolicyURI string) int {
	switch securityPolicyURI {
	case ua.SecurityPolicyURIBasic256Sha256, ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.SecurityPolicyURIAes256Sha256RsaPss:
		return 2048
	default:
		return 1024
	}
}

// CheckRSAKey returns ua.BadCertificatePolicyCheckFailed if the RSA key is shorter than the security
// policy allows (see MinRSAKeyLength), or longer than MaxRSAKeyLength.
func CheckRSAKey(key *rsa.PublicKey, securityPolicyURI string) error {
	if key == nil || key.N == nil {
		return ua.BadCertificatePolicyCheckFailed
	}
	if n := key.N.BitLen(); n < MinRSAKeyLength(securityPolicyURI) || n > MaxRSAKeyLength {
		return ua.BadCertificatePolicyCheckFailed
	}
	return nil
}

// RSAPublicKey returns the public key of a certificate received from the remote peer, for use with
// the given security policy. It returns an error if the key is not an RSA key, or its length is not
// allowed (see CheckRSAKey), so the returned key is safe to use for RSA operations.
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
