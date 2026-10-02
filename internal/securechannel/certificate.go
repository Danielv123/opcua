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

// MaxIssuerRSAKeyLength is the maximum length, in bits, of the RSA keys of the issuer certificates
// in a certificate chain received from the peer. Validating the chain verifies certificate
// signatures with these keys before the chain is known to be trusted, so their length is bounded
// too. The limit is higher than MaxRSAKeyLength, so that chains with 8192 bit CA certificates remain
// usable.
const MaxIssuerRSAKeyLength = 8192

// MaxCertificateChainLength is the maximum number of certificates in a certificate chain received from
// the peer: the leaf certificate and its issuer certificates. Together with MaxIssuerRSAKeyLength it
// bounds the number and cost of the signature checks made while the chain is validated.
const MaxCertificateChainLength = 10

// CheckCertificateChain returns ua.BadCertificatePolicyCheckFailed if a chain received from the peer
// holds more than MaxCertificateChainLength certificates, or a certificate that holds an RSA key that
// is too long: longer than MaxRSAKeyLength for the leaf certificate (the first one), or longer than
// MaxIssuerRSAKeyLength for the other certificates. It must be called before the chain is validated.
func CheckCertificateChain(certificates []*x509.Certificate) error {
	if len(certificates) > MaxCertificateChainLength {
		return ua.BadCertificatePolicyCheckFailed
	}
	for i, certificate := range certificates {
		key, ok := certificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		limit := MaxIssuerRSAKeyLength
		if i == 0 {
			limit = MaxRSAKeyLength
		}
		if key == nil || key.N == nil || key.N.BitLen() > limit {
			return ua.BadCertificatePolicyCheckFailed
		}
	}
	return nil
}

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

// SameLeafCertificate returns true if the DER encoded certificates, or certificate chains, a and b
// start with the same (leaf) certificate. The issuer certificates may differ.
func SameLeafCertificate(a, b []byte) bool {
	certsA, err := x509.ParseCertificates(a)
	if err != nil || len(certsA) == 0 {
		return false
	}
	certsB, err := x509.ParseCertificates(b)
	if err != nil || len(certsB) == 0 {
		return false
	}
	return certsA[0].Equal(certsB[0])
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
