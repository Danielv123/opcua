package server

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/awcullen/opcua/internal/securechannel"
	"github.com/awcullen/opcua/ua"
)

// userIdentityCertificateKey returns the RSA public key of the certificate (or certificate chain) of an
// X509IdentityToken, which is used to verify the token signature made with the algorithm of the token's
// security policy. It returns ua.BadIdentityTokenInvalid if the security policy is not an RSA based policy,
// the certificate cannot be parsed, the chain is too long or holds a key that is too long, or the key of the
// certificate is not an RSA key whose length the security policy allows. The checks are made before the
// key is used, since the certificate is supplied by a peer that is not authenticated yet.
func userIdentityCertificateKey(certificateData []byte, securityPolicyURI string) (*rsa.PublicKey, error) {
	switch securityPolicyURI {
	case ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256, ua.SecurityPolicyURIBasic256Sha256,
		ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.SecurityPolicyURIAes256Sha256RsaPss:
	default:
		// the token signature cannot be verified.
		return nil, ua.BadIdentityTokenInvalid
	}
	certs, err := x509.ParseCertificates(certificateData)
	if err != nil || len(certs) == 0 {
		return nil, ua.BadIdentityTokenInvalid
	}
	if err := securechannel.CheckCertificateChain(certs); err != nil {
		return nil, ua.BadIdentityTokenInvalid
	}
	key, err := securechannel.RSAPublicKey(certs[0], securityPolicyURI)
	if err != nil {
		return nil, ua.BadIdentityTokenInvalid
	}
	return key, nil
}
