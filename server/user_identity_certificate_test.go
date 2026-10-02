package server

import (
	"crypto/rsa"
	"math/big"
	"testing"
	"time"

	"github.com/awcullen/opcua/internal/securechannel"
	"github.com/awcullen/opcua/internal/securechannel/securechanneltest"
	"github.com/awcullen/opcua/ua"
)

func TestUserIdentityCertificateKey(t *testing.T) {
	loadTestCredentials(t)
	certificateForKey := func(bits int) []byte {
		t.Helper()
		key := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), bits-1, 1), E: 1<<31 - 1}
		cert, err := securechanneltest.NewCertificate("urn:localhost:user", testOtherClient.key, key)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	chainOf := func(n int) []byte {
		chain := append([]byte{}, testClient.cert...)
		for i := 1; i < n; i++ {
			chain = append(chain, testOtherClient.cert...)
		}
		return chain
	}
	huge := certificateForKey(1 << 21) // a 2 megabit modulus

	for _, p := range testRSAPolicies {
		name := p.uri[len("http://opcfoundation.org/UA/SecurityPolicy#"):]
		key, err := userIdentityCertificateKey(testClient.cert, p.uri)
		if err != nil || key.N.Cmp(testClient.key.N) != 0 {
			t.Errorf("%s: 2048 bit certificate: got (%v, %v), want the certificate's key", name, key, err)
		}
		if _, err := userIdentityCertificateKey(chainOf(securechannel.MaxCertificateChainLength), p.uri); err != nil {
			t.Errorf("%s: chain of %d certificates: %v", name, securechannel.MaxCertificateChainLength, err)
		}
		_, err = userIdentityCertificateKey(testShortClient.cert, p.uri)
		if allowed := securechannel.MinRSAKeyLength(p.uri) <= 1024; allowed != (err == nil) {
			t.Errorf("%s: 1024 bit certificate: got %v", name, err)
		}
		if err != nil && err != ua.BadIdentityTokenInvalid {
			t.Errorf("%s: 1024 bit certificate: got %v, want %v", name, err, ua.BadIdentityTokenInvalid)
		}

		start := time.Now()
		invalid := map[string][]byte{
			"Huge":          huge,
			"TooLong":       certificateForKey(securechannel.MaxRSAKeyLength + 1),
			"ChainTooLong":  chainOf(securechannel.MaxCertificateChainLength + 1),
			"IssuerTooLong": append(append([]byte{}, testClient.cert...), certificateForKey(securechannel.MaxIssuerRSAKeyLength+1)...),
			"ECDSA":         testECDSACert,
			"Ed25519":       testEd25519Cert,
			"RSA512":        testSmallRSACert,
			"Garbage":       {1, 2, 3},
			"Empty":         nil,
		}
		for invalidName, cert := range invalid {
			if key, err := userIdentityCertificateKey(cert, p.uri); key != nil || err != ua.BadIdentityTokenInvalid {
				t.Errorf("%s: %s: got (%v, %v), want %v", name, invalidName, key, err, ua.BadIdentityTokenInvalid)
			}
		}
		// the checks do not use the keys, so they are fast even for a huge key.
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: the checks took %v", name, d)
		}
	}

	// the token signature cannot be verified without an RSA based security policy.
	for _, policyURI := range []string{ua.SecurityPolicyURINone, "", "http://opcfoundation.org/UA/SecurityPolicy#Unknown"} {
		if key, err := userIdentityCertificateKey(testClient.cert, policyURI); key != nil || err != ua.BadIdentityTokenInvalid {
			t.Errorf("policy %q: got (%v, %v), want %v", policyURI, key, err, ua.BadIdentityTokenInvalid)
		}
	}
}
