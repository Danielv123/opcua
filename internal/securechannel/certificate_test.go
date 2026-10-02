package securechannel_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/awcullen/opcua/internal/securechannel"
	"github.com/awcullen/opcua/internal/securechannel/securechanneltest"
	"github.com/awcullen/opcua/ua"
)

var allPolicyURIs = []string{
	ua.SecurityPolicyURINone,
	ua.SecurityPolicyURIBasic128Rsa15,
	ua.SecurityPolicyURIBasic256,
	ua.SecurityPolicyURIBasic256Sha256,
	ua.SecurityPolicyURIAes128Sha256RsaOaep,
	ua.SecurityPolicyURIAes256Sha256RsaPss,
}

func newRSACertificate(t *testing.T, bits int) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := securechanneltest.NewCertificate("urn:test:rsa", key, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestParseRSAPublicKey(t *testing.T) {
	rsaCert, rsaKey := newRSACertificate(t, 2048)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaCert, err := securechanneltest.NewCertificate("urn:test:ecdsa", ecdsaKey, &ecdsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Public, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Cert, err := securechanneltest.NewCertificate("urn:test:ed25519", ed25519Key, ed25519Public)
	if err != nil {
		t.Fatal(err)
	}
	// a certificate holding a 512 bit RSA key (signed with a larger key).
	smallKey := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), 511, 1), E: 65537}
	smallKeyCert, err := securechanneltest.NewCertificate("urn:test:small", rsaKey, smallKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, policyURI := range allPolicyURIs {
		key, err := securechannel.ParseRSAPublicKey(rsaCert, policyURI)
		if err != nil || key == nil || key.N.Cmp(rsaKey.N) != 0 {
			t.Errorf("%s: RSA certificate: got (%v, %v), want the certificate's key", policyURI, key, err)
		}
		// a certificate chain returns the key of the leaf.
		key, err = securechannel.ParseRSAPublicKey(append(append([]byte{}, rsaCert...), ecdsaCert...), policyURI)
		if err != nil || key == nil || key.N.Cmp(rsaKey.N) != 0 {
			t.Errorf("%s: RSA certificate chain: got (%v, %v), want the leaf certificate's key", policyURI, key, err)
		}

		cases := []struct {
			name string
			cert []byte
			want ua.StatusCode
		}{
			{"ECDSA", ecdsaCert, ua.BadCertificatePolicyCheckFailed},
			{"Ed25519", ed25519Cert, ua.BadCertificatePolicyCheckFailed},
			{"RSA512", smallKeyCert, ua.BadCertificatePolicyCheckFailed},
			{"Empty", nil, ua.BadCertificateInvalid},
			{"Garbage", []byte{0x30, 0x03, 0x02, 0x01, 0x01}, ua.BadCertificateInvalid},
			{"Truncated", rsaCert[:len(rsaCert)/2], ua.BadCertificateInvalid},
		}
		for _, c := range cases {
			key, err := securechannel.ParseRSAPublicKey(c.cert, policyURI)
			if key != nil || err != c.want {
				t.Errorf("%s: %s: got (%v, %v), want (nil, %v)", policyURI, c.name, key, err, c.want)
			}
		}
	}
	if key, err := securechannel.RSAPublicKey(nil, ua.SecurityPolicyURIBasic256Sha256); key != nil || err == nil {
		t.Errorf("nil certificate: got (%v, %v), want an error", key, err)
	}
}

// TestRSAKeyLength checks the key lengths allowed by each security policy (OPC UA Part 7).
func TestRSAKeyLength(t *testing.T) {
	cert1024, key1024 := newRSACertificate(t, 1024)
	cert2048, key2048 := newRSACertificate(t, 2048)
	cert4096, key4096 := newRSACertificate(t, 4096)
	minLength := map[string]int{
		ua.SecurityPolicyURINone:                1024,
		ua.SecurityPolicyURIBasic128Rsa15:       1024,
		ua.SecurityPolicyURIBasic256:            1024,
		ua.SecurityPolicyURIBasic256Sha256:      2048,
		ua.SecurityPolicyURIAes128Sha256RsaOaep: 2048,
		ua.SecurityPolicyURIAes256Sha256RsaPss:  2048,
	}
	keys := []struct {
		bits int
		cert []byte
		key  *rsa.PrivateKey
	}{{1024, cert1024, key1024}, {2048, cert2048, key2048}, {4096, cert4096, key4096}}
	// certificates holding keys longer than MaxRSAKeyLength (signed with a shorter key).
	longKeys := map[int]*rsa.PublicKey{}
	longCerts := map[int][]byte{}
	for _, bits := range []int{securechannel.MaxRSAKeyLength + 1, 8192, 65536} {
		longKeys[bits] = &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), bits-1, 1), E: 65537}
		cert, err := securechanneltest.NewCertificate("urn:test:long", key2048, longKeys[bits])
		if err != nil {
			t.Fatal(err)
		}
		longCerts[bits] = cert
	}
	for _, policyURI := range allPolicyURIs {
		if got := securechannel.MinRSAKeyLength(policyURI); got != minLength[policyURI] {
			t.Errorf("MinRSAKeyLength(%s) = %d, want %d", policyURI, got, minLength[policyURI])
		}
		for bits, cert := range longCerts {
			if key, err := securechannel.ParseRSAPublicKey(cert, policyURI); err != ua.BadCertificatePolicyCheckFailed || key != nil {
				t.Errorf("%s: %d bit certificate: got (%v, %v), want %v", policyURI, bits, key, err, ua.BadCertificatePolicyCheckFailed)
			}
			if err := securechannel.CheckRSAKey(longKeys[bits], policyURI); err != ua.BadCertificatePolicyCheckFailed {
				t.Errorf("%s: CheckRSAKey(%d bit key) = %v, want %v", policyURI, bits, err, ua.BadCertificatePolicyCheckFailed)
			}
		}
		for _, k := range keys {
			allowed := k.bits >= minLength[policyURI]
			key, err := securechannel.ParseRSAPublicKey(k.cert, policyURI)
			if allowed && (err != nil || key == nil) {
				t.Errorf("%s: %d bit certificate rejected: %v", policyURI, k.bits, err)
			}
			if !allowed && (err != ua.BadCertificatePolicyCheckFailed || key != nil) {
				t.Errorf("%s: %d bit certificate: got (%v, %v), want %v", policyURI, k.bits, key, err, ua.BadCertificatePolicyCheckFailed)
			}
			err = securechannel.CheckRSAKey(&k.key.PublicKey, policyURI)
			if allowed != (err == nil) {
				t.Errorf("%s: CheckRSAKey(%d bit key) = %v", policyURI, k.bits, err)
			}
		}
	}
	if err := securechannel.CheckRSAKey(nil, ua.SecurityPolicyURIBasic256); err == nil {
		t.Error("CheckRSAKey(nil) succeeded")
	}
}
