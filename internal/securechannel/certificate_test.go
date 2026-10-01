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

func TestParseRSAPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaCert, err := securechanneltest.NewCertificate("urn:test:rsa", rsaKey, &rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
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

	key, err := securechannel.ParseRSAPublicKey(rsaCert)
	if err != nil || key == nil || key.N.Cmp(rsaKey.N) != 0 {
		t.Errorf("RSA certificate: got (%v, %v), want the certificate's key", key, err)
	}
	// a certificate chain returns the key of the leaf.
	key, err = securechannel.ParseRSAPublicKey(append(append([]byte{}, rsaCert...), ecdsaCert...))
	if err != nil || key == nil || key.N.Cmp(rsaKey.N) != 0 {
		t.Errorf("RSA certificate chain: got (%v, %v), want the leaf certificate's key", key, err)
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
		key, err := securechannel.ParseRSAPublicKey(c.cert)
		if key != nil || err != c.want {
			t.Errorf("%s: got (%v, %v), want (nil, %v)", c.name, key, err, c.want)
		}
	}
	if key, err := securechannel.RSAPublicKey(nil); key != nil || err == nil {
		t.Errorf("nil certificate: got (%v, %v), want an error", key, err)
	}
}
