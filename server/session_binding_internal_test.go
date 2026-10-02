// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/awcullen/opcua/ua"
)

// newTestUserCertificate creates a self-signed user certificate with the given subject common name.
func newTestUserCertificate(t *testing.T, key *rsa.PrivateKey, commonName string) ua.ByteString {
	t.Helper()
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return ua.ByteString(der)
}

// TestSameClientUserID tests the user identity comparison used when a session is transferred
// to a new secure channel.
func TestSameClientUserID(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	user1 := newTestUserCertificate(t, key, "user1")
	// another certificate with the same subject, e.g. from another issuer.
	user1Other := newTestUserCertificate(t, key, "user1")
	user2 := newTestUserCertificate(t, key, "user2")

	cases := []struct {
		name string
		a, b any
		want bool
	}{
		{"anonymous", ua.AnonymousIdentity{}, ua.AnonymousIdentity{}, true},
		{"same user name", ua.UserNameIdentity{UserName: "user1", Password: "a"}, ua.UserNameIdentity{UserName: "user1", Password: "b"}, true},
		{"other user name", ua.UserNameIdentity{UserName: "user1"}, ua.UserNameIdentity{UserName: "user2"}, false},
		{"same certificate", ua.X509Identity{Certificate: user1}, ua.X509Identity{Certificate: user1}, true},
		{"other certificate with same subject", ua.X509Identity{Certificate: user1}, ua.X509Identity{Certificate: user1Other}, false},
		{"other certificate", ua.X509Identity{Certificate: user1}, ua.X509Identity{Certificate: user2}, false},
		{"no certificate", ua.X509Identity{}, ua.X509Identity{}, false},
		{"same issued token", ua.IssuedIdentity{TokenData: ua.ByteString("token1")}, ua.IssuedIdentity{TokenData: ua.ByteString("token1")}, true},
		{"other issued token", ua.IssuedIdentity{TokenData: ua.ByteString("token1")}, ua.IssuedIdentity{TokenData: ua.ByteString("token2")}, false},
		{"no issued token", ua.IssuedIdentity{}, ua.IssuedIdentity{}, false},
		{"anonymous to user name", ua.AnonymousIdentity{}, ua.UserNameIdentity{UserName: "user1"}, false},
		{"user name to anonymous", ua.UserNameIdentity{UserName: "user1"}, ua.AnonymousIdentity{}, false},
		{"user name to certificate", ua.UserNameIdentity{UserName: "user1"}, ua.X509Identity{Certificate: user1}, false},
		{"no identity", nil, ua.AnonymousIdentity{}, false},
	}
	for _, c := range cases {
		if got := sameClientUserID(c.a, c.b); got != c.want {
			t.Errorf("%s: got %t, want %t", c.name, got, c.want)
		}
	}
}

// TestVerifiedClientCertificate tests which secure channels authenticate a client certificate.
func TestVerifiedClientCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaCert, err := x509.ParseCertificate([]byte(newTestUserCertificate(t, key, "client")))
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ecdsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatal(err)
	}
	ecCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		mode     ua.MessageSecurityMode
		policy   string
		crt      *x509.Certificate
		wantCert bool
		wantOK   bool
	}{
		{"none", ua.MessageSecurityModeNone, ua.SecurityPolicyURINone, nil, false, true},
		{"sign", ua.MessageSecurityModeSign, ua.SecurityPolicyURIBasic256Sha256, rsaCert, true, true},
		{"sign and encrypt", ua.MessageSecurityModeSignAndEncrypt, ua.SecurityPolicyURIBasic256Sha256, rsaCert, true, true},
		{"sign without certificate", ua.MessageSecurityModeSign, ua.SecurityPolicyURIBasic256Sha256, nil, false, false},
		{"sign with policy none", ua.MessageSecurityModeSign, ua.SecurityPolicyURINone, nil, false, false},
		{"mode none with policy", ua.MessageSecurityModeNone, ua.SecurityPolicyURIBasic256Sha256, nil, false, false},
		{"invalid mode", ua.MessageSecurityModeInvalid, ua.SecurityPolicyURINone, nil, false, false},
		{"non-rsa certificate", ua.MessageSecurityModeSign, ua.SecurityPolicyURIBasic256Sha256, ecCert, false, false},
	}
	for _, c := range cases {
		ch := &serverSecureChannel{securityMode: c.mode, securityPolicyURI: c.policy, verifiedRemoteCertificate: c.crt}
		crt, key, ok := verifiedClientCertificate(ch)
		if ok != c.wantOK || (crt != nil) != c.wantCert || (key != nil) != c.wantCert {
			t.Errorf("%s: got certificate %t, key %t, ok %t, want certificate %t, ok %t", c.name, crt != nil, key != nil, ok, c.wantCert, c.wantOK)
		}
	}
}
