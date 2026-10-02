// Copyright 2021 Converter Systems LLC. All rights reserved.

package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

// keyLengthTestPort is the port of the server started by TestServerKeyLength.
const keyLengthTestPort = 46413

// writeTestServerCertificate writes a self-signed server certificate with an RSA key of the given length
// to dir, and returns the paths of the certificate and key files.
func writeTestServerCertificate(t *testing.T, dir string, keyLength int, applicationURI string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(applicationURI)
	if err != nil {
		t.Fatal(err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "keylengthserver"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host, "localhost"},
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// TestServerKeyLength verifies that a server only advertises the security policies that its key supports.
func TestServerKeyLength(t *testing.T) {
	ctx := context.Background()
	keyEndpointURL := fmt.Sprintf("opc.tcp://%s:%d", host, keyLengthTestPort)
	applicationURI := fmt.Sprintf("urn:%s:keylengthserver", host)
	certPath, keyPath := writeTestServerCertificate(t, t.TempDir(), 1024, applicationURI)

	srv, err := server.New(
		ua.ApplicationDescription{
			ApplicationURI: applicationURI,
			ProductURI:     "http://github.com/awcullen/opcua",
			ApplicationName: ua.LocalizedText{
				Text:   fmt.Sprintf("keylengthserver@%s", host),
				Locale: "en",
			},
			ApplicationType: ua.ApplicationTypeServer,
			DiscoveryURLs:   []string{keyEndpointURL},
		},
		certPath,
		keyPath,
		keyEndpointURL,
		server.WithAuthenticateAnonymousIdentityFunc(func(userIdentity ua.AnonymousIdentity, applicationURI string, endpointURL string) error {
			return nil
		}),
		server.WithAuthenticateUserNameIdentityFunc(func(userIdentity ua.UserNameIdentity, applicationURI string, endpointURL string) error {
			if userIdentity.UserName == "user" && userIdentity.Password == "secret" {
				return nil
			}
			return ua.BadUserAccessDenied
		}),
		server.WithSecurityPolicyNone(true),
		server.WithInsecureSkipVerify(),
	)
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()
	defer srv.Close()

	// wait for server to listen.
	var res *ua.GetEndpointsResponse
	for deadline := time.Now().Add(10 * time.Second); ; {
		res, err = client.GetEndpoints(ctx, &ua.GetEndpointsRequest{EndpointURL: keyEndpointURL})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// a 1024 bit key supports Basic128Rsa15 and Basic256 only. Passwords are encrypted with Basic256.
	want := map[string]bool{
		ua.SecurityPolicyURINone:          true,
		ua.SecurityPolicyURIBasic128Rsa15: true,
		ua.SecurityPolicyURIBasic256:      true,
	}
	for _, ep := range res.Endpoints {
		if !want[ep.SecurityPolicyURI] {
			t.Errorf("advertised security policy %s, %s", ep.SecurityPolicyURI, ep.SecurityMode)
		}
		for _, tok := range ep.UserIdentityTokens {
			if tok.TokenType == ua.UserTokenTypeUserName && tok.SecurityPolicyURI != ua.SecurityPolicyURIBasic256 {
				t.Errorf("endpoint %s, %s: password security policy %s, want %s", ep.SecurityPolicyURI, ep.SecurityMode, tok.SecurityPolicyURI, ua.SecurityPolicyURIBasic256)
			}
		}
	}
	if len(res.Endpoints) != 5 {
		t.Errorf("advertised %d endpoints, want 5", len(res.Endpoints))
	}

	// the client logs in with a user name, without and with security, and with the best security available.
	for _, opts := range [][]client.Option{
		{client.WithSecurityPolicyURI(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)},
		{client.WithSecurityPolicyURI(ua.SecurityPolicyURIBasic256, ua.MessageSecurityModeSignAndEncrypt), client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key")},
		{client.WithSecurityPolicyURI(ua.SecurityPolicyURIBasic128Rsa15, ua.MessageSecurityModeSign), client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key")},
		{client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key")},
	} {
		opts = append(opts, client.WithInsecureSkipVerify(), client.WithUserNameIdentity("user", "secret"))
		ch, err := client.Dial(ctx, keyEndpointURL, opts...)
		if err != nil {
			t.Errorf("Dial: %v", err)
			continue
		}
		t.Logf("Logged in over %s, %s", ch.SecurityPolicyURI(), ch.SecurityMode())
		if _, err := ch.Read(ctx, &ua.ReadRequest{NodesToRead: []ua.ReadValueID{{NodeID: ua.VariableIDServerServerStatusState, AttributeID: ua.AttributeIDValue}}}); err != nil {
			t.Errorf("Read over %s, %s: %v", ch.SecurityPolicyURI(), ch.SecurityMode(), err)
		}
		ch.Abort(ctx)
	}
}
