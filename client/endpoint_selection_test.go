// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"context"
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

// newTestCertificate creates a self-signed server certificate for the given key.
func newTestCertificate(t *testing.T, pub, priv any) ua.ByteString {
	t.Helper()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "testserver"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return ua.ByteString(der)
}

func newTestRSACertificate(t *testing.T) ua.ByteString {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return newTestCertificate(t, &key.PublicKey, key)
}

func newTestECDSACertificate(t *testing.T) ua.ByteString {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newTestCertificate(t, &key.PublicKey, key)
}

func testEndpoint(policyURI string, mode ua.MessageSecurityMode, level uint8, cert ua.ByteString, tokens ...ua.UserTokenPolicy) ua.EndpointDescription {
	return ua.EndpointDescription{
		EndpointURL:         "opc.tcp://localhost:46310",
		ServerCertificate:   cert,
		SecurityMode:        mode,
		SecurityPolicyURI:   policyURI,
		UserIdentityTokens:  tokens,
		TransportProfileURI: ua.TransportProfileURIUaTcpTransport,
		SecurityLevel:       level,
	}
}

func anonymousToken(id string) ua.UserTokenPolicy {
	return ua.UserTokenPolicy{PolicyID: id, TokenType: ua.UserTokenTypeAnonymous, SecurityPolicyURI: ua.SecurityPolicyURINone}
}

func userNameToken(id, policyURI string) ua.UserTokenPolicy {
	return ua.UserTokenPolicy{PolicyID: id, TokenType: ua.UserTokenTypeUserName, SecurityPolicyURI: policyURI}
}

func issuedToken(id, policyURI string) ua.UserTokenPolicy {
	return ua.UserTokenPolicy{PolicyID: id, TokenType: ua.UserTokenTypeIssuedToken, SecurityPolicyURI: policyURI}
}

func x509Token(id, policyURI string) ua.UserTokenPolicy {
	return ua.UserTokenPolicy{PolicyID: id, TokenType: ua.UserTokenTypeCertificate, SecurityPolicyURI: policyURI}
}

func newTestClient(t *testing.T, opts ...Option) *Client {
	t.Helper()
	cli := &Client{
		userIdentity:      ua.AnonymousIdentity{},
		securityPolicyURI: ua.SecurityPolicyURIBestAvailable,
	}
	for _, opt := range opts {
		if err := opt(cli); err != nil {
			t.Fatal(err)
		}
	}
	return cli
}

func TestSelectEndpoint(t *testing.T) {
	serverCert := newTestRSACertificate(t)
	ecdsaCert := newTestECDSACertificate(t)
	clientCert := []byte(newTestRSACertificate(t))
	withClientCert := WithClientCertificate(clientCert, nil)
	withUserName := WithUserNameIdentity("user", "password")

	const (
		none   = ua.SecurityPolicyURINone
		b256   = ua.SecurityPolicyURIBasic256Sha256
		aes256 = ua.SecurityPolicyURIAes256Sha256RsaPss
	)

	tests := []struct {
		name       string
		opts       []Option
		endpoints  []ua.EndpointDescription
		wantPolicy string
		wantMode   ua.MessageSecurityMode
		wantToken  string
		wantErr    error
	}{
		{
			name: "anonymous without client certificate selects None",
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, anonymousToken("anon_0")),
				testEndpoint(b256, ua.MessageSecurityModeSignAndEncrypt, 5, serverCert, anonymousToken("anon_1")),
			},
			wantPolicy: none, wantMode: ua.MessageSecurityModeNone, wantToken: "anon_0",
		},
		{
			name: "anonymous with client certificate selects most secure",
			opts: []Option{withClientCert},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, anonymousToken("anon_0")),
				testEndpoint(b256, ua.MessageSecurityModeSign, 1, serverCert, anonymousToken("anon_1")),
				testEndpoint(b256, ua.MessageSecurityModeSignAndEncrypt, 5, serverCert, anonymousToken("anon_2")),
			},
			wantPolicy: b256, wantMode: ua.MessageSecurityModeSignAndEncrypt, wantToken: "anon_2",
		},
		{
			name: "anonymous with client certificate accepts None-only server",
			opts: []Option{withClientCert},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, anonymousToken("anon_0")),
			},
			wantPolicy: none, wantMode: ua.MessageSecurityModeNone, wantToken: "anon_0",
		},
		{
			// the attack of issue #4: discovery advertises only a None endpoint with a plaintext password policy.
			name: "credentials with client certificate reject None-only discovery by default",
			opts: []Option{withClientCert, withUserName},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 255, "", userNameToken("user_0", none)),
			},
			wantErr: ua.BadSecurityModeRejected,
		},
		{
			name: "credentials with client certificate skip None endpoint with highest security level",
			opts: []Option{withClientCert, withUserName},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 255, serverCert, userNameToken("user_0", b256)),
				testEndpoint(b256, ua.MessageSecurityModeSign, 1, serverCert, userNameToken("user_1", b256)),
			},
			wantPolicy: b256, wantMode: ua.MessageSecurityModeSign, wantToken: "user_1",
		},
		{
			name: "x509 identity with client certificate rejects None-only discovery by default",
			opts: []Option{withClientCert, WithX509Identity(clientCert, nil)},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, x509Token("x509_0", b256)),
			},
			wantErr: ua.BadSecurityModeRejected,
		},
		{
			name: "explicit None endpoint is not subject to the default minimum",
			opts: []Option{withClientCert, withUserName, WithSecurityPolicyURI(none, ua.MessageSecurityModeNone)},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, userNameToken("user_0", b256)),
				testEndpoint(b256, ua.MessageSecurityModeSignAndEncrypt, 5, serverCert, userNameToken("user_1", b256)),
			},
			wantPolicy: none, wantMode: ua.MessageSecurityModeNone, wantToken: "user_0",
		},
		{
			name: "min security mode allows None with WithMinSecurityMode(None)",
			opts: []Option{withClientCert, withUserName, WithMinSecurityMode(ua.MessageSecurityModeNone)},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, userNameToken("user_0", b256)),
			},
			wantPolicy: none, wantMode: ua.MessageSecurityModeNone, wantToken: "user_0",
		},
		{
			name: "min security mode rejects weaker discovery",
			opts: []Option{withClientCert, WithMinSecurityMode(ua.MessageSecurityModeSignAndEncrypt)},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, anonymousToken("anon_0")),
				testEndpoint(b256, ua.MessageSecurityModeSign, 1, serverCert, anonymousToken("anon_1")),
			},
			wantErr: ua.BadSecurityModeRejected,
		},
		{
			name: "min security mode applies to explicitly requested endpoint",
			opts: []Option{withClientCert, WithSecurityPolicyURI(none, ua.MessageSecurityModeNone), WithMinSecurityMode(ua.MessageSecurityModeSign)},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, anonymousToken("anon_0")),
			},
			wantErr: ua.BadSecurityModeRejected,
		},
		{
			name: "min security mode without client certificate fails",
			opts: []Option{WithMinSecurityMode(ua.MessageSecurityModeSign)},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, anonymousToken("anon_0")),
				testEndpoint(b256, ua.MessageSecurityModeSign, 1, serverCert, anonymousToken("anon_1")),
			},
			wantErr: ua.BadSecurityModeRejected,
		},
		{
			name: "explicit endpoint not offered by discovery fails",
			opts: []Option{withClientCert, WithSecurityPolicyURI(aes256, ua.MessageSecurityModeSignAndEncrypt)},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, anonymousToken("anon_0")),
				testEndpoint(aes256, ua.MessageSecurityModeSign, 1, serverCert, anonymousToken("anon_1")),
			},
			wantErr: ua.BadSecurityModeRejected,
		},
		{
			name: "explicit secured mode without client certificate fails rather than falling back to None",
			opts: []Option{WithSecurityPolicyURI("", ua.MessageSecurityModeSignAndEncrypt)},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, anonymousToken("anon_0")),
				testEndpoint(b256, ua.MessageSecurityModeSignAndEncrypt, 5, serverCert, anonymousToken("anon_1")),
			},
			wantErr: ua.BadSecurityModeRejected,
		},
		{
			name: "explicit policy with any mode selects most secure mode",
			opts: []Option{withClientCert, WithSecurityPolicyURI(b256, ua.MessageSecurityModeInvalid)},
			endpoints: []ua.EndpointDescription{
				testEndpoint(b256, ua.MessageSecurityModeSign, 1, serverCert, anonymousToken("anon_0")),
				testEndpoint(b256, ua.MessageSecurityModeSignAndEncrypt, 5, serverCert, anonymousToken("anon_1")),
				testEndpoint(aes256, ua.MessageSecurityModeSignAndEncrypt, 6, serverCert, anonymousToken("anon_2")),
			},
			wantPolicy: b256, wantMode: ua.MessageSecurityModeSignAndEncrypt, wantToken: "anon_1",
		},
		{
			name: "plaintext password over None is rejected",
			opts: []Option{withUserName},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, "", userNameToken("user_0", none)),
			},
			wantErr: ua.BadSecurityModeInsufficient,
		},
		{
			name: "plaintext password over None is rejected when token policy is empty",
			opts: []Option{withUserName},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, userNameToken("user_0", "")),
			},
			wantErr: ua.BadSecurityModeInsufficient,
		},
		{
			name: "plaintext password over Sign channel is rejected",
			opts: []Option{withClientCert, withUserName},
			endpoints: []ua.EndpointDescription{
				testEndpoint(b256, ua.MessageSecurityModeSign, 1, serverCert, userNameToken("user_0", none)),
			},
			wantErr: ua.BadSecurityModeInsufficient,
		},
		{
			name: "plaintext password over SignAndEncrypt channel is allowed",
			opts: []Option{withClientCert, withUserName},
			endpoints: []ua.EndpointDescription{
				testEndpoint(b256, ua.MessageSecurityModeSignAndEncrypt, 1, serverCert, userNameToken("user_0", none)),
			},
			wantPolicy: b256, wantMode: ua.MessageSecurityModeSignAndEncrypt, wantToken: "user_0",
		},
		{
			name: "plaintext password over None is allowed with opt-in",
			opts: []Option{withUserName, WithInsecurePlaintextCredentials()},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, "", userNameToken("user_0", none)),
			},
			wantPolicy: none, wantMode: ua.MessageSecurityModeNone, wantToken: "user_0",
		},
		{
			name: "plaintext issued token over None is rejected",
			opts: []Option{WithIssuedIdentity([]byte("token"))},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, "", issuedToken("issued_0", none)),
			},
			wantErr: ua.BadSecurityModeInsufficient,
		},
		{
			name: "encrypted password requires server certificate",
			opts: []Option{withUserName},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, "", userNameToken("user_0", b256)),
			},
			wantErr: ua.BadCertificateInvalid,
		},
		{
			name: "encrypted password requires RSA server certificate",
			opts: []Option{withUserName},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, ecdsaCert, userNameToken("user_0", b256)),
			},
			wantErr: ua.BadCertificateInvalid,
		},
		{
			name: "encrypted password over None with server certificate",
			opts: []Option{withUserName},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, userNameToken("user_0", b256)),
			},
			wantPolicy: none, wantMode: ua.MessageSecurityModeNone, wantToken: "user_0",
		},
		{
			name: "prefers encrypted token policy over plaintext",
			opts: []Option{withUserName, WithInsecurePlaintextCredentials()},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, userNameToken("user_0", none), userNameToken("user_1", b256)),
			},
			wantPolicy: none, wantMode: ua.MessageSecurityModeNone, wantToken: "user_1",
		},
		{
			name: "prefers encrypted token policy over plaintext on SignAndEncrypt channel",
			opts: []Option{withClientCert, withUserName},
			endpoints: []ua.EndpointDescription{
				testEndpoint(b256, ua.MessageSecurityModeSignAndEncrypt, 1, serverCert, userNameToken("user_0", none), userNameToken("user_1", "")),
			},
			wantPolicy: b256, wantMode: ua.MessageSecurityModeSignAndEncrypt, wantToken: "user_1",
		},
		{
			name: "skips plaintext token policy for encrypted one",
			opts: []Option{withUserName},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, userNameToken("user_0", none), userNameToken("user_1", b256)),
			},
			wantPolicy: none, wantMode: ua.MessageSecurityModeNone, wantToken: "user_1",
		},
		{
			name: "unsupported token policy is never used",
			opts: []Option{withUserName, WithInsecurePlaintextCredentials()},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, userNameToken("user_0", "http://example.com/UA/SecurityPolicy#Unknown")),
			},
			wantErr: ua.BadIdentityTokenRejected,
		},
		{
			name: "missing token type is rejected",
			opts: []Option{withUserName},
			endpoints: []ua.EndpointDescription{
				testEndpoint(none, ua.MessageSecurityModeNone, 0, serverCert, anonymousToken("anon_0")),
			},
			wantErr: ua.BadIdentityTokenRejected,
		},
		{
			name: "secured endpoint without server certificate is rejected",
			opts: []Option{withClientCert},
			endpoints: []ua.EndpointDescription{
				testEndpoint(b256, ua.MessageSecurityModeSignAndEncrypt, 5, "", anonymousToken("anon_0")),
			},
			wantErr: ua.BadCertificateInvalid,
		},
		{
			name: "secured endpoint with invalid server certificate is rejected",
			opts: []Option{withClientCert},
			endpoints: []ua.EndpointDescription{
				testEndpoint(b256, ua.MessageSecurityModeSign, 5, ua.ByteString("not a certificate"), anonymousToken("anon_0")),
			},
			wantErr: ua.BadCertificateInvalid,
		},
		{
			name: "secured endpoint with non-RSA server certificate is rejected",
			opts: []Option{withClientCert},
			endpoints: []ua.EndpointDescription{
				testEndpoint(b256, ua.MessageSecurityModeSign, 5, ecdsaCert, anonymousToken("anon_0")),
			},
			wantErr: ua.BadCertificateInvalid,
		},
		{
			name: "secured endpoint without server certificate is skipped for next secured endpoint",
			opts: []Option{withClientCert, withUserName},
			endpoints: []ua.EndpointDescription{
				testEndpoint(aes256, ua.MessageSecurityModeSignAndEncrypt, 6, "", userNameToken("user_0", aes256)),
				testEndpoint(b256, ua.MessageSecurityModeSignAndEncrypt, 5, serverCert, userNameToken("user_1", b256)),
			},
			wantPolicy: b256, wantMode: ua.MessageSecurityModeSignAndEncrypt, wantToken: "user_1",
		},
		{
			name: "unsupported and inconsistent endpoints are skipped",
			opts: []Option{withClientCert},
			endpoints: []ua.EndpointDescription{
				testEndpoint("http://example.com/UA/SecurityPolicy#Unknown", ua.MessageSecurityModeSignAndEncrypt, 9, serverCert, anonymousToken("anon_0")),
				testEndpoint(none, ua.MessageSecurityModeSignAndEncrypt, 8, serverCert, anonymousToken("anon_1")),
				testEndpoint(b256, ua.MessageSecurityModeNone, 7, serverCert, anonymousToken("anon_2")),
				testEndpoint(b256, ua.MessageSecurityModeInvalid, 6, serverCert, anonymousToken("anon_3")),
				testEndpoint(b256, ua.MessageSecurityModeSign, 1, serverCert, anonymousToken("anon_4")),
			},
			wantPolicy: b256, wantMode: ua.MessageSecurityModeSign, wantToken: "anon_4",
		},
		{
			name: "endpoints with other transports are skipped",
			opts: []Option{withClientCert},
			endpoints: func() []ua.EndpointDescription {
				e1 := testEndpoint(aes256, ua.MessageSecurityModeSignAndEncrypt, 9, serverCert, anonymousToken("anon_0"))
				e1.TransportProfileURI = ua.TransportProfileURIHttpsBinaryTransport
				e2 := testEndpoint(b256, ua.MessageSecurityModeSignAndEncrypt, 5, serverCert, anonymousToken("anon_1"))
				return []ua.EndpointDescription{e1, e2}
			}(),
			wantPolicy: b256, wantMode: ua.MessageSecurityModeSignAndEncrypt, wantToken: "anon_1",
		},
		{
			name:    "no endpoints",
			wantErr: ua.BadSecurityModeRejected,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli := newTestClient(t, tt.opts...)
			e, tok, err := cli.selectEndpoint(tt.endpoints)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Fatalf("selectEndpoint() error = %v, want %v", err, tt.wantErr)
				}
				if e != nil || tok != nil {
					t.Fatalf("selectEndpoint() returned endpoint with error")
				}
				return
			}
			if err != nil {
				t.Fatalf("selectEndpoint() error = %v", err)
			}
			if e.SecurityPolicyURI != tt.wantPolicy || e.SecurityMode != tt.wantMode {
				t.Errorf("selectEndpoint() = %s %s, want %s %s", e.SecurityPolicyURI, e.SecurityMode, tt.wantPolicy, tt.wantMode)
			}
			if tok == nil || tok.PolicyID != tt.wantToken {
				t.Errorf("selectEndpoint() token policy = %v, want %s", tok, tt.wantToken)
			}
		})
	}
}

func TestWithMinSecurityModeRejectsInvalidMode(t *testing.T) {
	cli := &Client{}
	if err := WithMinSecurityMode(ua.MessageSecurityModeInvalid)(cli); err != ua.BadInvalidArgument {
		t.Errorf("WithMinSecurityMode(Invalid) error = %v, want %v", err, ua.BadInvalidArgument)
	}
	if err := WithMinSecurityMode(ua.MessageSecurityMode(4))(cli); err != ua.BadInvalidArgument {
		t.Errorf("WithMinSecurityMode(4) error = %v, want %v", err, ua.BadInvalidArgument)
	}
}

func TestVerifyServerEndpoints(t *testing.T) {
	cert := newTestRSACertificate(t)
	otherCert := newTestRSACertificate(t)
	discovered := []ua.EndpointDescription{
		testEndpoint(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 0, cert, anonymousToken("anon_0"), userNameToken("user_0", ua.SecurityPolicyURIBasic256Sha256)),
		testEndpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign, 1, cert, anonymousToken("anon_1"), userNameToken("user_1", ua.SecurityPolicyURIBasic256Sha256)),
		testEndpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 2, cert, anonymousToken("anon_2"), userNameToken("user_2", ua.SecurityPolicyURIBasic256Sha256)),
	}
	clone := func() []ua.EndpointDescription {
		eps := make([]ua.EndpointDescription, len(discovered))
		for i, e := range discovered {
			e.UserIdentityTokens = append([]ua.UserTokenPolicy(nil), e.UserIdentityTokens...)
			eps[i] = e
		}
		return eps
	}

	tests := []struct {
		name    string
		modify  func([]ua.EndpointDescription) []ua.EndpointDescription
		wantErr bool
	}{
		{name: "identical", modify: func(eps []ua.EndpointDescription) []ua.EndpointDescription { return eps }},
		{name: "reordered", modify: func(eps []ua.EndpointDescription) []ua.EndpointDescription {
			return []ua.EndpointDescription{eps[2], eps[0], eps[1]}
		}},
		{name: "different endpoint url", modify: func(eps []ua.EndpointDescription) []ua.EndpointDescription {
			for i := range eps {
				eps[i].EndpointURL = "opc.tcp://otherhost:4840"
			}
			return eps
		}},
		{name: "certificates omitted", modify: func(eps []ua.EndpointDescription) []ua.EndpointDescription {
			for i := range eps {
				eps[i].ServerCertificate = ""
			}
			return eps
		}},
		{name: "other transports ignored", modify: func(eps []ua.EndpointDescription) []ua.EndpointDescription {
			e := eps[2]
			e.TransportProfileURI = ua.TransportProfileURIHttpsBinaryTransport
			e.SecurityLevel = 9
			return append(eps, e)
		}},
		{name: "secured endpoints stripped from discovery", wantErr: true, modify: func(eps []ua.EndpointDescription) []ua.EndpointDescription {
			e := testEndpoint(ua.SecurityPolicyURIAes256Sha256RsaPss, ua.MessageSecurityModeSignAndEncrypt, 3, cert, anonymousToken("anon_3"))
			return append(eps, e)
		}},
		{name: "endpoint added to discovery", wantErr: true, modify: func(eps []ua.EndpointDescription) []ua.EndpointDescription {
			return eps[1:]
		}},
		{name: "token policy weakened in discovery", wantErr: true, modify: func(eps []ua.EndpointDescription) []ua.EndpointDescription {
			eps[0].UserIdentityTokens[1].SecurityPolicyURI = ua.SecurityPolicyURIBasic128Rsa15
			return eps
		}},
		{name: "token policy removed in discovery", wantErr: true, modify: func(eps []ua.EndpointDescription) []ua.EndpointDescription {
			eps[0].UserIdentityTokens = eps[0].UserIdentityTokens[:1]
			return eps
		}},
		{name: "security level changed", wantErr: true, modify: func(eps []ua.EndpointDescription) []ua.EndpointDescription {
			eps[0].SecurityLevel = 255
			return eps
		}},
		{name: "security mode changed", wantErr: true, modify: func(eps []ua.EndpointDescription) []ua.EndpointDescription {
			eps[2].SecurityMode = ua.MessageSecurityModeSign
			return eps
		}},
		{name: "certificate changed", wantErr: true, modify: func(eps []ua.EndpointDescription) []ua.EndpointDescription {
			eps[1].ServerCertificate = otherCert
			return eps
		}},
		{name: "server returned no endpoints", wantErr: true, modify: func(eps []ua.EndpointDescription) []ua.EndpointDescription {
			return nil
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyServerEndpoints(discovered, tt.modify(clone()))
			if tt.wantErr && err != ua.BadSecurityChecksFailed {
				t.Errorf("verifyServerEndpoints() error = %v, want %v", err, ua.BadSecurityChecksFailed)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("verifyServerEndpoints() error = %v, want nil", err)
			}
		})
	}
}

// TestOpenRejectsSecuredChannelWithoutServerCertificate verifies that a Sign or SignAndEncrypt channel
// without a server certificate fails before connecting, rather than skipping certificate validation.
func TestOpenRejectsSecuredChannelWithoutServerCertificate(t *testing.T) {
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
		ch := newClientSecureChannel(
			ua.ApplicationDescription{},
			nil,
			nil,
			"opc.tcp://127.0.0.1:1", // nothing is listening, so a dial would fail with a different error.
			ua.SecurityPolicyURIBasic256Sha256,
			mode,
			nil,
			defaultConnectTimeout,
			"", "", "", "", "",
			true, true, true, true,
			defaultTimeoutHint,
			defaultDiagnosticsHint,
			defaultTokenRequestedLifetime,
			defaultMaxBufferSize,
			defaultMaxMessageSize,
			defaultMaxChunkCount,
			false,
		)
		if err := ch.Open(context.Background()); err != ua.BadCertificateInvalid {
			t.Errorf("Open(%s) error = %v, want %v", mode, err, ua.BadCertificateInvalid)
		}
	}
}
