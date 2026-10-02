// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

// sessionBindingTestPort is the port of the server started by TestSessionCertificateBinding.
const sessionBindingTestPort = 46411

// sbApplication is an application instance certificate (or user certificate) used by TestSessionCertificateBinding.
type sbApplication struct {
	certificate    []byte // DER encoded certificate, optionally followed by its issuer chain.
	key            *rsa.PrivateKey
	applicationURI string
}

// newSBCertificate creates a certificate for appName, with the uris urn:host:appName or the given uris.
// The certificate is self-signed if issuer is nil, otherwise it is signed by issuer and followed by the
// issuer certificate.
func newSBCertificate(t *testing.T, appName string, isCA bool, issuer *sbApplication, uriStrings ...string) sbApplication {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if len(uriStrings) == 0 {
		uriStrings = []string{fmt.Sprintf("urn:%s:%s", host, appName)}
	}
	applicationURI := uriStrings[0]
	var uris []*url.URL
	for _, s := range uriStrings {
		uri, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, uri)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: appName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              []string{host, "localhost"},
		URIs:                  uris,
	}
	parent, signer := template, key
	if issuer != nil {
		parent, err = x509.ParseCertificate(issuer.certificate)
		if err != nil {
			t.Fatal(err)
		}
		signer = issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	if issuer != nil {
		der = append(der, issuer.certificate...)
	}
	return sbApplication{certificate: der, key: key, applicationURI: applicationURI}
}

// leaf returns the first certificate of the certificate chain of app.
func (app sbApplication) leaf(t *testing.T) []byte {
	t.Helper()
	crts, err := x509.ParseCertificates(app.certificate)
	if err != nil || len(crts) == 0 {
		t.Fatalf("parse certificate: %v", err)
	}
	return crts[0].Raw
}

// sbRecorder records the application uris passed to the identity authenticators.
type sbRecorder struct {
	sync.Mutex
	uris []string
}

func (r *sbRecorder) record(applicationURI string) {
	r.Lock()
	defer r.Unlock()
	r.uris = append(r.uris, applicationURI)
}

// last returns the application uri of the most recent authentication.
func (r *sbRecorder) last(t *testing.T) string {
	t.Helper()
	r.Lock()
	defer r.Unlock()
	if len(r.uris) == 0 {
		t.Fatal("authenticator was not called")
	}
	return r.uris[len(r.uris)-1]
}

// sbConn is a client connection opened with the certificate of app, to the server endpoint.
type sbConn struct {
	cli      *Client
	app      sbApplication
	endpoint ua.EndpointDescription
}

// TestSessionCertificateBinding verifies that sessions are bound to the client certificate
// that was authenticated by the secure channel. See issue #7.
func TestSessionCertificateBinding(t *testing.T) {
	ctx := context.Background()
	endpointURL := fmt.Sprintf("opc.tcp://%s:%d", host, sessionBindingTestPort)
	recorder := &sbRecorder{}

	srv, err := server.New(
		ua.ApplicationDescription{
			ApplicationURI: fmt.Sprintf("urn:%s:testserver", host),
			ProductURI:     "http://github.com/awcullen/opcua",
			ApplicationName: ua.LocalizedText{
				Text:   fmt.Sprintf("sessionbindingserver@%s", host),
				Locale: "en",
			},
			ApplicationType: ua.ApplicationTypeServer,
			DiscoveryURLs:   []string{endpointURL},
		},
		"./pki/server.crt",
		"./pki/server.key",
		endpointURL,
		server.WithAuthenticateAnonymousIdentityFunc(func(userIdentity ua.AnonymousIdentity, applicationURI string, endpointURL string) error {
			recorder.record(applicationURI)
			return nil
		}),
		server.WithAuthenticateX509IdentityFunc(func(userIdentity ua.X509Identity, applicationURI string, endpointURL string) error {
			recorder.record(applicationURI)
			return nil
		}),
		server.WithSecurityPolicyNone(true),
		server.WithInsecureSkipVerify(),
	)
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()
	defer srv.Close()
	sbWaitForServer(t, endpointURL)

	appA := newSBCertificate(t, "binding-client-a", false, nil)
	appB := newSBCertificate(t, "binding-client-b", false, nil)
	user1 := newSBCertificate(t, "binding-user-1", false, nil)
	user2 := newSBCertificate(t, "binding-user-2", false, nil)
	user1Other := newSBCertificate(t, "binding-user-1", false, nil) // same subject as user1

	const (
		basic256Sha256 = ua.SecurityPolicyURIBasic256Sha256
		aes128         = ua.SecurityPolicyURIAes128Sha256RsaOaep
		none           = ua.SecurityPolicyURINone
		sign           = ua.MessageSecurityModeSign
		signAndEncrypt = ua.MessageSecurityModeSignAndEncrypt
		modeNone       = ua.MessageSecurityModeNone
	)

	t.Run("AuthenticatorReceivesVerifiedApplicationURI", func(t *testing.T) {
		c := sbDial(t, ctx, endpointURL, appA, basic256Sha256, sign)
		if got := recorder.last(t); got != appA.applicationURI {
			t.Errorf("authenticator received application uri %q, want %q", got, appA.applicationURI)
		}
		// a second session on the same channel, using the channel certificate.
		res, err := sbCreateSession(ctx, c.cli, appA.certificate, appA.applicationURI)
		if err != nil {
			t.Fatalf("CreateSession with channel certificate: %v", err)
		}
		if _, err := sbActivateSession(ctx, c, res.AuthenticationToken, res.ServerNonce, nil); err != nil {
			t.Fatalf("ActivateSession on creating channel: %v", err)
		}
		if got := recorder.last(t); got != appA.applicationURI {
			t.Errorf("authenticator received application uri %q, want %q", got, appA.applicationURI)
		}
		// the client certificate may be followed by other certificates of its chain.
		chain := append(append([]byte{}, appA.certificate...), appB.certificate...)
		res, err = sbCreateSession(ctx, c.cli, chain, appA.applicationURI)
		if err != nil {
			t.Fatalf("CreateSession with channel certificate chain: %v", err)
		}
		if _, err := sbActivateSession(ctx, c, res.AuthenticationToken, res.ServerNonce, nil); err != nil {
			t.Fatalf("ActivateSession of session created with certificate chain: %v", err)
		}
	})

	t.Run("CertificateChainInOpenSecureChannel", func(t *testing.T) {
		ca := newSBCertificate(t, "binding-ca", true, nil)
		appC := newSBCertificate(t, "binding-client-c", false, &ca)
		// the client sends the chain in OpenSecureChannel and CreateSession.
		c := sbDial(t, ctx, endpointURL, appC, basic256Sha256, sign)
		if got := recorder.last(t); got != appC.applicationURI {
			t.Errorf("authenticator received application uri %q, want %q", got, appC.applicationURI)
		}
		// the client certificate without the chain.
		res, err := sbCreateSession(ctx, c.cli, appC.leaf(t), appC.applicationURI)
		if err != nil {
			t.Fatalf("CreateSession with channel leaf certificate: %v", err)
		}
		if _, err := sbActivateSession(ctx, c, res.AuthenticationToken, res.ServerNonce, nil); err != nil {
			t.Fatalf("ActivateSession: %v", err)
		}
		// the issuer certificate.
		if _, err := sbCreateSession(ctx, c.cli, ca.certificate, ca.applicationURI); err != ua.BadCertificateInvalid {
			t.Fatalf("CreateSession with issuer certificate: got %v, want %v", err, ua.BadCertificateInvalid)
		}
	})

	t.Run("CertificateURIInvalidRejected", func(t *testing.T) {
		// an application instance certificate shall have exactly one absolute uri.
		cases := map[string][]string{
			"multiple": {fmt.Sprintf("urn:%s:binding-client-m", host), appB.applicationURI},
			"relative": {"binding-client-r"},
		}
		for name, uris := range cases {
			app := newSBCertificate(t, "binding-client-"+name, false, nil, uris...)
			cli, err := Dial(
				ctx,
				endpointURL,
				WithSecurityPolicyURI(basic256Sha256, sign),
				WithClientCertificate(app.certificate, app.key),
				WithInsecureSkipVerify(),
			)
			if err == nil {
				cli.Abort(ctx)
			}
			if err != ua.BadCertificateURIInvalid {
				t.Errorf("Dial with certificate with %s uris: got %v, want %v", name, err, ua.BadCertificateURIInvalid)
			}
		}
	})

	t.Run("CreateSessionWithOtherCertificateRejected", func(t *testing.T) {
		c := sbDial(t, ctx, endpointURL, appA, basic256Sha256, sign)
		// certificate (and matching application uri) of another application.
		_, err := sbCreateSession(ctx, c.cli, appB.certificate, appB.applicationURI)
		if err != ua.BadCertificateInvalid {
			t.Fatalf("CreateSession with certificate other than the channel certificate: got %v, want %v", err, ua.BadCertificateInvalid)
		}
		// certificate of another application, followed by the channel certificate.
		chain := append(append([]byte{}, appB.certificate...), appA.certificate...)
		_, err = sbCreateSession(ctx, c.cli, chain, appB.applicationURI)
		if err != ua.BadCertificateInvalid {
			t.Fatalf("CreateSession with other certificate followed by the channel certificate: got %v, want %v", err, ua.BadCertificateInvalid)
		}
		// application uri of another application.
		_, err = sbCreateSession(ctx, c.cli, appA.certificate, appB.applicationURI)
		if err != ua.BadCertificateURIInvalid {
			t.Fatalf("CreateSession with application uri of another application: got %v, want %v", err, ua.BadCertificateURIInvalid)
		}
		// missing certificate.
		_, err = sbCreateSession(ctx, c.cli, nil, appA.applicationURI)
		if err != ua.BadCertificateInvalid {
			t.Fatalf("CreateSession without certificate: got %v, want %v", err, ua.BadCertificateInvalid)
		}
	})

	t.Run("ActivateSessionWithOtherSignatureRejected", func(t *testing.T) {
		c := sbDial(t, ctx, endpointURL, appA, basic256Sha256, sign)
		res, err := sbCreateSession(ctx, c.cli, appA.certificate, appA.applicationURI)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		// signed with the key of another application.
		other := c
		other.app = appB
		if _, err := sbActivateSession(ctx, other, res.AuthenticationToken, res.ServerNonce, nil); err != ua.BadApplicationSignatureInvalid {
			t.Fatalf("ActivateSession signed by other key: got %v, want %v", err, ua.BadApplicationSignatureInvalid)
		}
		if _, err := sbActivateSession(ctx, c, res.AuthenticationToken, res.ServerNonce, nil); err != nil {
			t.Fatalf("ActivateSession: %v", err)
		}
	})

	t.Run("FirstActivationOnOtherChannelRejected", func(t *testing.T) {
		cA := sbDial(t, ctx, endpointURL, appA, basic256Sha256, sign)
		res, err := sbCreateSession(ctx, cA.cli, appA.certificate, appA.applicationURI)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		// channel authenticated with another certificate.
		cB := sbDial(t, ctx, endpointURL, appB, basic256Sha256, sign)
		_, err = sbActivateSession(ctx, cB, res.AuthenticationToken, res.ServerNonce, nil)
		if err != ua.BadSecureChannelIDInvalid {
			t.Fatalf("first ActivateSession on channel with other certificate: got %v, want %v", err, ua.BadSecureChannelIDInvalid)
		}
		// channel authenticated with the same certificate.
		cA2 := sbDial(t, ctx, endpointURL, appA, basic256Sha256, sign)
		_, err = sbActivateSession(ctx, cA2, res.AuthenticationToken, res.ServerNonce, nil)
		if err != ua.BadSecureChannelIDInvalid {
			t.Fatalf("first ActivateSession on other channel: got %v, want %v", err, ua.BadSecureChannelIDInvalid)
		}
		// the creating channel may still activate the session.
		if _, err := sbActivateSession(ctx, cA, res.AuthenticationToken, res.ServerNonce, nil); err != nil {
			t.Fatalf("ActivateSession on creating channel: %v", err)
		}
	})

	t.Run("TransferToChannelWithOtherCertificateRejected", func(t *testing.T) {
		cA := sbDial(t, ctx, endpointURL, appA, basic256Sha256, signAndEncrypt)
		cB := sbDial(t, ctx, endpointURL, appB, basic256Sha256, signAndEncrypt)
		token, err := sbTransfer(t, ctx, cA, cB, nil, nil)
		if err != ua.BadSecurityChecksFailed {
			t.Fatalf("ActivateSession on channel with other certificate: got %v, want %v", err, ua.BadSecurityChecksFailed)
		}
		// session remains usable on the original channel.
		if err := sbReadServerState(ctx, cA.cli, token); err != nil {
			t.Fatalf("Read on original channel after rejected transfer: %v", err)
		}
		// session is not usable on the other channel.
		if err := sbReadServerState(ctx, cB.cli, token); err != ua.BadSecureChannelIDInvalid {
			t.Fatalf("Read on other channel after rejected transfer: got %v, want %v", err, ua.BadSecureChannelIDInvalid)
		}
	})

	t.Run("TransferToChannelWithSameCertificate", func(t *testing.T) {
		cases := []struct {
			name        string
			fromPolicy  string
			fromMode    ua.MessageSecurityMode
			toPolicy    string
			toMode      ua.MessageSecurityMode
			fromUser    *sbApplication
			toUser      *sbApplication
			want        ua.StatusCode
			transferred bool
		}{
			{"Anonymous", basic256Sha256, signAndEncrypt, basic256Sha256, signAndEncrypt, nil, nil, ua.Good, true},
			{"AnonymousSign", basic256Sha256, sign, basic256Sha256, sign, nil, nil, ua.BadSecurityModeInsufficient, false},
			{"AnonymousNone", none, modeNone, none, modeNone, nil, nil, ua.BadSecurityChecksFailed, false},
			{"SameUser", basic256Sha256, sign, basic256Sha256, sign, &user1, &user1, ua.Good, true},
			{"OtherUser", basic256Sha256, signAndEncrypt, basic256Sha256, signAndEncrypt, &user1, &user2, ua.BadIdentityChangeNotSupported, false},
			{"OtherUserSameSubject", basic256Sha256, signAndEncrypt, basic256Sha256, signAndEncrypt, &user1, &user1Other, ua.BadIdentityChangeNotSupported, false},
			{"AnonymousToUser", basic256Sha256, signAndEncrypt, basic256Sha256, signAndEncrypt, nil, &user1, ua.BadIdentityChangeNotSupported, false},
			{"OtherPolicy", basic256Sha256, signAndEncrypt, aes128, signAndEncrypt, &user1, &user1, ua.BadSecurityChecksFailed, false},
			{"OtherMode", basic256Sha256, signAndEncrypt, basic256Sha256, sign, &user1, &user1, ua.BadSecurityChecksFailed, false},
			{"SecuredToNone", basic256Sha256, signAndEncrypt, none, modeNone, nil, nil, ua.BadSecurityChecksFailed, false},
			{"NoneToSecured", none, modeNone, basic256Sha256, signAndEncrypt, nil, nil, ua.BadSecurityChecksFailed, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				from := sbDial(t, ctx, endpointURL, appA, tc.fromPolicy, tc.fromMode)
				to := sbDial(t, ctx, endpointURL, appA, tc.toPolicy, tc.toMode)
				token, err := sbTransfer(t, ctx, from, to, tc.fromUser, tc.toUser)
				if tc.want == ua.Good {
					if err != nil {
						t.Fatalf("transfer: %v", err)
					}
				} else if err != tc.want {
					t.Fatalf("transfer: got %v, want %v", err, tc.want)
				}
				// after a transfer, requests are only accepted on the new channel.
				oldErr, newErr := error(nil), error(ua.BadSecureChannelIDInvalid)
				if tc.transferred {
					oldErr, newErr = ua.BadSecureChannelIDInvalid, nil
				}
				if err := sbReadServerState(ctx, from.cli, token); err != oldErr {
					t.Errorf("Read on old channel: got %v, want %v", err, oldErr)
				}
				if err := sbReadServerState(ctx, to.cli, token); err != newErr {
					t.Errorf("Read on new channel: got %v, want %v", err, newErr)
				}
			})
		}
	})

	t.Run("UnsecuredChannelApplicationURINotVerified", func(t *testing.T) {
		// the client claims the application uri of its certificate, but the certificate
		// is not authenticated by a secure channel without security.
		sbDial(t, ctx, endpointURL, appA, none, modeNone)
		if got := recorder.last(t); got != "" {
			t.Errorf("authenticator received unverified application uri %q, want empty", got)
		}
	})
}

// sbWaitForServer waits until the server at endpointURL responds.
func sbWaitForServer(t *testing.T, endpointURL string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := FindServers(context.Background(), &ua.FindServersRequest{EndpointURL: endpointURL})
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server at %s did not start: %v", endpointURL, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// sbDial opens a secure channel and an anonymous session, presenting the certificate of app.
func sbDial(t *testing.T, ctx context.Context, endpointURL string, app sbApplication, securityPolicyURI string, securityMode ua.MessageSecurityMode) sbConn {
	t.Helper()
	cli, err := Dial(
		ctx,
		endpointURL,
		WithSecurityPolicyURI(securityPolicyURI, securityMode),
		WithClientCertificate(app.certificate, app.key),
		WithInsecureSkipVerify(),
	)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { cli.Abort(ctx) })
	res, err := GetEndpoints(ctx, &ua.GetEndpointsRequest{EndpointURL: endpointURL})
	if err != nil {
		t.Fatalf("GetEndpoints: %v", err)
	}
	for _, ep := range res.Endpoints {
		if ep.SecurityPolicyURI == cli.SecurityPolicyURI() && ep.SecurityMode == cli.SecurityMode() {
			return sbConn{cli: cli, app: app, endpoint: ep}
		}
	}
	t.Fatalf("endpoint %s, %s not found", cli.SecurityPolicyURI(), cli.SecurityMode())
	return sbConn{}
}

// sbTransfer creates and activates a session on the secure channel of from, using user identity fromUser
// (anonymous if nil), then activates the session on the secure channel of to, using user identity toUser.
// It returns the authentication token of the session and the result of the transfer.
func sbTransfer(t *testing.T, ctx context.Context, from, to sbConn, fromUser, toUser *sbApplication) (ua.NodeID, error) {
	t.Helper()
	res, err := sbCreateSession(ctx, from.cli, from.app.certificate, from.app.applicationURI)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	act, err := sbActivateSession(ctx, from, res.AuthenticationToken, res.ServerNonce, fromUser)
	if err != nil {
		t.Fatalf("ActivateSession: %v", err)
	}
	_, err = sbActivateSession(ctx, to, res.AuthenticationToken, act.ServerNonce, toUser)
	return res.AuthenticationToken, err
}

// sbWithToken sends requests of f using the given authentication token. The token remains set afterwards.
func sbWithToken(cli *Client, token ua.NodeID, f func() error) error {
	cli.channel.SetAuthenticationToken(token)
	return f()
}

// sbCreateSession sends a CreateSessionRequest on the secure channel of cli.
func sbCreateSession(ctx context.Context, cli *Client, certificate []byte, applicationURI string) (*ua.CreateSessionResponse, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return cli.createSession(ctx, &ua.CreateSessionRequest{
		ClientDescription: ua.ApplicationDescription{
			ApplicationURI:  applicationURI,
			ApplicationName: ua.LocalizedText{Text: "binding-client"},
			ApplicationType: ua.ApplicationTypeClient,
		},
		EndpointURL:             cli.EndpointURL(),
		SessionName:             "binding-session",
		ClientNonce:             ua.ByteString(nonce),
		ClientCertificate:       ua.ByteString(certificate),
		RequestedSessionTimeout: 120000,
		MaxResponseMessageSize:  64 * 1024 * 1024,
	})
}

// sbSign signs the server certificate and nonce with key, as required by the security policy.
func sbSign(securityPolicyURI string, serverCertificate ua.ByteString, serverNonce ua.ByteString, key *rsa.PrivateKey) (ua.SignatureData, error) {
	switch securityPolicyURI {
	case ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256:
		hash := crypto.SHA1.New()
		hash.Write([]byte(serverCertificate))
		hash.Write([]byte(serverNonce))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, hash.Sum(nil))
		return ua.SignatureData{Signature: ua.ByteString(sig), Algorithm: ua.RsaSha1Signature}, err
	case ua.SecurityPolicyURIBasic256Sha256, ua.SecurityPolicyURIAes128Sha256RsaOaep:
		hash := crypto.SHA256.New()
		hash.Write([]byte(serverCertificate))
		hash.Write([]byte(serverNonce))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash.Sum(nil))
		return ua.SignatureData{Signature: ua.ByteString(sig), Algorithm: ua.RsaSha256Signature}, err
	case ua.SecurityPolicyURIAes256Sha256RsaPss:
		hash := crypto.SHA256.New()
		hash.Write([]byte(serverCertificate))
		hash.Write([]byte(serverNonce))
		sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		return ua.SignatureData{Signature: ua.ByteString(sig), Algorithm: ua.RsaPssSha256Signature}, err
	default:
		return ua.SignatureData{}, nil
	}
}

// sbTokenPolicy returns the user token policy of the endpoint of c for the token type.
func sbTokenPolicy(c sbConn, tokenType ua.UserTokenType) ua.UserTokenPolicy {
	for _, p := range c.endpoint.UserIdentityTokens {
		if p.TokenType == tokenType {
			if p.SecurityPolicyURI == "" {
				p.SecurityPolicyURI = c.endpoint.SecurityPolicyURI
			}
			return p
		}
	}
	return ua.UserTokenPolicy{}
}

// sbActivateSession sends an ActivateSessionRequest for the session with the given authentication token
// on the secure channel of c, signed with the key of c.app. The user identity is the X509 identity of user,
// or anonymous if user is nil.
func sbActivateSession(ctx context.Context, c sbConn, token ua.NodeID, serverNonce ua.ByteString, user *sbApplication) (*ua.ActivateSessionResponse, error) {
	if user == nil {
		policy := sbTokenPolicy(c, ua.UserTokenTypeAnonymous)
		return sbActivate(ctx, c, token, serverNonce, ua.AnonymousIdentityToken{PolicyID: policy.PolicyID}, ua.SignatureData{})
	}
	policy := sbTokenPolicy(c, ua.UserTokenTypeCertificate)
	identityTokenSignature, err := sbSign(policy.SecurityPolicyURI, c.endpoint.ServerCertificate, serverNonce, user.key)
	if err != nil {
		return nil, err
	}
	identityToken := ua.X509IdentityToken{CertificateData: ua.ByteString(user.certificate), PolicyID: policy.PolicyID}
	return sbActivate(ctx, c, token, serverNonce, identityToken, identityTokenSignature)
}

// sbActivate sends an ActivateSessionRequest with the given user identity token for the session with the given
// authentication token on the secure channel of c, signed with the key of c.app.
func sbActivate(ctx context.Context, c sbConn, token ua.NodeID, serverNonce ua.ByteString, identityToken any, identityTokenSignature ua.SignatureData) (*ua.ActivateSessionResponse, error) {
	signature, err := sbSign(c.endpoint.SecurityPolicyURI, c.endpoint.ServerCertificate, serverNonce, c.app.key)
	if err != nil {
		return nil, err
	}
	var res *ua.ActivateSessionResponse
	err = sbWithToken(c.cli, token, func() error {
		var err error
		res, err = c.cli.activateSession(ctx, &ua.ActivateSessionRequest{
			ClientSignature:    signature,
			LocaleIDs:          []string{"en"},
			UserIdentityToken:  identityToken,
			UserTokenSignature: identityTokenSignature,
		})
		return err
	})
	return res, err
}

// sbReadServerState reads the server state using the session with the given authentication token.
func sbReadServerState(ctx context.Context, cli *Client, token ua.NodeID) error {
	return sbWithToken(cli, token, func() error {
		_, err := cli.Read(ctx, &ua.ReadRequest{
			NodesToRead: []ua.ReadValueID{
				{NodeID: ua.VariableIDServerServerStatusState, AttributeID: ua.AttributeIDValue},
			},
		})
		return err
	})
}
