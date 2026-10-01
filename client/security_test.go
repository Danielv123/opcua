// Copyright 2021 Converter Systems LLC. All rights reserved.

package client_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
)

// testPassword is a distinctive password, so the tests can check it never appears on the wire.
const testPassword = "pa55w0rd-must-not-leak"

// fakeServer is a minimal OPC UA server that speaks just enough UA TCP with security policy None to
// serve crafted endpoint descriptions. It simulates an on-path attacker that tampers with discovery.
// If forwardAddr is set, every connection after the first (discovery) connection is forwarded to it.
type fakeServer struct {
	discoveryEndpoints []ua.EndpointDescription // returned by GetEndpoints
	sessionEndpoints   []ua.EndpointDescription // returned by CreateSession
	serverCertificate  ua.ByteString            // returned by CreateSession
	forwardAddr        string

	ln          net.Listener
	endpointURL string

	mu              sync.Mutex
	conns           int
	received        bytes.Buffer       // all bytes received from clients
	requests        []string           // names of the service requests handled
	tokens          []any              // user identity tokens received in ActivateSession
	tokenSignatures []ua.SignatureData // user token signatures received in ActivateSession
}

type fakeEncodingContext struct{}

func (fakeEncodingContext) NamespaceURIs() []string { return []string{"http://opcfoundation.org/UA/"} }

// start listens on an ephemeral port and serves connections until the test ends.
func (s *fakeServer) start(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	s.endpointURL = fmt.Sprintf("opc.tcp://%s", ln.Addr().String())
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns++
			n := s.conns
			s.mu.Unlock()
			if s.forwardAddr != "" && n > 1 {
				go s.forward(conn)
			} else {
				go s.handle(conn)
			}
		}
	}()
}

func (s *fakeServer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.received.Write(p)
}

// sawPassword returns true if the password was received in plaintext.
func (s *fakeServer) sawPassword() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Contains(s.received.Bytes(), []byte(testPassword))
}

func (s *fakeServer) handled(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.requests {
		if r == name {
			return true
		}
	}
	return false
}

func (s *fakeServer) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

func (s *fakeServer) forward(conn net.Conn) {
	defer conn.Close()
	upstream, err := net.Dial("tcp", s.forwardAddr)
	if err != nil {
		return
	}
	defer upstream.Close()
	go func() {
		io.Copy(conn, upstream)
		conn.Close()
	}()
	io.Copy(upstream, io.TeeReader(conn, s))
}

func (s *fakeServer) handle(conn net.Conn) {
	defer conn.Close()
	const channelID, tokenID uint32 = 1, 1
	var sequenceNumber uint32
	ec := fakeEncodingContext{}
	for {
		header := make([]byte, 8)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		msgType := binary.LittleEndian.Uint32(header[0:4])
		msgLen := binary.LittleEndian.Uint32(header[4:8])
		if msgLen < 8 || msgLen > 1<<20 {
			return
		}
		body := make([]byte, msgLen-8)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		s.Write(header)
		s.Write(body)
		dec := ua.NewBinaryDecoder(bytes.NewReader(body), ec)
		out := new(bytes.Buffer)
		enc := ua.NewBinaryEncoder(out, ec)

		switch msgType {
		case ua.MessageTypeHello:
			enc.WriteUInt32(0)     // protocol version
			enc.WriteUInt32(65536) // receive buffer size
			enc.WriteUInt32(65536) // send buffer size
			enc.WriteUInt32(0)     // max message size
			enc.WriteUInt32(0)     // max chunk count
			writeChunk(conn, ua.MessageTypeAck, out.Bytes())

		case ua.MessageTypeOpenFinal:
			var unused, requestID uint32
			var policyURI string
			var senderCertificate, receiverThumbprint ua.ByteString
			var nodeID ua.NodeID
			dec.ReadUInt32(&unused) // secure channel id
			dec.ReadString(&policyURI)
			dec.ReadByteString(&senderCertificate)
			dec.ReadByteString(&receiverThumbprint)
			dec.ReadUInt32(&unused) // sequence number
			dec.ReadUInt32(&requestID)
			dec.ReadNodeID(&nodeID)
			req := new(ua.OpenSecureChannelRequest)
			if policyURI != ua.SecurityPolicyURINone || nodeID != ua.ObjectIDOpenSecureChannelRequestEncodingDefaultBinary || dec.Decode(req) != nil {
				return
			}
			res := &ua.OpenSecureChannelResponse{
				ResponseHeader: ua.ResponseHeader{Timestamp: time.Now(), RequestHandle: req.RequestHandle},
				SecurityToken:  ua.ChannelSecurityToken{ChannelID: channelID, TokenID: tokenID, CreatedAt: time.Now(), RevisedLifetime: req.RequestedLifetime},
			}
			enc.WriteUInt32(channelID)
			enc.WriteString(ua.SecurityPolicyURINone)
			enc.WriteByteString("")
			enc.WriteByteString("")
			sequenceNumber++
			enc.WriteUInt32(sequenceNumber)
			enc.WriteUInt32(requestID)
			enc.WriteNodeID(ua.ObjectIDOpenSecureChannelResponseEncodingDefaultBinary)
			enc.Encode(res)
			writeChunk(conn, ua.MessageTypeOpenFinal, out.Bytes())

		case ua.MessageTypeFinal:
			var unused, requestID uint32
			var nodeID ua.NodeID
			dec.ReadUInt32(&unused) // secure channel id
			dec.ReadUInt32(&unused) // token id
			dec.ReadUInt32(&unused) // sequence number
			dec.ReadUInt32(&requestID)
			dec.ReadNodeID(&nodeID)
			var name string
			var res any
			var resID ua.NodeID
			switch nodeID {
			case ua.ObjectIDGetEndpointsRequestEncodingDefaultBinary:
				req := new(ua.GetEndpointsRequest)
				if dec.Decode(req) != nil {
					return
				}
				name, resID = "GetEndpoints", ua.ObjectIDGetEndpointsResponseEncodingDefaultBinary
				res = &ua.GetEndpointsResponse{
					ResponseHeader: ua.ResponseHeader{Timestamp: time.Now(), RequestHandle: req.RequestHandle},
					Endpoints:      s.discoveryEndpoints,
				}
			case ua.ObjectIDCreateSessionRequestEncodingDefaultBinary:
				req := new(ua.CreateSessionRequest)
				if dec.Decode(req) != nil {
					return
				}
				name, resID = "CreateSession", ua.ObjectIDCreateSessionResponseEncodingDefaultBinary
				res = &ua.CreateSessionResponse{
					ResponseHeader:        ua.ResponseHeader{Timestamp: time.Now(), RequestHandle: req.RequestHandle},
					SessionID:             ua.NewNodeIDNumeric(1, 1),
					AuthenticationToken:   ua.NewNodeIDNumeric(1, 2),
					RevisedSessionTimeout: req.RequestedSessionTimeout,
					ServerNonce:           ua.ByteString(bytes.Repeat([]byte{1}, 32)),
					ServerCertificate:     s.serverCertificate,
					ServerEndpoints:       s.sessionEndpoints,
				}
			case ua.ObjectIDActivateSessionRequestEncodingDefaultBinary:
				req := new(ua.ActivateSessionRequest)
				if dec.Decode(req) != nil {
					return
				}
				s.mu.Lock()
				s.tokens = append(s.tokens, req.UserIdentityToken)
				s.tokenSignatures = append(s.tokenSignatures, req.UserTokenSignature)
				s.mu.Unlock()
				name, resID = "ActivateSession", ua.ObjectIDActivateSessionResponseEncodingDefaultBinary
				res = &ua.ActivateSessionResponse{
					ResponseHeader: ua.ResponseHeader{Timestamp: time.Now(), RequestHandle: req.RequestHandle},
					ServerNonce:    ua.ByteString(bytes.Repeat([]byte{2}, 32)),
				}
			case ua.ObjectIDReadRequestEncodingDefaultBinary:
				req := new(ua.ReadRequest)
				if dec.Decode(req) != nil {
					return
				}
				name, resID = "Read", ua.ObjectIDReadResponseEncodingDefaultBinary
				res = &ua.ReadResponse{
					ResponseHeader: ua.ResponseHeader{Timestamp: time.Now(), RequestHandle: req.RequestHandle},
					Results: []ua.DataValue{
						ua.NewDataValue([]string{"http://opcfoundation.org/UA/"}, 0, time.Now(), 0, time.Now(), 0),
						ua.NewDataValue([]string{"urn:fakeserver"}, 0, time.Now(), 0, time.Now(), 0),
					},
				}
			case ua.ObjectIDCloseSessionRequestEncodingDefaultBinary:
				req := new(ua.CloseSessionRequest)
				if dec.Decode(req) != nil {
					return
				}
				name, resID = "CloseSession", ua.ObjectIDCloseSessionResponseEncodingDefaultBinary
				res = &ua.CloseSessionResponse{
					ResponseHeader: ua.ResponseHeader{Timestamp: time.Now(), RequestHandle: req.RequestHandle},
				}
			default:
				return
			}
			s.mu.Lock()
			s.requests = append(s.requests, name)
			s.mu.Unlock()
			enc.WriteUInt32(channelID)
			enc.WriteUInt32(tokenID)
			sequenceNumber++
			enc.WriteUInt32(sequenceNumber)
			enc.WriteUInt32(requestID)
			enc.WriteNodeID(resID)
			if err := enc.Encode(res); err != nil {
				return
			}
			writeChunk(conn, ua.MessageTypeFinal, out.Bytes())

		default: // CloseSecureChannel or unexpected message
			return
		}
	}
}

// writeChunk writes a message chunk with the given type and payload.
func writeChunk(w io.Writer, msgType uint32, payload []byte) error {
	header := make([]byte, 8)
	binary.LittleEndian.PutUint32(header[0:4], msgType)
	binary.LittleEndian.PutUint32(header[4:8], uint32(8+len(payload)))
	_, err := w.Write(append(header, payload...))
	return err
}

// newServerCertificate creates a self-signed server certificate for 127.0.0.1, and returns the DER bytes
// and the path to a PEM file containing it.
func newServerCertificate(t *testing.T) (ua.ByteString, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "fakeserver"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "server.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	return ua.ByteString(der), path
}

func fakeEndpoint(policyURI string, mode ua.MessageSecurityMode, level uint8, cert ua.ByteString, tokens ...ua.UserTokenPolicy) ua.EndpointDescription {
	return ua.EndpointDescription{
		EndpointURL:         "opc.tcp://127.0.0.1:4840",
		ServerCertificate:   cert,
		SecurityMode:        mode,
		SecurityPolicyURI:   policyURI,
		UserIdentityTokens:  tokens,
		TransportProfileURI: ua.TransportProfileURIUaTcpTransport,
		SecurityLevel:       level,
	}
}

// plaintextUserNameEndpoint is the endpoint an attacker advertises to obtain the password:
// security policy None, without a server certificate, and a UserName token policy without encryption.
func plaintextUserNameEndpoint() ua.EndpointDescription {
	return fakeEndpoint(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 255, "",
		ua.UserTokenPolicy{PolicyID: "anonymous", TokenType: ua.UserTokenTypeAnonymous, SecurityPolicyURI: ua.SecurityPolicyURINone},
		ua.UserTokenPolicy{PolicyID: "username", TokenType: ua.UserTokenTypeUserName, SecurityPolicyURI: ua.SecurityPolicyURINone},
	)
}

// TestDialRejectsEndpointBelowMinSecurityMode verifies that Dial fails when discovery only advertises
// endpoints weaker than the caller requires, instead of connecting to them.
func TestDialRejectsEndpointBelowMinSecurityMode(t *testing.T) {
	cert, _ := newServerCertificate(t)
	tests := []struct {
		name      string
		endpoints []ua.EndpointDescription
		opts      []client.Option
	}{
		{
			name:      "None advertised, Sign required",
			endpoints: []ua.EndpointDescription{plaintextUserNameEndpoint()},
			opts:      []client.Option{client.WithMinSecurityMode(ua.MessageSecurityModeSign)},
		},
		{
			name: "Sign advertised, SignAndEncrypt required",
			endpoints: []ua.EndpointDescription{fakeEndpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign, 255, cert,
				ua.UserTokenPolicy{PolicyID: "anonymous", TokenType: ua.UserTokenTypeAnonymous, SecurityPolicyURI: ua.SecurityPolicyURINone})},
			opts: []client.Option{client.WithMinSecurityMode(ua.MessageSecurityModeSignAndEncrypt)},
		},
		{
			name:      "None advertised, SignAndEncrypt requested",
			endpoints: []ua.EndpointDescription{plaintextUserNameEndpoint()},
			opts:      []client.Option{client.WithSecurityPolicyURI("", ua.MessageSecurityModeSignAndEncrypt)},
		},
		{
			name:      "None advertised, credentials with client certificate (default minimum)",
			endpoints: []ua.EndpointDescription{plaintextUserNameEndpoint()},
			opts:      []client.Option{client.WithUserNameIdentity("root", testPassword)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &fakeServer{discoveryEndpoints: tt.endpoints, sessionEndpoints: tt.endpoints}
			srv.start(t)
			opts := append([]client.Option{
				client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
				client.WithInsecureSkipVerify(),
			}, tt.opts...)
			ch, err := client.Dial(context.Background(), srv.endpointURL, opts...)
			if err == nil {
				ch.Abort(context.Background())
				t.Fatal("Dial succeeded, want error")
			}
			if err != ua.BadSecurityModeRejected {
				t.Errorf("Dial error = %v, want %v", err, ua.BadSecurityModeRejected)
			}
			if n := srv.connections(); n != 1 {
				t.Errorf("client made %d connections, want only the discovery connection", n)
			}
			if srv.sawPassword() {
				t.Error("password was sent in plaintext")
			}
		})
	}
}

// TestDialRejectsCredentialsWithoutClientCertificateByDefault verifies that, without a client certificate,
// Dial does not send credentials over an unsecured channel unless the caller accepts it explicitly, since an
// on-path attacker can relay the encrypted user token to the server to take over the session.
func TestDialRejectsCredentialsWithoutClientCertificateByDefault(t *testing.T) {
	cert, certPath := newServerCertificate(t)
	e := fakeEndpoint(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 0, cert,
		ua.UserTokenPolicy{PolicyID: "username", TokenType: ua.UserTokenTypeUserName, SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256})
	srv := &fakeServer{discoveryEndpoints: []ua.EndpointDescription{e}, sessionEndpoints: []ua.EndpointDescription{e}, serverCertificate: cert}
	srv.start(t)
	ch, err := client.Dial(context.Background(), srv.endpointURL,
		client.WithUserNameIdentity("root", testPassword),
		client.WithTrustedCertificatesPaths(certPath, ""),
	)
	if err == nil {
		ch.Abort(context.Background())
		t.Fatal("Dial succeeded, want error")
	}
	if err != ua.BadSecurityModeRejected {
		t.Errorf("Dial error = %v, want %v", err, ua.BadSecurityModeRejected)
	}
	if n := srv.connections(); n != 1 {
		t.Errorf("client made %d connections, want only the discovery connection", n)
	}
}

// TestDialRejectsPlaintextPassword verifies that Dial never sends a password in plaintext when discovery
// advertises only a None endpoint with a None UserName token policy.
func TestDialRejectsPlaintextPassword(t *testing.T) {
	srv := &fakeServer{
		discoveryEndpoints: []ua.EndpointDescription{plaintextUserNameEndpoint()},
		sessionEndpoints:   []ua.EndpointDescription{plaintextUserNameEndpoint()},
	}
	srv.start(t)
	ch, err := client.Dial(context.Background(), srv.endpointURL,
		client.WithUserNameIdentity("root", testPassword),
		client.WithMinSecurityMode(ua.MessageSecurityModeNone),
		client.WithInsecureSkipVerify(),
	)
	if err == nil {
		ch.Abort(context.Background())
		t.Fatal("Dial succeeded, want error")
	}
	if err != ua.BadSecurityModeInsufficient {
		t.Errorf("Dial error = %v, want %v", err, ua.BadSecurityModeInsufficient)
	}
	if srv.handled("CreateSession") || srv.handled("ActivateSession") {
		t.Error("client created a session")
	}
	if srv.sawPassword() {
		t.Error("password was sent in plaintext")
	}
}

// TestDialRejectsPlaintextIssuedToken verifies that Dial never sends an issued token in plaintext.
func TestDialRejectsPlaintextIssuedToken(t *testing.T) {
	e := fakeEndpoint(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 0, "",
		ua.UserTokenPolicy{PolicyID: "issued", TokenType: ua.UserTokenTypeIssuedToken, SecurityPolicyURI: ua.SecurityPolicyURINone})
	srv := &fakeServer{discoveryEndpoints: []ua.EndpointDescription{e}, sessionEndpoints: []ua.EndpointDescription{e}}
	srv.start(t)
	ch, err := client.Dial(context.Background(), srv.endpointURL,
		client.WithIssuedIdentity([]byte(testPassword)),
		client.WithMinSecurityMode(ua.MessageSecurityModeNone),
		client.WithInsecureSkipVerify(),
	)
	if err == nil {
		ch.Abort(context.Background())
		t.Fatal("Dial succeeded, want error")
	}
	if err != ua.BadSecurityModeInsufficient {
		t.Errorf("Dial error = %v, want %v", err, ua.BadSecurityModeInsufficient)
	}
	if srv.sawPassword() {
		t.Error("issued token was sent in plaintext")
	}
}

// TestDialAllowsPlaintextPasswordWithOptIn verifies that a caller can still explicitly opt in to sending
// the password in plaintext, e.g. for a legacy server on a trusted network.
func TestDialAllowsPlaintextPasswordWithOptIn(t *testing.T) {
	srv := &fakeServer{
		discoveryEndpoints: []ua.EndpointDescription{plaintextUserNameEndpoint()},
		sessionEndpoints:   []ua.EndpointDescription{plaintextUserNameEndpoint()},
	}
	srv.start(t)
	ctx := context.Background()
	ch, err := client.Dial(ctx, srv.endpointURL,
		client.WithUserNameIdentity("root", testPassword),
		client.WithMinSecurityMode(ua.MessageSecurityModeNone),
		client.WithInsecurePlaintextCredentials(),
	)
	if err != nil {
		t.Fatalf("Dial error = %v", err)
	}
	if err := ch.Close(ctx); err != nil {
		ch.Abort(ctx)
		t.Errorf("Close error = %v", err)
	}
	if !srv.sawPassword() {
		t.Error("expected the password to be sent in plaintext after opt-in")
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.tokens) != 1 {
		t.Fatalf("server received %d identity tokens, want 1", len(srv.tokens))
	}
	tok, ok := srv.tokens[0].(ua.UserNameIdentityToken)
	if !ok || tok.PolicyID != "username" || tok.EncryptionAlgorithm != "" || string(tok.Password) != testPassword {
		t.Errorf("unexpected identity token %#v", srv.tokens[0])
	}
}

// TestDialRejectsUnauthenticatedCertificateForUserToken verifies that the password is not encrypted with a
// server certificate from discovery unless the certificate is trusted, since an attacker may substitute
// their own certificate.
func TestDialRejectsUnauthenticatedCertificateForUserToken(t *testing.T) {
	attackerCert, attackerCertPath := newServerCertificate(t)
	_, otherCertPath := newServerCertificate(t)
	e := fakeEndpoint(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 0, attackerCert,
		ua.UserTokenPolicy{PolicyID: "username", TokenType: ua.UserTokenTypeUserName, SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256})
	ctx := context.Background()

	t.Run("untrusted certificate is rejected", func(t *testing.T) {
		srv := &fakeServer{discoveryEndpoints: []ua.EndpointDescription{e}, sessionEndpoints: []ua.EndpointDescription{e}, serverCertificate: attackerCert}
		srv.start(t)
		ch, err := client.Dial(ctx, srv.endpointURL,
			client.WithUserNameIdentity("root", testPassword),
			client.WithMinSecurityMode(ua.MessageSecurityModeNone),
			client.WithTrustedCertificatesPaths(otherCertPath, ""),
		)
		if err == nil {
			ch.Abort(ctx)
			t.Fatal("Dial succeeded, want error")
		}
		if err != ua.BadSecurityChecksFailed {
			t.Errorf("Dial error = %v, want %v", err, ua.BadSecurityChecksFailed)
		}
		if n := srv.connections(); n != 1 {
			t.Errorf("client made %d connections, want only the discovery connection", n)
		}
	})

	t.Run("trusted certificate is used to encrypt the password", func(t *testing.T) {
		srv := &fakeServer{discoveryEndpoints: []ua.EndpointDescription{e}, sessionEndpoints: []ua.EndpointDescription{e}, serverCertificate: attackerCert}
		srv.start(t)
		ch, err := client.Dial(ctx, srv.endpointURL,
			client.WithUserNameIdentity("root", testPassword),
			client.WithMinSecurityMode(ua.MessageSecurityModeNone),
			client.WithTrustedCertificatesPaths(attackerCertPath, ""),
		)
		if err != nil {
			t.Fatalf("Dial error = %v", err)
		}
		ch.Close(ctx)
		if srv.sawPassword() {
			t.Error("password was sent in plaintext")
		}
		srv.mu.Lock()
		defer srv.mu.Unlock()
		if len(srv.tokens) != 1 {
			t.Fatalf("server received %d identity tokens, want 1", len(srv.tokens))
		}
		if tok, ok := srv.tokens[0].(ua.UserNameIdentityToken); !ok || tok.EncryptionAlgorithm != ua.RsaOaepKeyWrap {
			t.Errorf("unexpected identity token %#v", srv.tokens[0])
		}
	})
}

// TestDialComparesCreateSessionCertificateByLeaf verifies that the certificate returned by CreateSession must have the
// same leaf certificate as the certificate of the secure channel, whether or not the issuer chain is included.
func TestDialComparesCreateSessionCertificateByLeaf(t *testing.T) {
	leaf, leafPath := newServerCertificate(t)
	issuer, _ := newServerCertificate(t)
	other, _ := newServerCertificate(t)
	e := fakeEndpoint(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 0, leaf+issuer,
		ua.UserTokenPolicy{PolicyID: "username", TokenType: ua.UserTokenTypeUserName, SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256})
	ctx := context.Background()
	tests := []struct {
		name              string
		serverCertificate ua.ByteString
		wantErr           error
	}{
		{name: "same leaf without chain", serverCertificate: leaf},
		{name: "same leaf with chain", serverCertificate: leaf + issuer},
		{name: "different leaf", serverCertificate: other, wantErr: ua.BadCertificateInvalid},
		{name: "missing", serverCertificate: "", wantErr: ua.BadCertificateInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &fakeServer{discoveryEndpoints: []ua.EndpointDescription{e}, sessionEndpoints: []ua.EndpointDescription{e}, serverCertificate: tt.serverCertificate}
			srv.start(t)
			ch, err := client.Dial(ctx, srv.endpointURL,
				client.WithUserNameIdentity("root", testPassword),
				client.WithMinSecurityMode(ua.MessageSecurityModeNone),
				client.WithTrustedCertificatesPaths(leafPath, ""),
			)
			if err == nil {
				ch.Close(ctx)
			}
			if err != tt.wantErr {
				t.Errorf("Dial error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil && srv.handled("ActivateSession") {
				t.Error("client activated the session")
			}
			if srv.sawPassword() {
				t.Error("password was sent in plaintext")
			}
		})
	}
}

// TestDialSignsCreateSessionCertificate verifies that the user token signature is calculated over the server
// certificate returned by CreateSession, when discovery returned the same leaf certificate with or without its chain.
func TestDialSignsCreateSessionCertificate(t *testing.T) {
	leaf, leafPath := newServerCertificate(t)
	issuer, _ := newServerCertificate(t)
	userKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	userTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "user"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	userCert, err := x509.CreateCertificate(rand.Reader, &userTemplate, &userTemplate, &userKey.PublicKey, userKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tests := []struct {
		name                 string
		discoveryCertificate ua.ByteString
		sessionCertificate   ua.ByteString
	}{
		{name: "chain in discovery, leaf from CreateSession", discoveryCertificate: leaf + issuer, sessionCertificate: leaf},
		{name: "leaf in discovery, chain from CreateSession", discoveryCertificate: leaf, sessionCertificate: leaf + issuer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := fakeEndpoint(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 0, tt.discoveryCertificate,
				ua.UserTokenPolicy{PolicyID: "x509", TokenType: ua.UserTokenTypeCertificate, SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256})
			srv := &fakeServer{discoveryEndpoints: []ua.EndpointDescription{e}, sessionEndpoints: []ua.EndpointDescription{e}, serverCertificate: tt.sessionCertificate}
			srv.start(t)
			ch, err := client.Dial(ctx, srv.endpointURL,
				client.WithX509Identity(userCert, userKey),
				client.WithMinSecurityMode(ua.MessageSecurityModeNone),
				client.WithTrustedCertificatesPaths(leafPath, ""),
			)
			if err != nil {
				t.Fatalf("Dial error = %v", err)
			}
			ch.Close(ctx)
			srv.mu.Lock()
			defer srv.mu.Unlock()
			if len(srv.tokenSignatures) != 1 {
				t.Fatalf("server received %d token signatures, want 1", len(srv.tokenSignatures))
			}
			hashed := sha256.Sum256(append([]byte(tt.sessionCertificate), bytes.Repeat([]byte{1}, 32)...)) // server nonce of fakeServer
			if err := rsa.VerifyPKCS1v15(&userKey.PublicKey, crypto.SHA256, hashed[:], []byte(srv.tokenSignatures[0].Signature)); err != nil {
				t.Errorf("token signature is not calculated over the CreateSession certificate: %v", err)
			}
		})
	}
}

// TestDialRejectsSecuredEndpointWithoutCertificate verifies that a secured endpoint, or a user token policy that
// requires encryption, without a server certificate is rejected rather than skipping certificate validation.
func TestDialRejectsSecuredEndpointWithoutCertificate(t *testing.T) {
	tests := []struct {
		name     string
		endpoint ua.EndpointDescription
		opts     []client.Option
	}{
		{
			name: "SignAndEncrypt endpoint",
			endpoint: fakeEndpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 255, "",
				ua.UserTokenPolicy{PolicyID: "anonymous", TokenType: ua.UserTokenTypeAnonymous, SecurityPolicyURI: ua.SecurityPolicyURINone}),
			opts: []client.Option{client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key")},
		},
		{
			name: "encrypted UserName token on None endpoint",
			endpoint: fakeEndpoint(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 255, "",
				ua.UserTokenPolicy{PolicyID: "username", TokenType: ua.UserTokenTypeUserName, SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256}),
			opts: []client.Option{client.WithUserNameIdentity("root", testPassword), client.WithMinSecurityMode(ua.MessageSecurityModeNone)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &fakeServer{discoveryEndpoints: []ua.EndpointDescription{tt.endpoint}, sessionEndpoints: []ua.EndpointDescription{tt.endpoint}}
			srv.start(t)
			ch, err := client.Dial(context.Background(), srv.endpointURL, append(tt.opts, client.WithInsecureSkipVerify())...)
			if err == nil {
				ch.Abort(context.Background())
				t.Fatal("Dial succeeded, want error")
			}
			if err != ua.BadCertificateInvalid {
				t.Errorf("Dial error = %v, want %v", err, ua.BadCertificateInvalid)
			}
			if n := srv.connections(); n != 1 {
				t.Errorf("client made %d connections, want only the discovery connection", n)
			}
		})
	}
}

// TestDialRejectsCreateSessionEndpointMismatch verifies that the client compares the endpoints returned by
// CreateSession with the endpoints returned by discovery, and does not send credentials if they differ.
func TestDialRejectsCreateSessionEndpointMismatch(t *testing.T) {
	cert, _ := newServerCertificate(t)
	discovered := plaintextUserNameEndpoint()
	secured := fakeEndpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 255, cert,
		ua.UserTokenPolicy{PolicyID: "username_1", TokenType: ua.UserTokenTypeUserName, SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256})
	srv := &fakeServer{
		discoveryEndpoints: []ua.EndpointDescription{discovered},
		sessionEndpoints:   []ua.EndpointDescription{discovered, secured},
	}
	srv.start(t)
	ch, err := client.Dial(context.Background(), srv.endpointURL,
		client.WithUserNameIdentity("root", testPassword),
		client.WithMinSecurityMode(ua.MessageSecurityModeNone),
		client.WithInsecurePlaintextCredentials(),
	)
	if err == nil {
		ch.Abort(context.Background())
		t.Fatal("Dial succeeded, want error")
	}
	if err != ua.BadSecurityChecksFailed {
		t.Errorf("Dial error = %v, want %v", err, ua.BadSecurityChecksFailed)
	}
	if !srv.handled("CreateSession") {
		t.Error("expected client to create a session")
	}
	if srv.handled("ActivateSession") {
		t.Error("client activated the session")
	}
	if srv.sawPassword() {
		t.Error("password was sent in plaintext")
	}
}

// TestDialDetectsStrippedEndpointsOnSecureChannel simulates an on-path attacker that removes the most secure
// endpoints of the real test server from the discovery response, and then forwards the connection to the real
// server. The client detects the downgrade by comparing with the endpoints returned by CreateSession, which arrive
// over the secure channel.
func TestDialDetectsStrippedEndpointsOnSecureChannel(t *testing.T) {
	ctx := context.Background()
	res, err := client.GetEndpoints(ctx, &ua.GetEndpointsRequest{EndpointURL: endpointURL})
	if err != nil {
		t.Fatal(err)
	}
	var stripped []ua.EndpointDescription
	for _, e := range res.Endpoints {
		if e.SecurityPolicyURI == ua.SecurityPolicyURIBasic256Sha256 && e.SecurityMode == ua.MessageSecurityModeSign {
			stripped = append(stripped, e)
		}
	}
	if len(stripped) != 1 {
		t.Fatalf("test server did not offer a Basic256Sha256 Sign endpoint")
	}
	forwardAddr := fmt.Sprintf("%s:%d", host, port)

	t.Run("unmodified discovery succeeds", func(t *testing.T) {
		srv := &fakeServer{discoveryEndpoints: res.Endpoints, forwardAddr: forwardAddr}
		srv.start(t)
		ch, err := client.Dial(ctx, srv.endpointURL,
			client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
			client.WithInsecureSkipVerify(),
			client.WithUserNameIdentity("root", "secret"),
		)
		if err != nil {
			t.Fatalf("Dial error = %v", err)
		}
		if ch.SecurityMode() != ua.MessageSecurityModeSignAndEncrypt {
			t.Errorf("SecurityMode = %s, want %s", ch.SecurityMode(), ua.MessageSecurityModeSignAndEncrypt)
		}
		if err := ch.Close(ctx); err != nil {
			ch.Abort(ctx)
		}
	})

	t.Run("certificate chain added to discovery succeeds", func(t *testing.T) {
		// the client signature is calculated over the certificate returned by CreateSession, which is the leaf.
		extra, _ := newServerCertificate(t)
		modified := make([]ua.EndpointDescription, len(res.Endpoints))
		copy(modified, res.Endpoints)
		for i := range modified {
			modified[i].ServerCertificate += extra
		}
		srv := &fakeServer{discoveryEndpoints: modified, forwardAddr: forwardAddr}
		srv.start(t)
		ch, err := client.Dial(ctx, srv.endpointURL,
			client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
			client.WithInsecureSkipVerify(),
			client.WithUserNameIdentity("root", "secret"),
		)
		if err != nil {
			t.Fatalf("Dial error = %v", err)
		}
		if err := ch.Close(ctx); err != nil {
			ch.Abort(ctx)
		}
	})

	t.Run("stripped discovery is detected", func(t *testing.T) {
		srv := &fakeServer{discoveryEndpoints: stripped, forwardAddr: forwardAddr}
		srv.start(t)
		ch, err := client.Dial(ctx, srv.endpointURL,
			client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
			client.WithInsecureSkipVerify(),
			client.WithUserNameIdentity("root", "secret"),
		)
		if err == nil {
			ch.Abort(ctx)
			t.Fatal("Dial succeeded, want error")
		}
		if err != ua.BadSecurityChecksFailed {
			t.Errorf("Dial error = %v, want %v", err, ua.BadSecurityChecksFailed)
		}
		if n := srv.connections(); n != 2 {
			t.Errorf("client made %d connections, want 2", n)
		}
	})

	t.Run("certificate stripped from strongest endpoint is rejected", func(t *testing.T) {
		modified := make([]ua.EndpointDescription, len(res.Endpoints))
		copy(modified, res.Endpoints)
		for i := range modified {
			if modified[i].SecurityPolicyURI == ua.SecurityPolicyURIAes256Sha256RsaPss && modified[i].SecurityMode == ua.MessageSecurityModeSignAndEncrypt {
				modified[i].ServerCertificate = ""
			}
		}
		srv := &fakeServer{discoveryEndpoints: modified, forwardAddr: forwardAddr}
		srv.start(t)
		ch, err := client.Dial(ctx, srv.endpointURL,
			client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
			client.WithInsecureSkipVerify(),
			client.WithUserNameIdentity("root", "secret"),
		)
		if err == nil {
			ch.Abort(ctx)
			t.Fatal("Dial succeeded, want error")
		}
		if err != ua.BadCertificateInvalid {
			t.Errorf("Dial error = %v, want %v", err, ua.BadCertificateInvalid)
		}
		if n := srv.connections(); n != 1 {
			t.Errorf("client made %d connections, want only the discovery connection", n)
		}
	})
}
