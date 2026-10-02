package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/awcullen/opcua/internal/securechannel"
	"github.com/awcullen/opcua/internal/securechannel/securechanneltest"
	"github.com/awcullen/opcua/ua"
)

// testCredential is a certificate and private key of a test application.
type testCredential struct {
	cert []byte
	key  *rsa.PrivateKey
}

var (
	testCredentialsOnce sync.Once
	testClient          testCredential // 2048 bit
	testServer          testCredential // 2048 bit
	testClientLarge     testCredential // 3072 bit, needs the extra padding byte
	testOtherServer     testCredential // 2048 bit
	testShortClient     testCredential // 1024 bit, too short for policies after Basic256
	testShortServer     testCredential // 1024 bit, too short for policies after Basic256
	testECDSACert       []byte
	testEd25519Cert     []byte
	testSmallRSACert    []byte // 512 bit
)

func loadTestCredentials(t *testing.T) {
	t.Helper()
	testCredentialsOnce.Do(func() {
		newCredential := func(uri string, bits int) testCredential {
			key, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				panic(err)
			}
			cert, err := securechanneltest.NewCertificate(uri, key, &key.PublicKey)
			if err != nil {
				panic(err)
			}
			return testCredential{cert, key}
		}
		testClient = newCredential("urn:localhost:testclient", 2048)
		testServer = newCredential("urn:localhost:testserver", 2048)
		testClientLarge = newCredential("urn:localhost:testclientlarge", 3072)
		testOtherServer = newCredential("urn:localhost:otherserver", 2048)
		testShortClient = newCredential("urn:localhost:shortclient", 1024)
		testShortServer = newCredential("urn:localhost:shortserver", 1024)

		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		if testECDSACert, err = securechanneltest.NewCertificate("urn:localhost:ecdsa", ecdsaKey, &ecdsaKey.PublicKey); err != nil {
			panic(err)
		}
		edPublic, edKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		if testEd25519Cert, err = securechanneltest.NewCertificate("urn:localhost:ed25519", edKey, edPublic); err != nil {
			panic(err)
		}
		smallKey := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), 511, 1), E: 65537}
		if testSmallRSACert, err = securechanneltest.NewCertificate("urn:localhost:small", testServer.key, smallKey); err != nil {
			panic(err)
		}
	})
}

type testPolicy struct {
	uri    string
	policy ua.SecurityPolicy
}

var testRSAPolicies = []testPolicy{
	{ua.SecurityPolicyURIBasic128Rsa15, new(ua.SecurityPolicyBasic128Rsa15)},
	{ua.SecurityPolicyURIBasic256, new(ua.SecurityPolicyBasic256)},
	{ua.SecurityPolicyURIBasic256Sha256, new(ua.SecurityPolicyBasic256Sha256)},
	{ua.SecurityPolicyURIAes128Sha256RsaOaep, new(ua.SecurityPolicyAes128Sha256RsaOaep)},
	{ua.SecurityPolicyURIAes256Sha256RsaPss, new(ua.SecurityPolicyAes256Sha256RsaPss)},
}

// newTestClientSecureChannel returns a client secure channel that skips the validation of the server certificate.
func newTestClientSecureChannel(endpointURL, policyURI string, mode ua.MessageSecurityMode, client testCredential, serverCert []byte) *clientSecureChannel {
	return newClientSecureChannel(
		ua.ApplicationDescription{ApplicationURI: "urn:localhost:testclient", ApplicationType: ua.ApplicationTypeClient},
		client.cert, client.key, endpointURL, policyURI, mode, serverCert,
		5000, "", "", "", "", "", true, true, true, true,
		defaultTimeoutHint, defaultDiagnosticsHint, defaultTokenRequestedLifetime,
		defaultMaxBufferSize, defaultMaxMessageSize, defaultMaxChunkCount, false,
	)
}

// listenAcknowledge accepts connections on an ephemeral port and acknowledges the Hello message.
func listenAcknowledge(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := securechanneltest.ReadChunk(conn); err != nil {
					return
				}
				conn.Write(securechanneltest.Acknowledge())
				securechanneltest.ReadChunk(conn)
			}()
		}
	}()
	return "opc.tcp://" + ln.Addr().String()
}

// TestClientRejectsUnsupportedCertificate checks that a server certificate that does not hold a
// supported RSA key is rejected before any RSA operation (issue #1).
func TestClientRejectsUnsupportedCertificate(t *testing.T) {
	loadTestCredentials(t)
	endpointURL := listenAcknowledge(t)
	for name, cert := range map[string][]byte{"ECDSA": testECDSACert, "Ed25519": testEd25519Cert, "RSA512": testSmallRSACert, "Garbage": {1, 2, 3}} {
		t.Run(name, func(t *testing.T) {
			var ch *clientSecureChannel
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("newClientSecureChannel panicked: %v", r)
					}
				}()
				ch = newTestClientSecureChannel(endpointURL, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, testClient, cert)
			}()
			if ch.remotePublicKey != nil {
				t.Fatal("remote public key was set")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := ch.Open(ctx)
			if err == nil {
				ch.Abort(ctx)
				t.Fatal("Open() succeeded, want an error")
			}
			if ch.conn != nil {
				ch.conn.Close()
			}
		})
	}
}

// TestClientRejectsKeyLengths checks that a server certificate, or a client certificate, with a key shorter
// than the security policy allows, or longer than any policy allows, is rejected: 1024 bit keys are allowed
// for Basic128Rsa15 and Basic256 only.
func TestClientRejectsKeyLengths(t *testing.T) {
	loadTestCredentials(t)
	endpointURL := listenAcknowledge(t)
	for _, p := range testRSAPolicies {
		t.Run(p.uri[len("http://opcfoundation.org/UA/SecurityPolicy#"):], func(t *testing.T) {
			allowed := securechannel.MinRSAKeyLength(p.uri) <= 1024
			open := func(client testCredential, serverCert []byte) error {
				ch := newTestClientSecureChannel(endpointURL, p.uri, ua.MessageSecurityModeSignAndEncrypt, client, serverCert)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				err := ch.Open(ctx)
				if ch.conn != nil {
					ch.conn.Close()
				}
				return err
			}

			// server certificate
			ch := newTestClientSecureChannel(endpointURL, p.uri, ua.MessageSecurityModeSignAndEncrypt, testClient, testShortServer.cert)
			if allowed && ch.remotePublicKey == nil {
				t.Error("1024 bit server key was rejected")
			}
			if !allowed {
				if ch.remotePublicKey != nil {
					t.Error("1024 bit server key was accepted")
				}
				if err := open(testClient, testShortServer.cert); err != ua.BadSecurityChecksFailed {
					t.Errorf("Open() with a 1024 bit server key = %v, want %v", err, ua.BadSecurityChecksFailed)
				}
			}

			// client certificate
			if !allowed {
				if err := open(testShortClient, testServer.cert); err != ua.BadCertificatePolicyCheckFailed {
					t.Errorf("Open() with a 1024 bit client key = %v, want %v", err, ua.BadCertificatePolicyCheckFailed)
				}
			}

			// keys longer than any security policy allows.
			longKey := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), 8191, 1), E: 65537}
			longCert, err := securechanneltest.NewCertificate("urn:localhost:long", testServer.key, longKey)
			if err != nil {
				t.Fatal(err)
			}
			if ch := newTestClientSecureChannel(endpointURL, p.uri, ua.MessageSecurityModeSignAndEncrypt, testClient, longCert); ch.remotePublicKey != nil {
				t.Error("8192 bit server key was accepted")
			}
			// rejected before the certificate (chain) is validated.
			if err := open(testClient, longCert); err != ua.BadCertificatePolicyCheckFailed {
				t.Errorf("Open() with an 8192 bit server key = %v, want %v", err, ua.BadCertificatePolicyCheckFailed)
			}
			issuerKey := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), 1<<16-1, 1), E: 1<<31 - 1}
			issuer, err := securechanneltest.NewCertificate("urn:localhost:issuer", testOtherServer.key, issuerKey)
			if err != nil {
				t.Fatal(err)
			}
			chain := append(append([]byte{}, testServer.cert...), issuer...)
			if err := open(testClient, chain); err != ua.BadCertificatePolicyCheckFailed {
				t.Errorf("Open() with a 65536 bit issuer key = %v, want %v", err, ua.BadCertificatePolicyCheckFailed)
			}
			long := testCredential{cert: testClient.cert, key: &rsa.PrivateKey{PublicKey: *longKey}}
			if err := open(long, testServer.cert); err != ua.BadCertificatePolicyCheckFailed {
				t.Errorf("Open() with an 8192 bit client key = %v, want %v", err, ua.BadCertificatePolicyCheckFailed)
			}
		})
	}
}

// TestClientOpenRejectsInconsistentSecurityMode checks that a channel with a security policy other than
// None cannot be opened with SecurityMode None, since the session would then need the server's key.
func TestClientOpenRejectsInconsistentSecurityMode(t *testing.T) {
	loadTestCredentials(t)
	endpointURL := listenAcknowledge(t)
	for name, cert := range map[string][]byte{"NoCertificate": nil, "ECDSA": testECDSACert} {
		ch := newTestClientSecureChannel(endpointURL, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeNone, testClient, cert)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := ch.Open(ctx)
		cancel()
		if ch.conn != nil {
			ch.conn.Close()
		}
		if err != ua.BadSecurityModeRejected {
			t.Errorf("%s: Open() = %v, want %v", name, err, ua.BadSecurityModeRejected)
		}
	}
}

// fakeServer is a minimal OPC UA server for SecurityPolicy None that answers GetEndpoints with the given endpoints.
type fakeServer struct {
	endpointURL string
	endpoints   func(endpointURL string) []ua.EndpointDescription
	// openResponse, if not nil, returns the body of the response to an OpenSecureChannel request.
	openResponse func(requestHandle uint32) []byte
}

func startFakeServer(t *testing.T, endpoints func(endpointURL string) []ua.EndpointDescription, openResponse func(requestHandle uint32) []byte) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &fakeServer{endpointURL: "opc.tcp://" + ln.Addr().String(), endpoints: endpoints, openResponse: openResponse}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *fakeServer) serve(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := securechanneltest.ReadChunk(conn); err != nil {
		return
	}
	if _, err := conn.Write(securechanneltest.Acknowledge()); err != nil {
		return
	}
	var sequenceNumber uint32 = 1
	for {
		chunk, err := securechanneltest.ReadChunk(conn)
		if err != nil {
			return
		}
		messageType := binary.LittleEndian.Uint32(chunk)
		var bodyStart int
		switch messageType {
		case ua.MessageTypeOpenFinal:
			dec := ua.NewBinaryDecoder(bytes.NewReader(chunk[12:]), ua.NewEncodingContext())
			var policyURI string
			var cert, thumbprint []byte
			dec.ReadString(&policyURI)
			dec.ReadByteArray(&cert)
			dec.ReadByteArray(&thumbprint)
			bodyStart = 12 + 4 + len(policyURI) + 4 + len(cert) + 4 + len(thumbprint) + 8
		case ua.MessageTypeFinal:
			bodyStart = 24
		default:
			return
		}
		requestID := binary.LittleEndian.Uint32(chunk[bodyStart-4:])
		dec := ua.NewBinaryDecoder(bytes.NewReader(chunk[bodyStart:]), ua.NewEncodingContext())
		var id ua.NodeID
		if err := dec.ReadNodeID(&id); err != nil {
			return
		}
		var response []byte
		switch id {
		case ua.ObjectIDOpenSecureChannelRequestEncodingDefaultBinary:
			req := new(ua.OpenSecureChannelRequest)
			if err := dec.Decode(req); err != nil {
				return
			}
			body := securechanneltest.EncodeBody(ua.ObjectIDOpenSecureChannelResponseEncodingDefaultBinary, &ua.OpenSecureChannelResponse{
				ResponseHeader: ua.ResponseHeader{Timestamp: time.Now(), RequestHandle: req.RequestHandle},
				SecurityToken:  ua.ChannelSecurityToken{ChannelID: 1, TokenID: 1, CreatedAt: time.Now(), RevisedLifetime: 3600000},
			})
			if s.openResponse != nil {
				body = s.openResponse(req.RequestHandle)
			}
			response, _ = securechanneltest.AsymmetricChunk{ChannelID: 1, PolicyURI: ua.SecurityPolicyURINone,
				SequenceNumber: sequenceNumber, RequestID: requestID, Body: body}.Encode()
		case ua.ObjectIDGetEndpointsRequestEncodingDefaultBinary:
			req := new(ua.GetEndpointsRequest)
			if err := dec.Decode(req); err != nil {
				return
			}
			body := securechanneltest.EncodeBody(ua.ObjectIDGetEndpointsResponseEncodingDefaultBinary, &ua.GetEndpointsResponse{
				ResponseHeader: ua.ResponseHeader{Timestamp: time.Now(), RequestHandle: req.RequestHandle},
				Endpoints:      s.endpoints(s.endpointURL),
			})
			response = securechanneltest.SymmetricChunk{MessageType: ua.MessageTypeFinal, ChannelID: 1, TokenID: 1,
				SequenceNumber: sequenceNumber, RequestID: requestID, Body: body, Policy: new(ua.SecurityPolicyNone), Mode: ua.MessageSecurityModeNone}.Encode()
		default:
			return
		}
		if _, err := conn.Write(response); err != nil {
			return
		}
		sequenceNumber++
	}
}

// TestClientDialRejectsUnsupportedServerCertificate checks that Dial returns an error, instead of
// panicking, when the server offers an endpoint with a certificate that does not hold an RSA key.
func TestClientDialRejectsUnsupportedServerCertificate(t *testing.T) {
	loadTestCredentials(t)
	for name, cert := range map[string][]byte{"ECDSA": testECDSACert, "Ed25519": testEd25519Cert} {
		t.Run(name, func(t *testing.T) {
			s := startFakeServer(t, func(endpointURL string) []ua.EndpointDescription {
				return []ua.EndpointDescription{{
					EndpointURL:         endpointURL,
					Server:              ua.ApplicationDescription{ApplicationURI: "urn:localhost:fakeserver", ApplicationType: ua.ApplicationTypeServer},
					ServerCertificate:   ua.ByteString(cert),
					SecurityMode:        ua.MessageSecurityModeSignAndEncrypt,
					SecurityPolicyURI:   ua.SecurityPolicyURIBasic256Sha256,
					UserIdentityTokens:  []ua.UserTokenPolicy{{PolicyID: "anonymous", TokenType: ua.UserTokenTypeAnonymous}},
					TransportProfileURI: ua.TransportProfileURIUaTcpTransport,
					SecurityLevel:       1,
				}}
			}, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Dial panicked: %v", r)
				}
			}()
			c, err := Dial(ctx, s.endpointURL,
				WithClientCertificate(testClient.cert, testClient.key),
				WithInsecureSkipVerify(),
			)
			if err == nil {
				c.Abort(ctx)
				t.Fatal("Dial succeeded, want an error")
			}
			// the endpoint may be rejected while it is selected, or when the channel is opened.
			if err != ua.BadSecurityChecksFailed && err != ua.BadCertificateInvalid {
				t.Fatalf("Dial() = %v, want %v or %v", err, ua.BadSecurityChecksFailed, ua.BadCertificateInvalid)
			}
		})
	}
}
