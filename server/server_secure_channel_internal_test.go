package server

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
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
	testServerLarge     testCredential // 3072 bit, needs the extra padding byte
	testOtherClient     testCredential // 2048 bit
	testShortClient     testCredential // 1024 bit, too short for policies after Basic256
	testShortServer     testCredential // 1024 bit, too short for policies after Basic256
	testECDSACert       []byte
	testEd25519Cert     []byte
	testSmallRSACert    []byte // 512 bit
	testLongRSACert     []byte // 8192 bit, longer than any security policy allows
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
		testServerLarge = newCredential("urn:localhost:testserverlarge", 3072)
		testOtherClient = newCredential("urn:localhost:otherclient", 2048)
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
		if testSmallRSACert, err = securechanneltest.NewCertificate("urn:localhost:small", testClient.key, smallKey); err != nil {
			panic(err)
		}
		if testLongRSACert, err = securechanneltest.NewCertificate("urn:localhost:long", testClient.key, testLongKey()); err != nil {
			panic(err)
		}
	})
}

// testLongKey returns an (unusable) 8192 bit RSA public key, longer than any security policy allows.
func testLongKey() *rsa.PublicKey {
	return &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), 8191, 1), E: 65537}
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

// newTestServerChannel returns a server secure channel that is connected by a pipe to the returned peer.
func newTestServerChannel(t *testing.T, server testCredential) (*serverSecureChannel, net.Conn) {
	t.Helper()
	srv := &Server{
		localDescription:                     ua.ApplicationDescription{ApplicationURI: "urn:localhost:testserver", DiscoveryURLs: []string{"opc.tcp://localhost:46219"}},
		endpointURL:                          "opc.tcp://localhost:46219",
		maxBufferSize:                        defaultMaxBufferSize,
		maxMessageSize:                       defaultMaxMessageSize,
		maxChunkCount:                        defaultMaxChunkCount,
		localCertificate:                     server.cert,
		localPrivateKey:                      server.key,
		allowSecurityPolicyNone:              true,
		suppressCertificateExpired:           true,
		suppressCertificateChainIncomplete:   true,
		suppressCertificateRevocationUnknown: true,
	}
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		conn.Close()
		peer.Close()
	})
	ch := newServerSecureChannel(srv, conn, false)
	ch.receiveBuffer = make([]byte, ch.receiveBufferSize)
	ch.sendBuffer = make([]byte, ch.sendBufferSize)
	ch.encryptionBuffer = make([]byte, ch.sendBufferSize)
	return ch, peer
}

// establishTestChannel puts the channel in the state reached after the first OpenSecureChannel
// request was handled by Open, with pending token 1. It returns the keys of the client.
func establishTestChannel(ch *serverSecureChannel, p testPolicy, mode ua.MessageSecurityMode) securechanneltest.SymmetricKeys {
	ch.securityPolicyURI = p.uri
	ch.securityPolicy = p.policy
	ch.securityMode = mode
	ch.localNonce = getNextNonce(p.policy.NonceSize())
	ch.remoteNonce = getNextNonce(p.policy.NonceSize())
	ch.pendingTokenID = 1
	ch.pendingTokenExpiration = time.Now().Add(time.Minute)
	if mode == ua.MessageSecurityModeNone {
		return securechanneltest.SymmetricKeys{}
	}
	a, b, c := p.policy.SymSignatureKeySize(), p.policy.SymEncryptionKeySize(), p.policy.SymEncryptionBlockSize()
	k := calculatePSHA(ch.localNonce, ch.remoteNonce, a+b+c, p.uri)
	return securechanneltest.SymmetricKeys{SigningKey: k[:a], EncryptingKey: k[a : a+b], InitializationVector: k[a+b:]}
}

// readTestRequest writes the chunks to the peer end of the channel and returns the result of readRequest.
func readTestRequest(t *testing.T, ch *serverSecureChannel, peer net.Conn, chunks ...[]byte) (req ua.ServiceRequest, id uint32, err error) {
	t.Helper()
	go func() {
		for _, chunk := range chunks {
			peer.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := peer.Write(chunk); err != nil {
				return
			}
		}
	}()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("readRequest panicked: %v", r)
		}
	}()
	return ch.readRequest()
}

var testReadRequest = &ua.ReadRequest{
	RequestHeader:      ua.RequestHeader{RequestHandle: 7, TimeoutHint: 1000},
	TimestampsToReturn: ua.TimestampsToReturnBoth,
	NodesToRead:        []ua.ReadValueID{{NodeID: ua.NewNodeIDNumeric(0, 2256), AttributeID: ua.AttributeIDValue}},
}

func testReadRequestBody() []byte {
	return securechanneltest.EncodeBody(ua.ObjectIDReadRequestEncodingDefaultBinary, testReadRequest)
}

func testOpenSecureChannelRequestBody(requestType ua.SecurityTokenRequestType, mode ua.MessageSecurityMode, nonceSize int) []byte {
	return securechanneltest.EncodeBody(ua.ObjectIDOpenSecureChannelRequestEncodingDefaultBinary, &ua.OpenSecureChannelRequest{
		RequestHeader:     ua.RequestHeader{RequestHandle: 1, TimeoutHint: 1000},
		RequestType:       requestType,
		SecurityMode:      mode,
		ClientNonce:       ua.ByteString(getNextNonce(nonceSize)),
		RequestedLifetime: 3600000,
	})
}

// testOpenChunk returns a valid OpenSecureChannel request chunk from client to server.
func testOpenChunk(p testPolicy, client, server testCredential, sequenceNumber uint32) securechanneltest.AsymmetricChunk {
	thumbprint := sha1.Sum(server.cert)
	return securechanneltest.AsymmetricChunk{
		PolicyURI:          p.uri,
		Policy:             p.policy,
		SenderCertificate:  client.cert,
		ReceiverThumbprint: thumbprint[:],
		SequenceNumber:     sequenceNumber,
		RequestID:          1,
		Body:               testOpenSecureChannelRequestBody(ua.SecurityTokenRequestTypeIssue, ua.MessageSecurityModeSignAndEncrypt, p.policy.NonceSize()),
		SenderKey:          client.key,
		ReceiverKey:        &server.key.PublicKey,
	}
}

func mustEncode(t *testing.T, c securechanneltest.AsymmetricChunk) []byte {
	t.Helper()
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestServerRejectsUnsupportedCertificate checks that an OpenSecureChannel request with a certificate
// that does not hold a supported RSA key is rejected before any RSA operation (issue #1).
func TestServerRejectsUnsupportedCertificate(t *testing.T) {
	loadTestCredentials(t)
	p := testRSAPolicies[2]
	for name, cert := range map[string][]byte{"ECDSA": testECDSACert, "Ed25519": testEd25519Cert, "RSA512": testSmallRSACert, "RSA8192": testLongRSACert, "Garbage": {1, 2, 3}} {
		t.Run(name, func(t *testing.T) {
			ch, peer := newTestServerChannel(t, testServer)
			c := testOpenChunk(p, testClient, testServer, 1)
			c.SenderCertificate = cert // still signed with the client's RSA key
			_, _, err := readTestRequest(t, ch, peer, mustEncode(t, c))
			if err == nil {
				t.Fatal("readRequest succeeded, want an error")
			}
			if ch.remotePublicKey != nil {
				t.Error("remote public key was set")
			}
		})
	}
}

// TestServerOpenRejectsLongIssuerKey checks that a certificate chain whose issuer certificate holds a very
// long RSA key is rejected before the chain is validated, which would verify a signature with that key.
func TestServerOpenRejectsLongIssuerKey(t *testing.T) {
	loadTestCredentials(t)
	issuerKey := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), 1<<16-1, 1), E: 1<<31 - 1}
	issuer, err := securechanneltest.NewCertificate("urn:localhost:issuer", testOtherClient.key, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	ch, peer := newTestServerChannel(t, testServer)
	c := testOpenChunk(testRSAPolicies[2], testClient, testServer, 1)
	c.SenderCertificate = append(append([]byte{}, testClient.cert...), issuer...)
	if err := openTestChannel(t, ch, peer, mustEncode(t, c)); err != ua.BadCertificatePolicyCheckFailed {
		t.Fatalf("Open() = %v, want %v", err, ua.BadCertificatePolicyCheckFailed)
	}
}

// TestServerRejectsShortClientKey checks that a client certificate with a key shorter than the security
// policy allows is rejected: 1024 bit keys are allowed for Basic128Rsa15 and Basic256 only.
func TestServerRejectsShortClientKey(t *testing.T) {
	loadTestCredentials(t)
	for _, p := range testRSAPolicies {
		t.Run(p.uri[len("http://opcfoundation.org/UA/SecurityPolicy#"):], func(t *testing.T) {
			allowed := securechannel.MinRSAKeyLength(p.uri) <= 1024
			ch, peer := newTestServerChannel(t, testServer)
			_, _, err := readTestRequest(t, ch, peer, mustEncode(t, testOpenChunk(p, testShortClient, testServer, 1)))
			if allowed && err != nil {
				t.Fatalf("readRequest() = %v, want success", err)
			}
			if !allowed && err != ua.BadCertificatePolicyCheckFailed {
				t.Fatalf("readRequest() = %v, want %v", err, ua.BadCertificatePolicyCheckFailed)
			}

			// the whole handshake.
			ch, peer = newTestServerChannel(t, testServer)
			err = openTestChannel(t, ch, peer, mustEncode(t, testOpenChunk(p, testShortClient, testServer, 1)))
			if allowed && err != nil {
				t.Fatalf("Open() = %v, want success", err)
			}
			if !allowed && err != ua.BadCertificatePolicyCheckFailed {
				t.Fatalf("Open() = %v, want %v", err, ua.BadCertificatePolicyCheckFailed)
			}
		})
	}
}

// TestServerRejectsPolicyForServerKeyLength checks that a server whose certificate holds a key with a
// length that a security policy does not allow rejects channels with that policy, instead of providing
// a weaker channel.
func TestServerRejectsPolicyForServerKeyLength(t *testing.T) {
	loadTestCredentials(t)
	for _, p := range testRSAPolicies {
		t.Run(p.uri[len("http://opcfoundation.org/UA/SecurityPolicy#"):], func(t *testing.T) {
			allowed := securechannel.MinRSAKeyLength(p.uri) <= 1024
			ch, peer := newTestServerChannel(t, testShortServer)
			_, _, err := readTestRequest(t, ch, peer, mustEncode(t, testOpenChunk(p, testClient, testShortServer, 1)))
			if allowed && err != nil {
				t.Fatalf("readRequest() = %v, want success", err)
			}
			if !allowed && err != ua.BadSecurityPolicyRejected {
				t.Fatalf("readRequest() = %v, want %v", err, ua.BadSecurityPolicyRejected)
			}

			// a key longer than any security policy allows.
			long := testCredential{cert: testServer.cert, key: &rsa.PrivateKey{PublicKey: *testLongKey()}}
			ch, peer = newTestServerChannel(t, long)
			if _, _, err = readTestRequest(t, ch, peer, mustEncode(t, testOpenChunk(p, testClient, testServer, 1))); err != ua.BadSecurityPolicyRejected {
				t.Fatalf("readRequest() with an 8192 bit server key = %v, want %v", err, ua.BadSecurityPolicyRejected)
			}
		})
	}
}

// TestServerOpenRejectsUnsupportedCertificate runs the whole Open handshake with a non RSA certificate.
func TestServerOpenRejectsUnsupportedCertificate(t *testing.T) {
	loadTestCredentials(t)
	ch, peer := newTestServerChannel(t, testServer)
	c := testOpenChunk(testRSAPolicies[2], testClient, testServer, 1)
	c.SenderCertificate = testECDSACert
	err := openTestChannel(t, ch, peer, mustEncode(t, c))
	if err != ua.BadCertificatePolicyCheckFailed {
		t.Fatalf("Open() = %v, want %v", err, ua.BadCertificatePolicyCheckFailed)
	}
}

// openTestChannel runs Open with a Hello message and the given OpenSecureChannel chunk.
func openTestChannel(t *testing.T, ch *serverSecureChannel, peer net.Conn, opn []byte) (err error) {
	t.Helper()
	go func() {
		peer.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := peer.Write(securechanneltest.Hello("opc.tcp://localhost:46219")); err != nil {
			return
		}
		if _, err := securechanneltest.ReadChunk(peer); err != nil {
			return
		}
		if _, err := peer.Write(opn); err != nil {
			return
		}
		securechanneltest.ReadChunk(peer) // the response, if any
	}()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Open panicked: %v", r)
		}
	}()
	return ch.Open()
}

// TestServerOpen checks that a valid secured OpenSecureChannel request opens the channel.
func TestServerOpen(t *testing.T) {
	loadTestCredentials(t)
	for _, p := range testRSAPolicies {
		t.Run(p.uri[len("http://opcfoundation.org/UA/SecurityPolicy#"):], func(t *testing.T) {
			ch, peer := newTestServerChannel(t, testServer)
			if err := openTestChannel(t, ch, peer, mustEncode(t, testOpenChunk(p, testClient, testServer, 1))); err != nil {
				t.Fatalf("Open() = %v", err)
			}
			if ch.remotePublicKey == nil || ch.remotePublicKey.N.Cmp(testClient.key.N) != 0 {
				t.Error("remote public key is not the client's key")
			}
		})
	}
}

// TestServerOpenRejectsInconsistentSecurityMode checks that a channel with an RSA security policy
// cannot be opened with SecurityMode None, which would skip the validation of the certificate.
func TestServerOpenRejectsInconsistentSecurityMode(t *testing.T) {
	loadTestCredentials(t)
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeInvalid, ua.MessageSecurityMode(99)} {
		ch, peer := newTestServerChannel(t, testServer)
		c := testOpenChunk(testRSAPolicies[2], testOtherClient, testServer, 1)
		c.Body = testOpenSecureChannelRequestBody(ua.SecurityTokenRequestTypeIssue, mode, 32)
		if err := openTestChannel(t, ch, peer, mustEncode(t, c)); err != ua.BadSecurityModeRejected {
			t.Errorf("mode %d: Open() = %v, want %v", mode, err, ua.BadSecurityModeRejected)
		}
	}
	// SecurityPolicy None with a secured mode.
	ch, peer := newTestServerChannel(t, testServer)
	c := securechanneltest.AsymmetricChunk{PolicyURI: ua.SecurityPolicyURINone, SequenceNumber: 1, RequestID: 1,
		Body: testOpenSecureChannelRequestBody(ua.SecurityTokenRequestTypeIssue, ua.MessageSecurityModeSign, 0)}
	if err := openTestChannel(t, ch, peer, mustEncode(t, c)); err == nil {
		t.Error("Open() with SecurityPolicy None and SecurityMode Sign succeeded")
	}
}

// TestServerRenewalRejectsChangedSecurity checks that a renewal cannot change the security policy or
// the certificate of the channel, since a renewal does not validate the certificate again.
func TestServerRenewalRejectsChangedSecurity(t *testing.T) {
	loadTestCredentials(t)
	p := testRSAPolicies[2]
	renew := func(c securechanneltest.AsymmetricChunk) securechanneltest.AsymmetricChunk {
		c.Body = testOpenSecureChannelRequestBody(ua.SecurityTokenRequestTypeRenew, ua.MessageSecurityModeSignAndEncrypt, 32)
		return c
	}
	open := func(t *testing.T) (*serverSecureChannel, net.Conn) {
		ch, peer := newTestServerChannel(t, testServer)
		if err := openTestChannel(t, ch, peer, mustEncode(t, testOpenChunk(p, testClient, testServer, 1))); err != nil {
			t.Fatalf("Open() = %v", err)
		}
		return ch, peer
	}

	t.Run("SameSecurity", func(t *testing.T) {
		ch, peer := open(t)
		c := renew(testOpenChunk(p, testClient, testServer, 2))
		c.ChannelID = ch.channelID
		if _, _, err := readTestRequest(t, ch, peer, mustEncode(t, c)); err != nil {
			t.Fatalf("renewal failed: %v", err)
		}
	})
	t.Run("SameLeafOtherChain", func(t *testing.T) {
		// the channel is opened with a certificate chain, and renewed with the leaf certificate only.
		ch, peer := newTestServerChannel(t, testServer)
		c := testOpenChunk(p, testClient, testServer, 1)
		c.SenderCertificate = append(append([]byte{}, testClient.cert...), testOtherClient.cert...)
		if err := openTestChannel(t, ch, peer, mustEncode(t, c)); err != nil {
			t.Fatalf("Open() = %v", err)
		}
		c = renew(testOpenChunk(p, testClient, testServer, 2))
		c.ChannelID = ch.channelID
		if _, _, err := readTestRequest(t, ch, peer, mustEncode(t, c)); err != nil {
			t.Fatalf("renewal failed: %v", err)
		}
	})
	t.Run("OtherCertificate", func(t *testing.T) {
		ch, peer := open(t)
		c := renew(testOpenChunk(p, testOtherClient, testServer, 2))
		c.ChannelID = ch.channelID
		if _, _, err := readTestRequest(t, ch, peer, mustEncode(t, c)); err == nil {
			t.Fatal("renewal with another certificate succeeded")
		}
		if ch.remotePublicKey.N.Cmp(testClient.key.N) != 0 {
			t.Error("remote public key was replaced")
		}
	})
	t.Run("OtherPolicy", func(t *testing.T) {
		ch, peer := open(t)
		c := renew(testOpenChunk(testRSAPolicies[4], testClient, testServer, 2))
		c.ChannelID = ch.channelID
		if _, _, err := readTestRequest(t, ch, peer, mustEncode(t, c)); err != ua.BadSecurityPolicyRejected {
			t.Fatalf("renewal with another policy = %v, want %v", err, ua.BadSecurityPolicyRejected)
		}
	})
	t.Run("PolicyNone", func(t *testing.T) {
		ch, peer := open(t)
		c := securechanneltest.AsymmetricChunk{ChannelID: ch.channelID, PolicyURI: ua.SecurityPolicyURINone, SequenceNumber: 2, RequestID: 2,
			Body: testOpenSecureChannelRequestBody(ua.SecurityTokenRequestTypeRenew, ua.MessageSecurityModeNone, 0)}
		if _, _, err := readTestRequest(t, ch, peer, mustEncode(t, c)); err != ua.BadSecurityPolicyRejected {
			t.Fatalf("renewal with policy None = %v, want %v", err, ua.BadSecurityPolicyRejected)
		}
		if ch.securityPolicyURI != p.uri {
			t.Errorf("security policy changed to %s", ch.securityPolicyURI)
		}
	})
	t.Run("OtherChannel", func(t *testing.T) {
		ch, peer := open(t)
		c := renew(testOpenChunk(p, testClient, testServer, 2))
		c.ChannelID = ch.channelID + 1
		if _, _, err := readTestRequest(t, ch, peer, mustEncode(t, c)); err == nil {
			t.Fatal("renewal for another channel succeeded")
		}
	})
}
