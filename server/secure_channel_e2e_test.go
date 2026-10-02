package server_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/internal/securechannel/securechanneltest"
	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

// hardeningServerPort is the port of the server that is attacked by the secure channel hardening tests.
const hardeningServerPort = 46210

var (
	hardeningServerOnce sync.Once
	hardeningServerErr  error
	hardeningServerKey  *rsa.PrivateKey
	hardeningServerCert []byte
	hardeningClientKey  *rsa.PrivateKey
	hardeningClientCert []byte
)

// hardeningServerURL starts a server with security policies None and RSA, which accepts any
// client certificate, and returns its endpoint url. The server runs until the tests end.
func hardeningServerURL(t *testing.T) string {
	t.Helper()
	endpointURL := fmt.Sprintf("opc.tcp://localhost:%d", hardeningServerPort)
	hardeningServerOnce.Do(func() {
		hardeningServerErr = func() error {
			var err error
			if hardeningServerKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
				return err
			}
			if hardeningServerCert, err = securechanneltest.NewCertificate("urn:localhost:hardeningserver", hardeningServerKey, &hardeningServerKey.PublicKey); err != nil {
				return err
			}
			if hardeningClientKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
				return err
			}
			if hardeningClientCert, err = securechanneltest.NewCertificate("urn:localhost:hardeningclient", hardeningClientKey, &hardeningClientKey.PublicKey); err != nil {
				return err
			}
			dir, err := os.MkdirTemp("", "opcua-hardening")
			if err != nil {
				return err
			}
			certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
			if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hardeningServerCert}), 0600); err != nil {
				return err
			}
			if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(hardeningServerKey)}), 0600); err != nil {
				return err
			}
			srv, err := server.New(
				ua.ApplicationDescription{
					ApplicationURI:  "urn:localhost:hardeningserver",
					ApplicationName: ua.LocalizedText{Text: "hardeningserver"},
					ApplicationType: ua.ApplicationTypeServer,
					DiscoveryURLs:   []string{endpointURL},
				},
				certFile, keyFile, endpointURL,
				server.WithSecurityPolicyNone(true),
				server.WithAnonymousIdentity(true),
				server.WithAuthenticateX509IdentityFunc(func(ua.X509Identity, string, string) error { return nil }),
				server.WithInsecureSkipVerify(),
			)
			if err != nil {
				return err
			}
			go srv.ListenAndServe()
			for i := 0; i < 100; i++ {
				if _, err = client.FindServers(context.Background(), &ua.FindServersRequest{EndpointURL: endpointURL}); err == nil {
					return nil
				}
				time.Sleep(100 * time.Millisecond)
			}
			return err
		}()
	})
	if hardeningServerErr != nil {
		t.Fatalf("Error starting server: %v", hardeningServerErr)
	}
	return endpointURL
}

// checkServerAvailable checks that the server still opens secure channels and sessions and handles requests.
func checkServerAvailable(t *testing.T, endpointURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeSignAndEncrypt} {
		policyURI := ua.SecurityPolicyURIBasic256Sha256
		if mode == ua.MessageSecurityModeNone {
			policyURI = ua.SecurityPolicyURINone
		}
		c, err := client.Dial(ctx, endpointURL,
			client.WithSecurityPolicyURI(policyURI, mode),
			client.WithClientCertificate(hardeningClientCert, hardeningClientKey),
			client.WithInsecureSkipVerify(),
		)
		if err != nil {
			t.Fatalf("server is not available: Dial(%s) = %v", mode, err)
		}
		_, err = c.Read(ctx, &ua.ReadRequest{
			NodesToRead: []ua.ReadValueID{{NodeID: ua.VariableIDServerServerStatus, AttributeID: ua.AttributeIDValue}},
		})
		if err != nil {
			c.Abort(ctx)
			t.Fatalf("server is not available: Read = %v", err)
		}
		if err := c.Close(ctx); err != nil {
			t.Fatalf("Close() = %v", err)
		}
	}
}

// rawConnection connects to the server and exchanges Hello and Acknowledge messages.
func rawConnection(t *testing.T, endpointURL string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", hardeningServerPort))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(securechanneltest.Hello(endpointURL)); err != nil {
		t.Fatal(err)
	}
	ack, err := securechanneltest.ReadChunk(conn)
	if err != nil || binary.LittleEndian.Uint32(ack) != ua.MessageTypeAck {
		t.Fatalf("no Acknowledge received: %v", err)
	}
	return conn
}

// expectRejected checks that the server answers with an Error message, or closes the connection.
// It returns the status code of the Error message.
func expectRejected(t *testing.T, conn net.Conn) ua.StatusCode {
	t.Helper()
	chunk, err := securechanneltest.ReadChunk(conn)
	if err != nil {
		return ua.BadSecureChannelClosed
	}
	if binary.LittleEndian.Uint32(chunk) != ua.MessageTypeError || len(chunk) < 12 {
		t.Fatalf("got message type %q, want an Error message", chunk[:4])
	}
	return ua.StatusCode(binary.LittleEndian.Uint32(chunk[8:]))
}

// openSecureChannelChunk returns an OpenSecureChannel request chunk for the hardening server.
func openSecureChannelChunk(senderCert []byte) securechanneltest.AsymmetricChunk {
	thumbprint := sha1.Sum(hardeningServerCert)
	return securechanneltest.AsymmetricChunk{
		PolicyURI:          ua.SecurityPolicyURIBasic256Sha256,
		Policy:             new(ua.SecurityPolicyBasic256Sha256),
		SenderCertificate:  senderCert,
		ReceiverThumbprint: thumbprint[:],
		SequenceNumber:     1,
		RequestID:          1,
		Body: securechanneltest.EncodeBody(ua.ObjectIDOpenSecureChannelRequestEncodingDefaultBinary, &ua.OpenSecureChannelRequest{
			RequestHeader:     ua.RequestHeader{RequestHandle: 1, TimeoutHint: 1000},
			RequestType:       ua.SecurityTokenRequestTypeIssue,
			SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
			ClientNonce:       ua.ByteString(make([]byte, 32)),
			RequestedLifetime: 3600000,
		}),
		SenderKey:   hardeningClientKey,
		ReceiverKey: &hardeningServerKey.PublicKey,
	}
}

// rawSecureChannel is the client side of a secure channel opened over a raw connection.
type rawSecureChannel struct {
	conn           net.Conn
	mode           ua.MessageSecurityMode
	channelID      uint32
	tokenID        uint32
	keys           securechanneltest.SymmetricKeys
	sequenceNumber uint32
}

// openRawSecureChannel opens a secure channel with SecurityPolicy Basic256Sha256 over a raw connection.
func openRawSecureChannel(t *testing.T, endpointURL string, mode ua.MessageSecurityMode) *rawSecureChannel {
	t.Helper()
	policy := new(ua.SecurityPolicyBasic256Sha256)
	conn := rawConnection(t, endpointURL)
	clientNonce := make([]byte, 32)
	rand.Read(clientNonce)
	opn := openSecureChannelChunk(hardeningClientCert)
	opn.Body = securechanneltest.EncodeBody(ua.ObjectIDOpenSecureChannelRequestEncodingDefaultBinary, &ua.OpenSecureChannelRequest{
		RequestHeader:     ua.RequestHeader{RequestHandle: 1, TimeoutHint: 1000},
		RequestType:       ua.SecurityTokenRequestTypeIssue,
		SecurityMode:      mode,
		ClientNonce:       ua.ByteString(clientNonce),
		RequestedLifetime: 3600000,
	})
	chunk, err := opn.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(chunk); err != nil {
		t.Fatal(err)
	}
	if chunk, err = securechanneltest.ReadChunk(conn); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(chunk) != ua.MessageTypeOpenFinal {
		t.Fatalf("got message type %q, want an OpenSecureChannel response", chunk[:4])
	}
	_, plainText, err := securechanneltest.DecryptAsymmetric(chunk, policy, hardeningClientKey)
	if err != nil {
		t.Fatal(err)
	}
	dec := ua.NewBinaryDecoder(bytes.NewReader(plainText[8:]), ua.NewEncodingContext())
	var id ua.NodeID
	res := new(ua.OpenSecureChannelResponse)
	if err := dec.ReadNodeID(&id); err != nil || id != ua.ObjectIDOpenSecureChannelResponseEncodingDefaultBinary {
		t.Fatalf("unexpected response %v, %v", id, err)
	}
	if err := dec.Decode(res); err != nil {
		t.Fatal(err)
	}
	return &rawSecureChannel{
		conn:           conn,
		mode:           mode,
		channelID:      res.SecurityToken.ChannelID,
		tokenID:        res.SecurityToken.TokenID,
		keys:           securechanneltest.DeriveKeys(ua.SecurityPolicyURIBasic256Sha256, policy, []byte(res.ServerNonce), clientNonce),
		sequenceNumber: 2,
	}
}

// message returns the next message chunk with a FindServers request.
func (ch *rawSecureChannel) message(requestID uint32) securechanneltest.SymmetricChunk {
	c := securechanneltest.SymmetricChunk{
		MessageType: ua.MessageTypeFinal, ChannelID: ch.channelID, TokenID: ch.tokenID, SequenceNumber: ch.sequenceNumber, RequestID: requestID,
		Body: securechanneltest.EncodeBody(ua.ObjectIDFindServersRequestEncodingDefaultBinary, &ua.FindServersRequest{
			RequestHeader: ua.RequestHeader{RequestHandle: requestID, TimeoutHint: 1000},
		}),
		Policy: new(ua.SecurityPolicyBasic256Sha256), Mode: ch.mode, Keys: ch.keys,
	}
	ch.sequenceNumber++
	return c
}

// expectResponse checks that the server answers with a message.
func expectResponse(t *testing.T, conn net.Conn) {
	t.Helper()
	chunk, err := securechanneltest.ReadChunk(conn)
	if err != nil {
		t.Fatalf("no response: %v", err)
	}
	if binary.LittleEndian.Uint32(chunk) != ua.MessageTypeFinal {
		t.Fatalf("got message type %q, want a message", chunk[:4])
	}
}

// TestSecureChannelRejectsMalformedOpenSecureChannel sends an OpenSecureChannel request with a valid
// signature and a padding size larger than the chunk, and checks that the server rejects it and
// remains available (issue #5).
func TestSecureChannelRejectsMalformedOpenSecureChannel(t *testing.T) {
	endpointURL := hardeningServerURL(t)
	conn := rawConnection(t, endpointURL)
	opn := openSecureChannelChunk(hardeningClientCert)
	opn.MutateFooter = func(footer []byte) {
		for i := range footer {
			footer[i] = 0xFF
		}
	}
	chunk, err := opn.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(chunk); err != nil {
		t.Fatal(err)
	}
	if code := expectRejected(t, conn); code == ua.Good {
		t.Errorf("got %v, want an error", code)
	}
	checkServerAvailable(t, endpointURL)
}

// TestSecureChannelRejectsMalformedMessageChunk opens a secure channel, then sends chunks that are too
// short to hold a signature, and checks that the server closes the channel and remains available (issue #5).
func TestSecureChannelRejectsMalformedMessageChunk(t *testing.T) {
	endpointURL := hardeningServerURL(t)
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
		t.Run(mode.String(), func(t *testing.T) {
			ch := openRawSecureChannel(t, endpointURL, mode)
			// a valid message is answered.
			if _, err := ch.conn.Write(ch.message(2).Encode()); err != nil {
				t.Fatal(err)
			}
			expectResponse(t, ch.conn)
			// the headers of a message, without sequence header, body and signature.
			chunk := ch.message(3).Encode()[:16]
			binary.LittleEndian.PutUint32(chunk[4:], 16)
			if _, err := ch.conn.Write(chunk); err != nil {
				t.Fatal(err)
			}
			if code := expectRejected(t, ch.conn); code == ua.Good {
				t.Errorf("got %v, want an error", code)
			}
			checkServerAvailable(t, endpointURL)
		})
	}
}

// TestSecureChannelRejectsReplayedMessage opens a secure channel, sends a message and then replays it,
// and checks that the server does not process the replayed message and remains available (issue #6).
func TestSecureChannelRejectsReplayedMessage(t *testing.T) {
	endpointURL := hardeningServerURL(t)
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
		t.Run(mode.String(), func(t *testing.T) {
			ch := openRawSecureChannel(t, endpointURL, mode)
			msg := ch.message(2).Encode()
			if _, err := ch.conn.Write(msg); err != nil {
				t.Fatal(err)
			}
			expectResponse(t, ch.conn)
			// a later message is answered.
			if _, err := ch.conn.Write(ch.message(3).Encode()); err != nil {
				t.Fatal(err)
			}
			expectResponse(t, ch.conn)
			// the replayed message is rejected.
			if _, err := ch.conn.Write(msg); err != nil {
				t.Fatal(err)
			}
			if code := expectRejected(t, ch.conn); code == ua.Good {
				t.Errorf("got %v, want an error", code)
			}
			checkServerAvailable(t, endpointURL)
		})
	}
}

// TestSecureChannelRejectsNonRSACertificate sends an OpenSecureChannel request with an ECDSA
// certificate, and checks that the server rejects it and remains available (issue #1).
func TestSecureChannelRejectsNonRSACertificate(t *testing.T) {
	endpointURL := hardeningServerURL(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := securechanneltest.NewCertificate("urn:localhost:ecdsaclient", key, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	conn := rawConnection(t, endpointURL)
	chunk, err := openSecureChannelChunk(cert).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(chunk); err != nil {
		t.Fatal(err)
	}
	if code := expectRejected(t, conn); code != ua.BadCertificatePolicyCheckFailed {
		t.Errorf("got %v, want %v", code, ua.BadCertificatePolicyCheckFailed)
	}
	checkServerAvailable(t, endpointURL)
}

// TestActivateSessionRejectsInvalidIdentityCertificate activates sessions with X509 identity tokens whose
// certificates hold a huge or an undersized RSA key, and checks that the server rejects them quickly,
// before it uses the key, and remains available (issue #1).
func TestActivateSessionRejectsInvalidIdentityCertificate(t *testing.T) {
	endpointURL := hardeningServerURL(t)
	identityKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	validCert, err := securechanneltest.NewCertificate("urn:localhost:user", identityKey, &identityKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	hugeKey := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), 1<<20-1, 1), E: 1<<31 - 1}
	hugeCert, err := securechanneltest.NewCertificate("urn:localhost:user", identityKey, hugeKey)
	if err != nil {
		t.Fatal(err)
	}
	shortKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	shortCert, err := securechanneltest.NewCertificate("urn:localhost:user", shortKey, &shortKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dial := func(cert []byte, key *rsa.PrivateKey) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := client.Dial(ctx, endpointURL,
			client.WithSecurityPolicyURI(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt),
			client.WithClientCertificate(hardeningClientCert, hardeningClientKey),
			client.WithInsecureSkipVerify(),
			client.WithX509Identity(cert, key),
		)
		if err == nil {
			c.Close(ctx)
		}
		return err
	}

	// a valid identity is accepted.
	if err := dial(validCert, identityKey); err != nil {
		t.Fatalf("Dial() with a valid identity = %v", err)
	}
	// a certificate with a 1 megabit modulus is rejected before the signature is verified with it.
	start := time.Now()
	if err := dial(hugeCert, identityKey); err != ua.BadIdentityTokenInvalid {
		t.Errorf("Dial() with a huge identity key = %v, want %v", err, ua.BadIdentityTokenInvalid)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("Dial() with a huge identity key took %v", d)
	}
	// a certificate with a 1024 bit key is rejected for the Basic256Sha256 token policy. The token is
	// signed with a longer key, so that a client that checks its own key still sends it.
	if err := dial(shortCert, identityKey); err != ua.BadIdentityTokenInvalid {
		t.Errorf("Dial() with a 1024 bit identity key = %v, want %v", err, ua.BadIdentityTokenInvalid)
	}
	checkServerAvailable(t, endpointURL)
}
