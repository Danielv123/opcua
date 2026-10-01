package server_test

import (
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
