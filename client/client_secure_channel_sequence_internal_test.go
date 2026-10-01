package client

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awcullen/opcua/internal/securechannel/securechanneltest"
	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

// TestClientSequenceNumbers checks that replayed and out of order chunks are rejected (issue #6).
func TestClientSequenceNumbers(t *testing.T) {
	loadTestCredentials(t)
	p := testRSAPolicies[2]
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
		pol := p
		if mode == ua.MessageSecurityModeNone {
			pol = testPolicy{ua.SecurityPolicyURINone, new(ua.SecurityPolicyNone)}
		}
		newChannel := func(t *testing.T) (*clientSecureChannel, net.Conn, securechanneltest.SymmetricChunk) {
			ch, peer, keys := newTestReceivingChannel(t, pol, mode, testClient, testServer)
			return ch, peer, securechanneltest.SymmetricChunk{
				MessageType: ua.MessageTypeFinal, ChannelID: 1, TokenID: 1, RequestID: 5,
				Body: testReadResponseBody(), Policy: pol.policy, Mode: mode, Keys: keys,
			}
		}
		// read sends the chunk with the given sequence number and returns the result of readResponse.
		read := func(t *testing.T, ch *clientSecureChannel, peer net.Conn, c securechanneltest.SymmetricChunk, n uint32) ua.StatusCode {
			c.SequenceNumber = n
			_, status := readTestResponse(t, ch, peer, c.Encode())
			return status
		}
		type step struct {
			n  uint32
			ok bool
		}
		cases := map[string][]step{
			"Increment":        {{100, true}, {101, true}, {102, true}},
			"Replay":           {{100, true}, {101, true}, {101, false}},
			"ReplayOlder":      {{100, true}, {101, true}, {100, false}},
			"Gap":              {{100, true}, {102, false}},
			"Rollover":         {{math.MaxUint32 - 1, true}, {math.MaxUint32, true}, {1, true}, {2, true}},
			"InvalidRollover":  {{math.MaxUint32 - 2000, true}, {1, false}},
			"RolloverTooLarge": {{math.MaxUint32, true}, {1024, false}},
		}
		for name, steps := range cases {
			t.Run(mode.String()+"/"+name, func(t *testing.T) {
				ch, peer, c := newChannel(t)
				for i, s := range steps {
					status := read(t, ch, peer, c, s.n)
					if s.ok && status != ua.Good {
						t.Fatalf("step %d: sequence number %d: %v", i, s.n, status)
					}
					if !s.ok && status != ua.BadSequenceNumberInvalid {
						t.Fatalf("step %d: sequence number %d: got %v, want %v", i, s.n, status, ua.BadSequenceNumberInvalid)
					}
				}
			})
		}
		if mode != ua.MessageSecurityModeNone {
			t.Run(mode.String()+"/UnauthenticatedChunkIgnored", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				if status := read(t, ch, peer, c, 100); status != ua.Good {
					t.Fatal(status)
				}
				// a forged chunk does not change the expected sequence number.
				forged := c
				forged.SequenceNumber = 500
				chunk := forged.Encode()
				chunk[len(chunk)-1] ^= 0x01
				if _, status := readTestResponse(t, ch, peer, chunk); status != ua.BadSecurityChecksFailed {
					t.Fatalf("forged chunk: %v", status)
				}
				if status := read(t, ch, peer, c, 101); status != ua.Good {
					t.Fatalf("sequence number 101 after a forged chunk: %v", status)
				}
			})
		}
	}

	// the sequence numbers are shared by OpenSecureChannel and other messages.
	t.Run("SharedWithOpenSecureChannel", func(t *testing.T) {
		ch, peer, keys := newTestReceivingChannel(t, p, ua.MessageSecurityModeSignAndEncrypt, testClient, testServer)
		if _, status := readTestResponse(t, ch, peer, mustEncode(t, testOpenResponseChunk(p, testClient, testServer, 41))); status != ua.Good {
			t.Fatalf("OpenSecureChannel response 41: %v", status)
		}
		msg := securechanneltest.SymmetricChunk{
			MessageType: ua.MessageTypeFinal, ChannelID: 1, TokenID: 1, SequenceNumber: 42, RequestID: 5,
			Body: testReadResponseBody(), Policy: p.policy, Mode: ua.MessageSecurityModeSignAndEncrypt, Keys: keys,
		}
		if _, status := readTestResponse(t, ch, peer, msg.Encode()); status != ua.Good {
			t.Fatalf("message 42: %v", status)
		}
		if _, status := readTestResponse(t, ch, peer, mustEncode(t, testOpenResponseChunk(p, testClient, testServer, 43))); status != ua.Good {
			t.Fatalf("OpenSecureChannel response 43: %v", status)
		}
		msg.SequenceNumber = 43
		if _, status := readTestResponse(t, ch, peer, msg.Encode()); status != ua.BadSequenceNumberInvalid {
			t.Fatalf("message 43 after OpenSecureChannel response 43: got %v, want %v", status, ua.BadSequenceNumberInvalid)
		}
	})
}

// TestClientServerSequenceNumbers checks that the client and server of this library agree on the
// sequence numbers of a secure channel, including when the security token is renewed (issue #6).
func TestClientServerSequenceNumbers(t *testing.T) {
	loadTestCredentials(t)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testServer.cert}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testServer.key)}), 0600); err != nil {
		t.Fatal(err)
	}
	endpointURL := fmt.Sprintf("opc.tcp://localhost:%d", 46211)
	srv, err := server.New(
		ua.ApplicationDescription{
			ApplicationURI:  "urn:localhost:testserver",
			ApplicationName: ua.LocalizedText{Text: "testserver"},
			ApplicationType: ua.ApplicationTypeServer,
			DiscoveryURLs:   []string{endpointURL},
		},
		certFile, keyFile, endpointURL,
		server.WithSecurityPolicyNone(true),
		server.WithAnonymousIdentity(true),
		server.WithInsecureSkipVerify(),
	)
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
		t.Run(mode.String(), func(t *testing.T) {
			policyURI := ua.SecurityPolicyURIBasic256Sha256
			if mode == ua.MessageSecurityModeNone {
				policyURI = ua.SecurityPolicyURINone
			}
			var c *Client
			var err error
			for i := 0; i < 50; i++ {
				if c, err = Dial(ctx, endpointURL,
					WithSecurityPolicyURI(policyURI, mode),
					WithClientCertificate(testClient.cert, testClient.key),
					WithInsecureSkipVerify(),
				); err == nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if err != nil {
				t.Fatalf("Dial() = %v", err)
			}
			read := func() {
				t.Helper()
				if _, err := c.Read(ctx, &ua.ReadRequest{
					NodesToRead: []ua.ReadValueID{{NodeID: ua.VariableIDServerServerStatus, AttributeID: ua.AttributeIDValue}},
				}); err != nil {
					c.Abort(ctx)
					t.Fatalf("Read() = %v", err)
				}
			}
			read()
			for i := 0; i < 3; i++ {
				// renew the security token; the server switches to the new token with the next request.
				if err := c.channel.renewToken(ctx); err != nil {
					c.Abort(ctx)
					t.Fatalf("renewToken() = %v", err)
				}
				read()
				read()
			}
			if err := c.Close(ctx); err != nil {
				t.Fatalf("Close() = %v", err)
			}
		})
	}
}
