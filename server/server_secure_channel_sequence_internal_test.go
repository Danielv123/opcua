package server

import (
	"math"
	"net"
	"testing"

	"github.com/awcullen/opcua/internal/securechannel/securechanneltest"
	"github.com/awcullen/opcua/ua"
)

// TestServerSequenceNumbers checks that replayed and out of order chunks are rejected (issue #6).
func TestServerSequenceNumbers(t *testing.T) {
	loadTestCredentials(t)
	p := testRSAPolicies[2]
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
		pol := p
		if mode == ua.MessageSecurityModeNone {
			pol = testPolicy{ua.SecurityPolicyURINone, new(ua.SecurityPolicyNone)}
		}
		newChannel := func(t *testing.T) (*serverSecureChannel, net.Conn, securechanneltest.SymmetricChunk) {
			ch, peer := newTestServerChannel(t, testServer)
			keys := establishTestChannel(ch, pol, mode)
			return ch, peer, securechanneltest.SymmetricChunk{
				MessageType: ua.MessageTypeFinal, ChannelID: ch.channelID, TokenID: 1, RequestID: 5,
				Body: testReadRequestBody(), Policy: pol.policy, Mode: mode, Keys: keys,
			}
		}
		// read sends the chunk with the given sequence number and returns the result of readRequest.
		read := func(t *testing.T, ch *serverSecureChannel, peer net.Conn, c securechanneltest.SymmetricChunk, n uint32) error {
			c.SequenceNumber = n
			_, _, err := readTestRequest(t, ch, peer, c.Encode())
			return err
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
					err := read(t, ch, peer, c, s.n)
					if s.ok && err != nil {
						t.Fatalf("step %d: sequence number %d: %v", i, s.n, err)
					}
					if !s.ok && err != ua.BadSequenceNumberInvalid {
						t.Fatalf("step %d: sequence number %d: got %v, want %v", i, s.n, err, ua.BadSequenceNumberInvalid)
					}
				}
			})
		}
		if mode != ua.MessageSecurityModeNone {
			t.Run(mode.String()+"/UnauthenticatedChunkIgnored", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				if err := read(t, ch, peer, c, 100); err != nil {
					t.Fatal(err)
				}
				// a forged chunk does not change the expected sequence number.
				forged := c
				forged.SequenceNumber = 500
				chunk := forged.Encode()
				chunk[len(chunk)-1] ^= 0x01
				if _, _, err := readTestRequest(t, ch, peer, chunk); err != ua.BadSecurityChecksFailed {
					t.Fatalf("forged chunk: %v", err)
				}
				if err := read(t, ch, peer, c, 101); err != nil {
					t.Fatalf("sequence number 101 after a forged chunk: %v", err)
				}
			})
		}
	}

	// the sequence numbers are shared by OpenSecureChannel and other messages.
	t.Run("SharedWithOpenSecureChannel", func(t *testing.T) {
		ch, peer := newTestServerChannel(t, testServer)
		if err := openTestChannel(t, ch, peer, mustEncode(t, testOpenChunk(p, testClient, testServer, 41))); err != nil {
			t.Fatalf("Open() = %v", err)
		}
		a, b, c := p.policy.SymSignatureKeySize(), p.policy.SymEncryptionKeySize(), p.policy.SymEncryptionBlockSize()
		k := calculatePSHA(ch.localNonce, ch.remoteNonce, a+b+c, p.uri)
		msg := securechanneltest.SymmetricChunk{
			MessageType: ua.MessageTypeFinal, ChannelID: ch.channelID, TokenID: ch.pendingTokenID, SequenceNumber: 42, RequestID: 5,
			Body: testReadRequestBody(), Policy: p.policy, Mode: ua.MessageSecurityModeSignAndEncrypt,
			Keys: securechanneltest.SymmetricKeys{SigningKey: k[:a], EncryptingKey: k[a : a+b], InitializationVector: k[a+b:]},
		}
		if _, _, err := readTestRequest(t, ch, peer, msg.Encode()); err != nil {
			t.Fatalf("message 42: %v", err)
		}
		renew := testOpenChunk(p, testClient, testServer, 43)
		renew.ChannelID = ch.channelID
		renew.Body = testOpenSecureChannelRequestBody(ua.SecurityTokenRequestTypeRenew, ua.MessageSecurityModeSignAndEncrypt, 32)
		if _, _, err := readTestRequest(t, ch, peer, mustEncode(t, renew)); err != nil {
			t.Fatalf("renewal 43: %v", err)
		}
		msg.SequenceNumber = 43
		if _, _, err := readTestRequest(t, ch, peer, msg.Encode()); err != ua.BadSequenceNumberInvalid {
			t.Fatalf("message 43 after renewal 43: got %v, want %v", err, ua.BadSequenceNumberInvalid)
		}
	})
}
