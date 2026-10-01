package client

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/awcullen/opcua/internal/securechannel/securechanneltest"
	"github.com/awcullen/opcua/ua"
)

// newTestReceivingChannel returns a client secure channel in the state reached after Open, which
// receives chunks written to the returned peer. It returns the keys the server uses to send chunks.
func newTestReceivingChannel(t *testing.T, p testPolicy, mode ua.MessageSecurityMode, client, server testCredential) (*clientSecureChannel, net.Conn, securechanneltest.SymmetricKeys) {
	t.Helper()
	ch := newTestClientSecureChannel("opc.tcp://localhost:46219", p.uri, mode, client, server.cert)
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		conn.Close()
		peer.Close()
	})
	ch.conn = conn
	ch.securityPolicy = p.policy
	ch.localSigningKey = make([]byte, p.policy.SymSignatureKeySize())
	ch.localEncryptingKey = make([]byte, p.policy.SymEncryptionKeySize())
	ch.localInitializationVector = make([]byte, p.policy.SymEncryptionBlockSize())
	ch.remoteSigningKey = make([]byte, p.policy.SymSignatureKeySize())
	ch.remoteEncryptingKey = make([]byte, p.policy.SymEncryptionKeySize())
	ch.remoteInitializationVector = make([]byte, p.policy.SymEncryptionBlockSize())
	if mode != ua.MessageSecurityModeNone {
		ch.localPrivateKeySize = ch.localPrivateKey.Size()
		ch.remotePublicKeySize = ch.remotePublicKey.Size()
	}
	ch.channelID = 1
	ch.tokenID = 1
	ch.localNonce = getNextNonce(p.policy.NonceSize())
	ch.remoteNonce = getNextNonce(p.policy.NonceSize())
	if mode == ua.MessageSecurityModeNone {
		return ch, peer, securechanneltest.SymmetricKeys{}
	}
	a, b, c := p.policy.SymSignatureKeySize(), p.policy.SymEncryptionKeySize(), p.policy.SymEncryptionBlockSize()
	k := calculatePSHA(ch.localNonce, ch.remoteNonce, a+b+c, p.uri)
	return ch, peer, securechanneltest.SymmetricKeys{SigningKey: k[:a], EncryptingKey: k[a : a+b], InitializationVector: k[a+b:]}
}

// readTestResponse writes the chunks to the peer end of the channel and returns the result of readResponse.
func readTestResponse(t *testing.T, ch *clientSecureChannel, peer net.Conn, chunks ...[]byte) (res ua.ServiceResponse, status ua.StatusCode) {
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
			t.Fatalf("readResponse panicked: %v", r)
		}
	}()
	ch.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	return ch.readResponse()
}

func testReadResponseBody() []byte {
	return securechanneltest.EncodeBody(ua.ObjectIDReadResponseEncodingDefaultBinary, &ua.ReadResponse{
		ResponseHeader: ua.ResponseHeader{Timestamp: time.Now(), RequestHandle: 7},
		Results:        []ua.DataValue{{Value: int32(42)}},
	})
}

// testOpenResponseChunk returns a valid OpenSecureChannel response chunk from server to client.
func testOpenResponseChunk(p testPolicy, client, server testCredential, sequenceNumber uint32) securechanneltest.AsymmetricChunk {
	thumbprint := sha1.Sum(client.cert)
	return securechanneltest.AsymmetricChunk{
		ChannelID:          1,
		PolicyURI:          p.uri,
		Policy:             p.policy,
		SenderCertificate:  server.cert,
		ReceiverThumbprint: thumbprint[:],
		SequenceNumber:     sequenceNumber,
		RequestID:          1,
		Body: securechanneltest.EncodeBody(ua.ObjectIDOpenSecureChannelResponseEncodingDefaultBinary, &ua.OpenSecureChannelResponse{
			ResponseHeader: ua.ResponseHeader{Timestamp: time.Now(), RequestHandle: 1},
			SecurityToken:  ua.ChannelSecurityToken{ChannelID: 1, TokenID: 2, CreatedAt: time.Now(), RevisedLifetime: 3600000},
			ServerNonce:    ua.ByteString(getNextNonce(p.policy.NonceSize())),
		}),
		SenderKey:   server.key,
		ReceiverKey: &client.key.PublicKey,
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

// setMessageSize updates the message size in the header of a chunk.
func setMessageSize(chunk []byte) []byte {
	binary.LittleEndian.PutUint32(chunk[4:], uint32(len(chunk)))
	return chunk
}

// asymmetricHeaderSize returns the size of the message header and asymmetric security header.
func asymmetricHeaderSize(c securechanneltest.AsymmetricChunk) int {
	return 12 + 4 + len(c.PolicyURI) + 4 + len(c.SenderCertificate) + 4 + len(c.ReceiverThumbprint)
}

// withAsymmetricPadding appends bytes to the body of the chunk until it has at least 2 bytes of padding.
func withAsymmetricPadding(c securechanneltest.AsymmetricChunk) securechanneltest.AsymmetricChunk {
	plainTextBlockSize := c.ReceiverKey.Size() - c.Policy.RSAPaddingSize()
	paddingHeaderSize := 1
	if c.ReceiverKey.Size() > 256 {
		paddingHeaderSize = 2
	}
	for {
		n := 8 + len(c.Body) + paddingHeaderSize + c.SenderKey.Size()
		if paddingSize := (plainTextBlockSize - n%plainTextBlockSize) % plainTextBlockSize; paddingSize >= 2 {
			return c
		}
		c.Body = append(c.Body, 0)
	}
}

// withSymmetricPadding appends bytes to the body of the chunk until it has at least 2 bytes of padding.
func withSymmetricPadding(c securechanneltest.SymmetricChunk) securechanneltest.SymmetricChunk {
	blockSize := c.Policy.SymEncryptionBlockSize()
	for {
		n := 8 + len(c.Body) + 1 + c.Policy.SymSignatureSize()
		if paddingSize := (blockSize - n%blockSize) % blockSize; paddingSize >= 2 {
			return c
		}
		c.Body = append(c.Body, 0)
	}
}

// TestClientAsymmetricChunkValidation checks the bounds checks of the OpenSecureChannel response receive path (issue #5).
func TestClientAsymmetricChunkValidation(t *testing.T) {
	loadTestCredentials(t)
	type keyPair struct {
		name           string
		client, server testCredential
	}
	keyPairs := []keyPair{
		{"2048", testClient, testServer},
		{"3072", testClientLarge, testServer},
	}
	for _, p := range testRSAPolicies {
		for _, kp := range keyPairs {
			name := p.uri[len("http://opcfoundation.org/UA/SecurityPolicy#"):] + "/" + kp.name
			valid := func() securechanneltest.AsymmetricChunk { return testOpenResponseChunk(p, kp.client, kp.server, 1) }
			newChannel := func(t *testing.T) (*clientSecureChannel, net.Conn) {
				ch, peer, _ := newTestReceivingChannel(t, p, ua.MessageSecurityModeSignAndEncrypt, kp.client, kp.server)
				return ch, peer
			}

			t.Run(name+"/Valid", func(t *testing.T) {
				ch, peer := newChannel(t)
				res, status := readTestResponse(t, ch, peer, mustEncode(t, valid()))
				if r, ok := res.(*ua.OpenSecureChannelResponse); status != ua.Good || !ok || r.SecurityToken.TokenID != 2 {
					t.Fatalf("readResponse() = %T, %v", res, status)
				}
			})

			invalid := map[string]func(t *testing.T) []byte{
				"PartialBlock": func(t *testing.T) []byte {
					b := mustEncode(t, valid())
					return setMessageSize(b[:len(b)-1])
				},
				"MissingBlock": func(t *testing.T) []byte {
					b := mustEncode(t, valid())
					return setMessageSize(b[:len(b)-kp.client.key.Size()])
				},
				"HeaderOnly": func(t *testing.T) []byte {
					b := mustEncode(t, valid())
					return setMessageSize(b[:asymmetricHeaderSize(valid())])
				},
				"SingleBlock": func(t *testing.T) []byte {
					// a valid encrypted block that is too short to hold the signature.
					b := mustEncode(t, valid())
					header := b[:asymmetricHeaderSize(valid())]
					plainText := make([]byte, kp.client.key.Size()-p.policy.RSAPaddingSize())
					chunk, err := securechanneltest.EncryptAsymmetric(p.policy, &kp.client.key.PublicKey, header, plainText)
					if err != nil {
						t.Fatal(err)
					}
					return setMessageSize(chunk)
				},
				"InvalidSignature": func(t *testing.T) []byte {
					c := valid()
					c.SenderKey = testOtherServer.key
					return mustEncode(t, c)
				},
				"PaddingSizeTooLarge": func(t *testing.T) []byte {
					c := valid()
					c.MutateFooter = func(f []byte) {
						for i := range f {
							f[i] = 0xFF
						}
					}
					return mustEncode(t, c)
				},
				"PaddingMismatch": func(t *testing.T) []byte {
					c := withAsymmetricPadding(valid())
					c.MutateFooter = func(f []byte) { f[0] ^= 0x01 }
					return mustEncode(t, c)
				},
			}
			for invalidName, chunk := range invalid {
				t.Run(name+"/"+invalidName, func(t *testing.T) {
					ch, peer := newChannel(t)
					res, status := readTestResponse(t, ch, peer, chunk(t))
					if status == ua.Good {
						t.Fatalf("readResponse() = %T, want an error", res)
					}
				})
			}
		}
	}

	t.Run("None/Truncated", func(t *testing.T) {
		valid, err := securechanneltest.AsymmetricChunk{ChannelID: 1, PolicyURI: ua.SecurityPolicyURINone, SequenceNumber: 1, RequestID: 1,
			Body: securechanneltest.EncodeBody(ua.ObjectIDOpenSecureChannelResponseEncodingDefaultBinary, &ua.OpenSecureChannelResponse{})}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		headerSize := 12 + 4 + len(ua.SecurityPolicyURINone) + 4 + 4
		for size := 8; size < headerSize+8; size++ {
			ch, peer, _ := newTestReceivingChannel(t, testPolicy{ua.SecurityPolicyURINone, new(ua.SecurityPolicyNone)}, ua.MessageSecurityModeNone, testClient, testServer)
			chunk := setMessageSize(append([]byte{}, valid[:size]...))
			if _, status := readTestResponse(t, ch, peer, chunk); status == ua.Good {
				t.Errorf("size %d: readResponse succeeded", size)
			}
		}
	})
}

// TestClientSymmetricChunkValidation checks the bounds checks of the MSG receive path (issue #5).
func TestClientSymmetricChunkValidation(t *testing.T) {
	loadTestCredentials(t)
	type config struct {
		p    testPolicy
		mode ua.MessageSecurityMode
	}
	configs := []config{{testPolicy{ua.SecurityPolicyURINone, new(ua.SecurityPolicyNone)}, ua.MessageSecurityModeNone}}
	for _, p := range testRSAPolicies {
		configs = append(configs, config{p, ua.MessageSecurityModeSign}, config{p, ua.MessageSecurityModeSignAndEncrypt})
	}
	for _, cfg := range configs {
		name := cfg.p.uri[len("http://opcfoundation.org/UA/SecurityPolicy#"):] + "/" + cfg.mode.String()
		signatureSize := 0
		if cfg.mode != ua.MessageSecurityModeNone {
			signatureSize = cfg.p.policy.SymSignatureSize()
		}
		paddingHeaderSize := 0
		if cfg.mode == ua.MessageSecurityModeSignAndEncrypt {
			paddingHeaderSize = 1
		}
		newChannel := func(t *testing.T) (*clientSecureChannel, net.Conn, securechanneltest.SymmetricChunk) {
			ch, peer, keys := newTestReceivingChannel(t, cfg.p, cfg.mode, testClient, testServer)
			return ch, peer, securechanneltest.SymmetricChunk{
				MessageType: ua.MessageTypeFinal, ChannelID: 1, TokenID: 1, SequenceNumber: 2, RequestID: 5,
				Body: testReadResponseBody(), Policy: cfg.p.policy, Mode: cfg.mode, Keys: keys,
			}
		}

		t.Run(name+"/Valid", func(t *testing.T) {
			ch, peer, c := newChannel(t)
			res, status := readTestResponse(t, ch, peer, c.Encode())
			if r, ok := res.(*ua.ReadResponse); status != ua.Good || !ok || r.RequestHandle != 7 {
				t.Fatalf("readResponse() = %T, %v", res, status)
			}
		})

		t.Run(name+"/Truncated", func(t *testing.T) {
			// every chunk shorter than the headers, padding header and signature.
			for size := 8; size < 16+8+paddingHeaderSize+signatureSize; size++ {
				ch, peer, c := newChannel(t)
				chunk := make([]byte, size)
				copy(chunk, c.Encode())
				setMessageSize(chunk)
				if _, status := readTestResponse(t, ch, peer, chunk); status == ua.Good {
					t.Errorf("size %d: readResponse succeeded", size)
				}
			}
		})

		if cfg.mode != ua.MessageSecurityModeNone {
			t.Run(name+"/InvalidSignature", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				chunk := c.Encode()
				chunk[len(chunk)-1] ^= 0x01
				if _, status := readTestResponse(t, ch, peer, chunk); status != ua.BadSecurityChecksFailed {
					t.Errorf("readResponse() = %v, want %v", status, ua.BadSecurityChecksFailed)
				}
			})
			t.Run(name+"/TokenIDZero", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				c.TokenID = 0
				if _, status := readTestResponse(t, ch, peer, c.Encode()); status == ua.Good {
					t.Error("readResponse succeeded")
				}
			})
		}

		if cfg.mode == ua.MessageSecurityModeSignAndEncrypt {
			t.Run(name+"/PartialBlock", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				chunk := c.Encode()
				if _, status := readTestResponse(t, ch, peer, setMessageSize(chunk[:len(chunk)-1])); status == ua.Good {
					t.Error("readResponse succeeded")
				}
			})
			t.Run(name+"/PaddingSizeTooLarge", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				c.MutateFooter = func(f []byte) { f[len(f)-1] = 0xFF }
				if _, status := readTestResponse(t, ch, peer, c.Encode()); status == ua.Good {
					t.Error("readResponse succeeded")
				}
			})
			t.Run(name+"/PaddingMismatch", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				c = withSymmetricPadding(c)
				c.MutateFooter = func(f []byte) { f[0] ^= 0x01 }
				if _, status := readTestResponse(t, ch, peer, c.Encode()); status == ua.Good {
					t.Error("readResponse succeeded")
				}
			})
			t.Run(name+"/EmptyCipherText", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				if _, status := readTestResponse(t, ch, peer, setMessageSize(c.Encode()[:16])); status == ua.Good {
					t.Error("readResponse succeeded")
				}
			})
		}
	}
}

// TestClientChunkReassembly checks that the chunks of a message belong to the same message.
func TestClientChunkReassembly(t *testing.T) {
	loadTestCredentials(t)
	p := testRSAPolicies[2]
	newChannel := func(t *testing.T) (*clientSecureChannel, net.Conn, securechanneltest.SymmetricChunk) {
		ch, peer, keys := newTestReceivingChannel(t, p, ua.MessageSecurityModeSignAndEncrypt, testClient, testServer)
		return ch, peer, securechanneltest.SymmetricChunk{
			ChannelID: 1, TokenID: 1, SequenceNumber: 2, RequestID: 5,
			Policy: p.policy, Mode: ua.MessageSecurityModeSignAndEncrypt, Keys: keys,
		}
	}
	split := func(c securechanneltest.SymmetricChunk, parts int, mutate func(i int, c *securechanneltest.SymmetricChunk)) [][]byte {
		body := testReadResponseBody()
		chunks := [][]byte{}
		for i := 0; i < parts; i++ {
			c.Body = body[i*len(body)/parts : (i+1)*len(body)/parts]
			c.MessageType = ua.MessageTypeChunk
			if i == parts-1 {
				c.MessageType = ua.MessageTypeFinal
			}
			if mutate != nil {
				mutate(i, &c)
			}
			chunks = append(chunks, c.Encode())
			c.SequenceNumber++
		}
		return chunks
	}

	t.Run("Valid", func(t *testing.T) {
		ch, peer, c := newChannel(t)
		res, status := readTestResponse(t, ch, peer, split(c, 3, nil)...)
		if _, ok := res.(*ua.ReadResponse); status != ua.Good || !ok {
			t.Fatalf("readResponse() = %T, %v", res, status)
		}
	})
	t.Run("RequestIDMismatch", func(t *testing.T) {
		ch, peer, c := newChannel(t)
		chunks := split(c, 3, func(i int, c *securechanneltest.SymmetricChunk) {
			if i == 2 {
				c.RequestID = 6
			}
		})
		if _, status := readTestResponse(t, ch, peer, chunks...); status == ua.Good {
			t.Fatal("readResponse succeeded")
		}
	})
	t.Run("OpenAfterChunk", func(t *testing.T) {
		ch, peer, c := newChannel(t)
		chunks := split(c, 2, nil)
		if _, status := readTestResponse(t, ch, peer, chunks[0], mustEncode(t, testOpenResponseChunk(p, testClient, testServer, 3))); status == ua.Good {
			t.Fatal("readResponse succeeded")
		}
	})
	t.Run("MaxChunkCount", func(t *testing.T) {
		ch, peer, c := newChannel(t)
		ch.maxResponseChunkCount = 2
		if _, status := readTestResponse(t, ch, peer, split(c, 3, nil)...); status != ua.BadResponseTooLarge {
			t.Fatalf("readResponse() = %v, want %v", status, ua.BadResponseTooLarge)
		}
	})
	t.Run("MaxMessageSize", func(t *testing.T) {
		ch, peer, c := newChannel(t)
		ch.maxResponseMessageSize = 16
		if _, status := readTestResponse(t, ch, peer, split(c, 3, nil)...); status != ua.BadResponseTooLarge {
			t.Fatalf("readResponse() = %v, want %v", status, ua.BadResponseTooLarge)
		}
	})
}

// TestClientAbortChunk checks that an abort chunk is verified like other chunks, and that a valid abort
// chunk fails the aborted request and keeps the channel open.
func TestClientAbortChunk(t *testing.T) {
	loadTestCredentials(t)
	configs := []struct {
		p    testPolicy
		mode ua.MessageSecurityMode
	}{
		{testPolicy{ua.SecurityPolicyURINone, new(ua.SecurityPolicyNone)}, ua.MessageSecurityModeNone},
		{testRSAPolicies[2], ua.MessageSecurityModeSign},
		{testRSAPolicies[2], ua.MessageSecurityModeSignAndEncrypt},
	}
	for _, cfg := range configs {
		newChannel := func(t *testing.T) (*clientSecureChannel, net.Conn, securechanneltest.SymmetricChunk) {
			ch, peer, keys := newTestReceivingChannel(t, cfg.p, cfg.mode, testClient, testServer)
			return ch, peer, securechanneltest.SymmetricChunk{
				ChannelID: 1, TokenID: 1, Policy: cfg.p.policy, Mode: cfg.mode, Keys: keys,
			}
		}
		chunk := func(c securechanneltest.SymmetricChunk, messageType, sequenceNumber, requestID uint32, body []byte) []byte {
			c.MessageType, c.SequenceNumber, c.RequestID, c.Body = messageType, sequenceNumber, requestID, body
			return c.Encode()
		}
		abort := securechanneltest.AbortBody(ua.BadResponseTooLarge, "too large")
		body := testReadResponseBody()

		t.Run(cfg.mode.String()+"/AbortedResponseFailsRequest", func(t *testing.T) {
			ch, peer, c := newChannel(t)
			res, status := readTestResponse(t, ch, peer,
				chunk(c, ua.MessageTypeChunk, 2, 9, body[:10]),
				chunk(c, ua.MessageTypeAbort, 3, 9, abort),
			)
			if f, ok := res.(*ua.ServiceFault); status != ua.Good || !ok || f.RequestHandle != 9 || f.ServiceResult != ua.BadResponseTooLarge {
				t.Fatalf("readResponse() = %#v, %v, want a fault for request 9", res, status)
			}
			// the channel remains open.
			res, status = readTestResponse(t, ch, peer, chunk(c, ua.MessageTypeFinal, 4, 7, body))
			if r, ok := res.(*ua.ReadResponse); status != ua.Good || !ok || r.RequestHandle != 7 {
				t.Fatalf("readResponse() = %T, %v, want the response after the abort", res, status)
			}
		})
		t.Run(cfg.mode.String()+"/AbortWithGoodStatus", func(t *testing.T) {
			ch, peer, c := newChannel(t)
			res, status := readTestResponse(t, ch, peer, chunk(c, ua.MessageTypeAbort, 2, 9, securechanneltest.AbortBody(ua.Good, "")))
			if f, ok := res.(*ua.ServiceFault); status != ua.Good || !ok || !f.ServiceResult.IsBad() {
				t.Fatalf("readResponse() = %#v, %v, want a fault with a bad status", res, status)
			}
		})
		t.Run(cfg.mode.String()+"/ReplayedAbort", func(t *testing.T) {
			ch, peer, c := newChannel(t)
			a := chunk(c, ua.MessageTypeAbort, 2, 9, abort)
			if _, status := readTestResponse(t, ch, peer, a); status != ua.Good {
				t.Fatalf("readResponse() = %v", status)
			}
			if _, status := readTestResponse(t, ch, peer, a); status != ua.BadSequenceNumberInvalid {
				t.Fatalf("readResponse() = %v, want %v", status, ua.BadSequenceNumberInvalid)
			}
		})
		t.Run(cfg.mode.String()+"/AbortOfOtherRequest", func(t *testing.T) {
			ch, peer, c := newChannel(t)
			if _, status := readTestResponse(t, ch, peer,
				chunk(c, ua.MessageTypeChunk, 2, 9, body[:10]),
				chunk(c, ua.MessageTypeAbort, 3, 10, abort),
			); status == ua.Good {
				t.Fatal("readResponse succeeded")
			}
		})
		t.Run(cfg.mode.String()+"/TruncatedAbort", func(t *testing.T) {
			ch, peer, c := newChannel(t)
			for _, b := range [][]byte{setMessageSize(chunk(c, ua.MessageTypeAbort, 2, 9, abort)[:16]), chunk(c, ua.MessageTypeAbort, 2, 9, abort[:2])} {
				if _, status := readTestResponse(t, ch, peer, b); status == ua.Good {
					t.Fatal("readResponse succeeded")
				}
				ch, peer, c = newChannel(t)
			}
		})
		if cfg.mode != ua.MessageSecurityModeNone {
			t.Run(cfg.mode.String()+"/ForgedAbort", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				a := chunk(c, ua.MessageTypeAbort, 2, 9, abort)
				a[len(a)-1] ^= 0x01
				if _, status := readTestResponse(t, ch, peer, a); status != ua.BadSecurityChecksFailed {
					t.Fatalf("readResponse() = %v, want %v", status, ua.BadSecurityChecksFailed)
				}
			})
		}
	}
}

// TestClientRejectsUnexpectedOpenSecureChannelResponse checks that the client returns an error, instead
// of panicking, when the server answers an OpenSecureChannel request with another type of response.
func TestClientRejectsUnexpectedOpenSecureChannelResponse(t *testing.T) {
	s := startFakeServer(t, func(string) []ua.EndpointDescription { return nil }, func(requestHandle uint32) []byte {
		return securechanneltest.EncodeBody(ua.ObjectIDGetEndpointsResponseEncodingDefaultBinary, &ua.GetEndpointsResponse{
			ResponseHeader: ua.ResponseHeader{Timestamp: time.Now(), RequestHandle: requestHandle},
		})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GetEndpoints panicked: %v", r)
		}
	}()
	if _, err := GetEndpoints(ctx, &ua.GetEndpointsRequest{EndpointURL: s.endpointURL}); err != ua.BadUnknownResponse {
		t.Fatalf("GetEndpoints() = %v, want %v", err, ua.BadUnknownResponse)
	}
}
