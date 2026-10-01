package server

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/awcullen/opcua/internal/securechannel/securechanneltest"
	"github.com/awcullen/opcua/ua"
)

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

// TestServerAsymmetricChunkValidation checks the bounds checks of the OpenSecureChannel receive path (issue #5).
func TestServerAsymmetricChunkValidation(t *testing.T) {
	loadTestCredentials(t)
	type keyPair struct {
		name           string
		client, server testCredential
	}
	keyPairs := []keyPair{
		{"2048", testClient, testServer},
		{"3072", testClient, testServerLarge},
	}
	for _, p := range testRSAPolicies {
		for _, kp := range keyPairs {
			name := p.uri[len("http://opcfoundation.org/UA/SecurityPolicy#"):] + "/" + kp.name
			valid := func() securechanneltest.AsymmetricChunk { return testOpenChunk(p, kp.client, kp.server, 1) }

			t.Run(name+"/Valid", func(t *testing.T) {
				ch, peer := newTestServerChannel(t, kp.server)
				req, id, err := readTestRequest(t, ch, peer, mustEncode(t, valid()))
				if err != nil {
					t.Fatalf("readRequest() = %v", err)
				}
				if _, ok := req.(*ua.OpenSecureChannelRequest); !ok || id != 1 {
					t.Fatalf("readRequest() = %T, %d", req, id)
				}
			})

			invalid := map[string]func(t *testing.T) []byte{
				"PartialBlock": func(t *testing.T) []byte {
					b := mustEncode(t, valid())
					return setMessageSize(b[:len(b)-1])
				},
				"MissingBlock": func(t *testing.T) []byte {
					b := mustEncode(t, valid())
					return setMessageSize(b[:len(b)-kp.server.key.Size()])
				},
				"HeaderOnly": func(t *testing.T) []byte {
					b := mustEncode(t, valid())
					return setMessageSize(b[:asymmetricHeaderSize(valid())])
				},
				"SingleBlock": func(t *testing.T) []byte {
					// a valid encrypted block that is too short to hold the signature.
					b := mustEncode(t, valid())
					header := b[:asymmetricHeaderSize(valid())]
					plainText := make([]byte, kp.server.key.Size()-p.policy.RSAPaddingSize())
					chunk, err := securechanneltest.EncryptAsymmetric(p.policy, &kp.server.key.PublicKey, header, plainText)
					if err != nil {
						t.Fatal(err)
					}
					return setMessageSize(chunk)
				},
				"InvalidSignature": func(t *testing.T) []byte {
					c := valid()
					c.SenderKey = testOtherClient.key
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
					ch, peer := newTestServerChannel(t, kp.server)
					req, _, err := readTestRequest(t, ch, peer, chunk(t))
					if err == nil {
						t.Fatalf("readRequest() = %T, want an error", req)
					}
				})
			}
		}
	}

	t.Run("None/Truncated", func(t *testing.T) {
		valid, err := securechanneltest.AsymmetricChunk{PolicyURI: ua.SecurityPolicyURINone, SequenceNumber: 1, RequestID: 1,
			Body: testOpenSecureChannelRequestBody(ua.SecurityTokenRequestTypeIssue, ua.MessageSecurityModeNone, 0)}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		headerSize := 12 + 4 + len(ua.SecurityPolicyURINone) + 4 + 4
		for size := 8; size < headerSize+8; size++ {
			ch, peer := newTestServerChannel(t, testServer)
			chunk := setMessageSize(append([]byte{}, valid[:size]...))
			if _, _, err := readTestRequest(t, ch, peer, chunk); err == nil {
				t.Errorf("size %d: readRequest succeeded", size)
			}
		}
	})
	t.Run("UnknownPolicy", func(t *testing.T) {
		ch, peer := newTestServerChannel(t, testServer)
		c := securechanneltest.AsymmetricChunk{PolicyURI: "http://opcfoundation.org/UA/SecurityPolicy#Unknown", SequenceNumber: 1, RequestID: 1,
			Body: testOpenSecureChannelRequestBody(ua.SecurityTokenRequestTypeIssue, ua.MessageSecurityModeNone, 0)}
		if _, _, err := readTestRequest(t, ch, peer, mustEncode(t, c)); err != ua.BadSecurityPolicyRejected {
			t.Errorf("readRequest() = %v, want %v", err, ua.BadSecurityPolicyRejected)
		}
	})
}

// TestServerSymmetricChunkValidation checks the bounds checks of the MSG/CLO receive path (issue #5).
func TestServerSymmetricChunkValidation(t *testing.T) {
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
		newChannel := func(t *testing.T) (*serverSecureChannel, net.Conn, securechanneltest.SymmetricChunk) {
			ch, peer := newTestServerChannel(t, testServer)
			keys := establishTestChannel(ch, cfg.p, cfg.mode)
			return ch, peer, securechanneltest.SymmetricChunk{
				MessageType: ua.MessageTypeFinal, ChannelID: ch.channelID, TokenID: 1, SequenceNumber: 2, RequestID: 5,
				Body: testReadRequestBody(), Policy: cfg.p.policy, Mode: cfg.mode, Keys: keys,
			}
		}

		t.Run(name+"/Valid", func(t *testing.T) {
			ch, peer, c := newChannel(t)
			req, id, err := readTestRequest(t, ch, peer, c.Encode())
			if err != nil {
				t.Fatalf("readRequest() = %v", err)
			}
			if r, ok := req.(*ua.ReadRequest); !ok || id != 5 || r.RequestHandle != 7 {
				t.Fatalf("readRequest() = %T, %d", req, id)
			}
		})

		t.Run(name+"/Truncated", func(t *testing.T) {
			// every chunk shorter than the headers, padding header and signature.
			for size := 8; size < 16+8+paddingHeaderSize+signatureSize; size++ {
				ch, peer, c := newChannel(t)
				chunk := make([]byte, size)
				copy(chunk, c.Encode())
				setMessageSize(chunk)
				if _, _, err := readTestRequest(t, ch, peer, chunk); err == nil {
					t.Errorf("size %d: readRequest succeeded", size)
				}
			}
		})

		if cfg.mode != ua.MessageSecurityModeNone {
			t.Run(name+"/InvalidSignature", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				chunk := c.Encode()
				chunk[len(chunk)-1] ^= 0x01
				if _, _, err := readTestRequest(t, ch, peer, chunk); err != ua.BadSecurityChecksFailed {
					t.Errorf("readRequest() = %v, want %v", err, ua.BadSecurityChecksFailed)
				}
			})
			t.Run(name+"/TokenIDZero", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				c.TokenID = 0
				if _, _, err := readTestRequest(t, ch, peer, c.Encode()); err == nil {
					t.Error("readRequest succeeded")
				}
			})
		}

		if cfg.mode == ua.MessageSecurityModeSignAndEncrypt {
			t.Run(name+"/PartialBlock", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				chunk := c.Encode()
				if _, _, err := readTestRequest(t, ch, peer, setMessageSize(chunk[:len(chunk)-1])); err == nil {
					t.Error("readRequest succeeded")
				}
			})
			t.Run(name+"/PaddingSizeTooLarge", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				c.MutateFooter = func(f []byte) { f[len(f)-1] = 0xFF }
				if _, _, err := readTestRequest(t, ch, peer, c.Encode()); err == nil {
					t.Error("readRequest succeeded")
				}
			})
			t.Run(name+"/PaddingMismatch", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				c = withSymmetricPadding(c)
				c.MutateFooter = func(f []byte) { f[0] ^= 0x01 }
				if _, _, err := readTestRequest(t, ch, peer, c.Encode()); err == nil {
					t.Error("readRequest succeeded")
				}
			})
			t.Run(name+"/EmptyCipherText", func(t *testing.T) {
				ch, peer, c := newChannel(t)
				if _, _, err := readTestRequest(t, ch, peer, setMessageSize(c.Encode()[:16])); err == nil {
					t.Error("readRequest succeeded")
				}
			})
		}
	}
}

// TestServerChunkReassembly checks that the chunks of a message belong to the same message.
func TestServerChunkReassembly(t *testing.T) {
	loadTestCredentials(t)
	p := testRSAPolicies[2]
	newChannel := func(t *testing.T) (*serverSecureChannel, net.Conn, securechanneltest.SymmetricChunk) {
		ch, peer := newTestServerChannel(t, testServer)
		keys := establishTestChannel(ch, p, ua.MessageSecurityModeSignAndEncrypt)
		return ch, peer, securechanneltest.SymmetricChunk{
			MessageType: ua.MessageTypeChunk, ChannelID: ch.channelID, TokenID: 1, SequenceNumber: 2, RequestID: 5,
			Policy: p.policy, Mode: ua.MessageSecurityModeSignAndEncrypt, Keys: keys,
		}
	}
	split := func(c securechanneltest.SymmetricChunk, parts int, mutate func(i int, c *securechanneltest.SymmetricChunk)) [][]byte {
		body := testReadRequestBody()
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
		req, id, err := readTestRequest(t, ch, peer, split(c, 3, nil)...)
		if _, ok := req.(*ua.ReadRequest); err != nil || !ok || id != 5 {
			t.Fatalf("readRequest() = %T, %d, %v", req, id, err)
		}
	})
	t.Run("RequestIDMismatch", func(t *testing.T) {
		ch, peer, c := newChannel(t)
		chunks := split(c, 3, func(i int, c *securechanneltest.SymmetricChunk) {
			if i == 2 {
				c.RequestID = 6
			}
		})
		if _, _, err := readTestRequest(t, ch, peer, chunks...); err == nil {
			t.Fatal("readRequest succeeded")
		}
	})
	t.Run("CloseAfterChunk", func(t *testing.T) {
		ch, peer, c := newChannel(t)
		chunks := split(c, 2, func(i int, c *securechanneltest.SymmetricChunk) {
			if i == 1 {
				c.MessageType = ua.MessageTypeCloseFinal
			}
		})
		if _, _, err := readTestRequest(t, ch, peer, chunks...); err == nil {
			t.Fatal("readRequest succeeded")
		}
	})
	t.Run("OpenAfterChunk", func(t *testing.T) {
		ch, peer, c := newChannel(t)
		chunks := split(c, 2, nil)
		opn := testOpenChunk(p, testClient, testServer, c.SequenceNumber+1)
		opn.ChannelID = ch.channelID
		if _, _, err := readTestRequest(t, ch, peer, chunks[0], mustEncode(t, opn)); err == nil {
			t.Fatal("readRequest succeeded")
		}
	})
	t.Run("MaxChunkCount", func(t *testing.T) {
		ch, peer, c := newChannel(t)
		ch.maxRequestChunkCount = 2
		if _, _, err := readTestRequest(t, ch, peer, split(c, 3, nil)...); err != ua.BadRequestTooLarge {
			t.Fatalf("readRequest() = %v, want %v", err, ua.BadRequestTooLarge)
		}
	})
	t.Run("MaxMessageSize", func(t *testing.T) {
		ch, peer, c := newChannel(t)
		ch.maxRequestMessageSize = 16
		if _, _, err := readTestRequest(t, ch, peer, split(c, 3, nil)...); err != ua.BadRequestTooLarge {
			t.Fatalf("readRequest() = %v, want %v", err, ua.BadRequestTooLarge)
		}
	})
}
