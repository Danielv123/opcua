// Package securechanneltest builds and reads UA Secure Conversation message chunks for tests,
// including deliberately malformed chunks.
package securechanneltest

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/awcullen/opcua/ua"
)

// SymmetricKeys holds the keys that sign and encrypt symmetric chunks.
type SymmetricKeys struct {
	SigningKey           []byte
	EncryptingKey        []byte
	InitializationVector []byte
}

// SymmetricChunk describes a symmetric (MSG or CLO) message chunk.
type SymmetricChunk struct {
	MessageType    uint32
	ChannelID      uint32
	TokenID        uint32
	SequenceNumber uint32
	RequestID      uint32
	Body           []byte
	Policy         ua.SecurityPolicy
	Mode           ua.MessageSecurityMode
	Keys           SymmetricKeys
	// MutateFooter, if not nil, is called with the padding footer of an encrypted chunk before
	// the chunk is signed, e.g. to corrupt the padding of an otherwise valid chunk.
	MutateFooter func(footer []byte)
}

// Encode returns the signed and encrypted chunk.
func (c SymmetricChunk) Encode() []byte {
	signed := c.Mode == ua.MessageSecurityModeSign || c.Mode == ua.MessageSecurityModeSignAndEncrypt
	encrypted := c.Mode == ua.MessageSecurityModeSignAndEncrypt
	signatureSize := 0
	if signed {
		signatureSize = c.Policy.SymSignatureSize()
	}
	plainText := append(SequenceHeader(c.SequenceNumber, c.RequestID), c.Body...)
	if encrypted {
		blockSize := c.Policy.SymEncryptionBlockSize()
		paddingHeaderSize := paddingHeaderSizeOf(blockSize)
		paddingSize := (blockSize - ((len(plainText) + paddingHeaderSize + signatureSize) % blockSize)) % blockSize
		footer := PaddingFooter(paddingSize, paddingHeaderSize)
		if c.MutateFooter != nil {
			c.MutateFooter(footer)
		}
		plainText = append(plainText, footer...)
	}
	chunk := make([]byte, 16, 16+len(plainText)+signatureSize)
	binary.LittleEndian.PutUint32(chunk[0:], c.MessageType)
	binary.LittleEndian.PutUint32(chunk[4:], uint32(16+len(plainText)+signatureSize))
	binary.LittleEndian.PutUint32(chunk[8:], c.ChannelID)
	binary.LittleEndian.PutUint32(chunk[12:], c.TokenID)
	chunk = append(chunk, plainText...)
	if signed {
		mac := c.Policy.SymHMACFactory(c.Keys.SigningKey)
		mac.Write(chunk)
		chunk = mac.Sum(chunk)
	}
	if encrypted {
		block, err := aes.NewCipher(c.Keys.EncryptingKey)
		if err != nil {
			panic(err)
		}
		cipher.NewCBCEncrypter(block, c.Keys.InitializationVector).CryptBlocks(chunk[16:], chunk[16:])
	}
	return chunk
}

// AsymmetricChunk describes an asymmetric (OPN) message chunk.
type AsymmetricChunk struct {
	ChannelID          uint32
	PolicyURI          string
	Policy             ua.SecurityPolicy
	SenderCertificate  []byte
	ReceiverThumbprint []byte
	SequenceNumber     uint32
	RequestID          uint32
	Body               []byte
	// SenderKey signs and ReceiverKey encrypts the chunk. Both are nil for SecurityPolicy None.
	SenderKey   *rsa.PrivateKey
	ReceiverKey *rsa.PublicKey
	// MutateFooter, if not nil, is called with the padding footer before the chunk is signed.
	MutateFooter func(footer []byte)
}

// Encode returns the signed and encrypted chunk.
func (c AsymmetricChunk) Encode() ([]byte, error) {
	header := new(bytes.Buffer)
	enc := ua.NewBinaryEncoder(header, ua.NewEncodingContext())
	enc.WriteUInt32(ua.MessageTypeOpenFinal)
	enc.WriteUInt32(0) // message size, set below
	enc.WriteUInt32(c.ChannelID)
	enc.WriteString(c.PolicyURI)
	enc.WriteByteArray(c.SenderCertificate)
	enc.WriteByteArray(c.ReceiverThumbprint)
	plainHeader := header.Bytes()
	plainText := append(SequenceHeader(c.SequenceNumber, c.RequestID), c.Body...)

	if c.SenderKey == nil || c.ReceiverKey == nil {
		chunk := append(plainHeader, plainText...)
		binary.LittleEndian.PutUint32(chunk[4:], uint32(len(chunk)))
		return chunk, nil
	}

	cipherTextBlockSize := c.ReceiverKey.Size()
	plainTextBlockSize := cipherTextBlockSize - c.Policy.RSAPaddingSize()
	signatureSize := c.SenderKey.Size()
	paddingHeaderSize := paddingHeaderSizeOf(cipherTextBlockSize)
	paddingSize := (plainTextBlockSize - ((len(plainText) + paddingHeaderSize + signatureSize) % plainTextBlockSize)) % plainTextBlockSize
	footer := PaddingFooter(paddingSize, paddingHeaderSize)
	if c.MutateFooter != nil {
		c.MutateFooter(footer)
	}
	plainText = append(plainText, footer...)
	blocks := (len(plainText) + signatureSize) / plainTextBlockSize
	if (len(plainText)+signatureSize)%plainTextBlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of the plaintext block size")
	}
	binary.LittleEndian.PutUint32(plainHeader[4:], uint32(len(plainHeader)+blocks*cipherTextBlockSize))
	signature, err := c.Policy.RSASign(c.SenderKey, append(append([]byte{}, plainHeader...), plainText...))
	if err != nil {
		return nil, err
	}
	plainText = append(plainText, signature...)
	return EncryptAsymmetric(c.Policy, c.ReceiverKey, plainHeader, plainText)
}

// EncryptAsymmetric encrypts plainText block by block and appends the cipher text to plainHeader.
// The message size in the header is not updated.
func EncryptAsymmetric(policy ua.SecurityPolicy, key *rsa.PublicKey, plainHeader, plainText []byte) ([]byte, error) {
	plainTextBlockSize := key.Size() - policy.RSAPaddingSize()
	chunk := append([]byte{}, plainHeader...)
	for i := 0; i < len(plainText); i += plainTextBlockSize {
		j := i + plainTextBlockSize
		if j > len(plainText) {
			j = len(plainText)
		}
		cipherText, err := policy.RSAEncrypt(key, plainText[i:j])
		if err != nil {
			return nil, err
		}
		chunk = append(chunk, cipherText...)
	}
	return chunk, nil
}

// paddingHeaderSizeOf returns the size of the padding header for the given encryption key or block size.
func paddingHeaderSizeOf(cipherTextBlockSize int) int {
	if cipherTextBlockSize > 256 {
		return 2
	}
	return 1
}

// SequenceHeader returns an encoded sequence header.
func SequenceHeader(sequenceNumber, requestID uint32) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[0:], sequenceNumber)
	binary.LittleEndian.PutUint32(b[4:], requestID)
	return b
}

// PaddingFooter returns the PaddingSize, Padding and (if paddingHeaderSize is 2) ExtraPaddingSize fields.
func PaddingFooter(paddingSize, paddingHeaderSize int) []byte {
	footer := bytes.Repeat([]byte{byte(paddingSize)}, 1+paddingSize)
	if paddingHeaderSize == 2 {
		footer = append(footer, byte(paddingSize>>8))
	}
	return footer
}

// Frame returns a chunk with the given message type and payload, with a consistent message size.
func Frame(messageType uint32, payload []byte) []byte {
	chunk := make([]byte, 8, 8+len(payload))
	binary.LittleEndian.PutUint32(chunk[0:], messageType)
	binary.LittleEndian.PutUint32(chunk[4:], uint32(8+len(payload)))
	return append(chunk, payload...)
}

// EncodeBody encodes a service request or response, prefixed by its binary encoding id.
func EncodeBody(id ua.NodeID, v any) []byte {
	buf := new(bytes.Buffer)
	enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
	if err := enc.WriteNodeID(id); err != nil {
		panic(err)
	}
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// ReadChunk reads one chunk from r.
func ReadChunk(r io.Reader) ([]byte, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(header[4:])
	if size < 8 || size > 16*1024*1024 {
		return nil, errors.New("invalid chunk size")
	}
	chunk := make([]byte, size)
	copy(chunk, header)
	if _, err := io.ReadFull(r, chunk[8:]); err != nil {
		return nil, err
	}
	return chunk, nil
}

// Hello returns a HEL message.
func Hello(endpointURL string) []byte {
	buf := new(bytes.Buffer)
	enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
	enc.WriteUInt32(0)         // protocol version
	enc.WriteUInt32(64 * 1024) // receive buffer size
	enc.WriteUInt32(64 * 1024) // send buffer size
	enc.WriteUInt32(0)         // max message size
	enc.WriteUInt32(0)         // max chunk count
	enc.WriteString(endpointURL)
	return Frame(ua.MessageTypeHello, buf.Bytes())
}

// Acknowledge returns an ACK message.
func Acknowledge() []byte {
	buf := new(bytes.Buffer)
	enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
	enc.WriteUInt32(0)         // protocol version
	enc.WriteUInt32(64 * 1024) // receive buffer size
	enc.WriteUInt32(64 * 1024) // send buffer size
	enc.WriteUInt32(0)         // max message size
	enc.WriteUInt32(0)         // max chunk count
	return Frame(ua.MessageTypeAck, buf.Bytes())
}

// NewCertificate returns a DER encoded, self-signed certificate for the public key of signer,
// usable as an OPC UA application instance certificate.
func NewCertificate(applicationURI string, signer any, publicKey any) ([]byte, error) {
	uri, err := url.Parse(applicationURI)
	if err != nil {
		return nil, err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		URIs:                  []*url.URL{uri},
	}
	return x509.CreateCertificate(rand.Reader, &template, &template, publicKey, signer)
}
