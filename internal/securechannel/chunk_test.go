package securechannel_test

import (
	"bytes"
	"testing"

	"github.com/awcullen/opcua/internal/securechannel"
	"github.com/awcullen/opcua/internal/securechannel/securechanneltest"
)

func TestPaddingHeaderSize(t *testing.T) {
	for size, want := range map[int]int{16: 1, 128: 1, 256: 1, 257: 2, 384: 2, 512: 2} {
		if got := securechannel.PaddingHeaderSize(size); got != want {
			t.Errorf("PaddingHeaderSize(%d) = %d, want %d", size, got, want)
		}
	}
}

func TestSignatureStart(t *testing.T) {
	cases := []struct {
		chunkSize, bodyStart, paddingHeaderSize, signatureSize int
		want                                                   int
		ok                                                     bool
	}{
		{chunkSize: 24, bodyStart: 24, want: 24, ok: true},                                              // None, empty body
		{chunkSize: 23, bodyStart: 24},                                                                  // None, truncated sequence header
		{chunkSize: 0, bodyStart: 24},                                                                   // empty chunk
		{chunkSize: 56, bodyStart: 24, signatureSize: 32, want: 24, ok: true},                           // Sign, empty body
		{chunkSize: 55, bodyStart: 24, signatureSize: 32},                                               // Sign, truncated signature
		{chunkSize: 16, bodyStart: 24, signatureSize: 32},                                               // Sign, header only
		{chunkSize: 57, bodyStart: 24, paddingHeaderSize: 1, signatureSize: 32, want: 25, ok: true},     // SignAndEncrypt
		{chunkSize: 56, bodyStart: 24, paddingHeaderSize: 1, signatureSize: 32},                         // SignAndEncrypt, no padding header
		{chunkSize: 600, bodyStart: 100, paddingHeaderSize: 2, signatureSize: 512, want: 88, ok: false}, // 4096 bit key, truncated
		{chunkSize: 614, bodyStart: 100, paddingHeaderSize: 2, signatureSize: 512, want: 102, ok: true},
		{chunkSize: 100, bodyStart: 4},                        // body start before the end of the sequence header
		{chunkSize: 100, bodyStart: 24, paddingHeaderSize: 3}, // invalid padding header size
		{chunkSize: 100, bodyStart: 24, signatureSize: -1},    // invalid signature size
	}
	for _, c := range cases {
		got, err := securechannel.SignatureStart(c.chunkSize, c.bodyStart, c.paddingHeaderSize, c.signatureSize)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("SignatureStart(%d, %d, %d, %d) = (%d, %v), want %d", c.chunkSize, c.bodyStart, c.paddingHeaderSize, c.signatureSize, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("SignatureStart(%d, %d, %d, %d) = %d, want an error", c.chunkSize, c.bodyStart, c.paddingHeaderSize, c.signatureSize, got)
		}
	}
}

func TestBodyEnd(t *testing.T) {
	const bodyStart = 24
	body := bytes.Repeat([]byte{0xAB}, 10)
	data := func(footer ...byte) []byte {
		b := append(make([]byte, bodyStart), body...)
		return append(b, footer...)
	}

	valid := []struct {
		name              string
		data              []byte
		paddingHeaderSize int
		want              int
	}{
		{"None", data(), 0, bodyStart + len(body)},
		{"NoPadding", data(securechanneltest.PaddingFooter(0, 1)...), 1, bodyStart + len(body)},
		{"Padding", data(securechanneltest.PaddingFooter(5, 1)...), 1, bodyStart + len(body)},
		{"MaxPadding", data(securechanneltest.PaddingFooter(255, 1)...), 1, bodyStart + len(body)},
		{"ExtraPaddingNone", data(securechanneltest.PaddingFooter(0, 2)...), 2, bodyStart + len(body)},
		{"ExtraPadding", data(securechanneltest.PaddingFooter(300, 2)...), 2, bodyStart + len(body)},
		{"EmptyBody", append(make([]byte, bodyStart), securechanneltest.PaddingFooter(3, 1)...), 1, bodyStart},
	}
	for _, c := range valid {
		got, err := securechannel.BodyEnd(c.data, bodyStart, c.paddingHeaderSize)
		if err != nil || got != c.want {
			t.Errorf("%s: got (%d, %v), want %d", c.name, got, err, c.want)
		}
	}

	invalidPadding := securechanneltest.PaddingFooter(5, 1)
	invalidPadding[2] ^= 0xFF
	invalidPaddingSizeByte := securechanneltest.PaddingFooter(5, 1)
	invalidPaddingSizeByte[0] = 4
	invalidExtraPadding := securechanneltest.PaddingFooter(300, 2)
	invalidExtraPadding[100] = 0
	invalid := []struct {
		name              string
		data              []byte
		paddingHeaderSize int
	}{
		{"PaddingSizeExceedsChunk", data(0xFF), 1},
		{"PaddingSizeExceedsBody", data(bytes.Repeat([]byte{30}, 12)...), 1}, // the padding would start inside the sequence header
		{"PaddingOverlapsBody", data(bytes.Repeat([]byte{20}, 12)...), 1},    // the padding would start inside the body
		{"PaddingByteMismatch", data(invalidPadding...), 1},
		{"PaddingSizeByteMismatch", data(invalidPaddingSizeByte...), 1},
		{"ExtraPaddingByteMismatch", data(invalidExtraPadding...), 2},
		{"ExtraPaddingSizeExceedsChunk", data(0, 0xFF), 2},
		{"MissingPaddingHeader", make([]byte, bodyStart), 1},
		{"MissingExtraPaddingHeader", make([]byte, bodyStart+1), 2},
		{"TruncatedSequenceHeader", make([]byte, bodyStart-1), 0},
		{"InvalidPaddingHeaderSize", data(0, 0, 0), 3},
	}
	for _, c := range invalid {
		if got, err := securechannel.BodyEnd(c.data, bodyStart, c.paddingHeaderSize); err == nil {
			t.Errorf("%s: got %d, want an error", c.name, got)
		}
	}
}
