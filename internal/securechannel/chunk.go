package securechannel

import "github.com/awcullen/opcua/ua"

// SequenceHeaderSize is the size of the sequence header of a message chunk.
const SequenceHeaderSize = 8

// PaddingHeaderSize returns the size of the padding header of an encrypted chunk: 1 byte, or
// 2 bytes if the encryption key (or block) is larger than 2048 bits.
func PaddingHeaderSize(cipherTextBlockSize int) int {
	if cipherTextBlockSize > 256 {
		return 2
	}
	return 1
}

// SignatureStart checks that a decrypted chunk of chunkSize bytes is large enough to hold the
// sequence header, the padding header and the signature, and returns the offset of the signature.
// bodyStart is the offset of the first byte following the sequence header. paddingHeaderSize is
// 0 if the chunk is not encrypted, and signatureSize is 0 if the chunk is not signed.
// The check depends only on sizes, so it is made before the chunk is decrypted or verified.
func SignatureStart(chunkSize, bodyStart, paddingHeaderSize, signatureSize int) (int, error) {
	if bodyStart < SequenceHeaderSize || paddingHeaderSize < 0 || paddingHeaderSize > 2 || signatureSize < 0 ||
		chunkSize-signatureSize-paddingHeaderSize < bodyStart {
		return 0, ua.BadDecodingError
	}
	return chunkSize - signatureSize, nil
}

// BodyEnd checks the padding of a decrypted and verified chunk and returns the end offset of
// the body. data is the chunk without its signature, i.e. chunk[:SignatureStart(...)].
// bodyStart is the offset of the first byte following the sequence header. paddingHeaderSize is
// 0 if the chunk is not encrypted, otherwise PaddingHeaderSize of the encryption key or block.
//
// The padding must only be parsed after the signature has been verified, so that a malformed
// padding reveals nothing about the plaintext of a forged or tampered chunk.
func BodyEnd(data []byte, bodyStart, paddingHeaderSize int) (int, error) {
	end := len(data)
	if bodyStart < 0 || paddingHeaderSize < 0 || paddingHeaderSize > 2 || end-paddingHeaderSize < bodyStart {
		return 0, ua.BadDecodingError
	}
	if paddingHeaderSize == 0 {
		return end, nil
	}
	// The footer is PaddingSize (1 byte), Padding (PaddingSize bytes) and, for keys larger than
	// 2048 bits, ExtraPaddingSize (1 byte) holding the most significant byte of the padding size.
	// The PaddingSize byte and every padding byte hold the least significant byte of the padding size.
	paddingSize := int(data[end-paddingHeaderSize])
	if paddingHeaderSize == 2 {
		paddingSize |= int(data[end-1]) << 8
	}
	bodyEnd := end - paddingHeaderSize - paddingSize
	if bodyEnd < bodyStart {
		return 0, ua.BadDecodingError
	}
	var invalid byte
	for _, b := range data[bodyEnd : bodyEnd+1+paddingSize] {
		invalid |= b ^ byte(paddingSize)
	}
	if invalid != 0 {
		return 0, ua.BadDecodingError
	}
	return bodyEnd, nil
}
