package securechannel

import (
	"crypto/rand"
	"crypto/rsa"
	"io"

	"github.com/awcullen/opcua/ua"
)

// DecryptBlock decrypts one cipher text block of an asymmetric chunk into plainText, which has the
// size of a plain text block. It returns false if the block does not decrypt to a whole plain text
// block. Callers must decrypt every block and verify the signature of the chunk regardless of the
// result, and report decryption and verification failures alike.
//
// For PKCS #1 v1.5 encryption (Basic128Rsa15) the padding is checked in constant time and an invalid
// block decrypts to random bytes (implicit rejection), so that neither the result nor the timing
// reveals whether the padding of a chosen cipher text is valid; the signature verification fails.
func DecryptBlock(policy ua.SecurityPolicy, key *rsa.PrivateKey, cipherText, plainText []byte) bool {
	if _, ok := policy.(*ua.SecurityPolicyBasic128Rsa15); ok {
		if _, err := io.ReadFull(rand.Reader, plainText); err != nil {
			return false
		}
		// returns an error only for cipher text and key sizes, which are not secret.
		return rsa.DecryptPKCS1v15SessionKey(rand.Reader, key, cipherText, plainText) == nil
	}
	decrypted, err := policy.RSADecrypt(key, cipherText)
	copy(plainText, decrypted)
	return err == nil && len(decrypted) == len(plainText)
}
