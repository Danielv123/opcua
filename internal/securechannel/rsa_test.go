package securechannel_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/awcullen/opcua/internal/securechannel"
	"github.com/awcullen/opcua/ua"
)

func TestDecryptBlock(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	policies := []ua.SecurityPolicy{
		new(ua.SecurityPolicyBasic128Rsa15),
		new(ua.SecurityPolicyBasic256),
		new(ua.SecurityPolicyBasic256Sha256),
		new(ua.SecurityPolicyAes128Sha256RsaOaep),
		new(ua.SecurityPolicyAes256Sha256RsaPss),
	}
	for _, policy := range policies {
		name := policy.PolicyURI()
		plainTextBlockSize := key.Size() - policy.RSAPaddingSize()
		want := make([]byte, plainTextBlockSize)
		rand.Read(want)
		cipherText, err := policy.RSAEncrypt(&key.PublicKey, want)
		if err != nil {
			t.Fatal(err)
		}

		// a valid block decrypts to its plain text.
		got := make([]byte, plainTextBlockSize)
		if !securechannel.DecryptBlock(policy, key, cipherText, got) || !bytes.Equal(got, want) {
			t.Errorf("%s: valid block was not decrypted", name)
		}

		// a corrupted block, or a block that decrypts to a shorter plain text, is rejected. For PKCS #1 v1.5
		// it decrypts to random bytes instead (implicit rejection), which fails the signature verification.
		_, pkcs1v15 := policy.(*ua.SecurityPolicyBasic128Rsa15)
		corrupted := append([]byte{}, cipherText...)
		corrupted[10] ^= 0x01
		short, err := policy.RSAEncrypt(&key.PublicKey, want[:plainTextBlockSize-1])
		if err != nil {
			t.Fatal(err)
		}
		for _, invalid := range [][]byte{corrupted, short} {
			got := make([]byte, plainTextBlockSize)
			ok := securechannel.DecryptBlock(policy, key, invalid, got)
			if pkcs1v15 && (!ok || bytes.Equal(got[:plainTextBlockSize-1], want[:plainTextBlockSize-1])) {
				t.Errorf("%s: invalid block was not replaced by random bytes", name)
			}
			if !pkcs1v15 && ok {
				t.Errorf("%s: invalid block was decrypted", name)
			}
		}
	}
}
