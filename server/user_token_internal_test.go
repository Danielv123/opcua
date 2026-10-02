// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/awcullen/opcua/ua"
)

// TestDecryptUserTokenSecret tests the decryption of user token secrets in the legacy encrypted token secret
// format: length || secret || nonce, encrypted in one block.
func TestDecryptUserTokenSecret(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k := key.Size()
	nonce := bytes.Repeat([]byte{7}, 32)
	otherNonce := bytes.Repeat([]byte{8}, 32)
	secret := []byte("secret")
	maxSecret := bytes.Repeat([]byte{'s'}, 64)
	tooLong := bytes.Repeat([]byte{'s'}, 65)

	plain := func(declaredLength int, secret, nonce []byte, padding ...byte) []byte {
		b := binary.LittleEndian.AppendUint32(nil, uint32(declaredLength))
		b = append(b, secret...)
		b = append(b, nonce...)
		return append(b, padding...)
	}
	// a block that decrypts to 0x00 ... 0x02, which has invalid padding for every algorithm.
	invalidPadding := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(key.E)), key.N).FillBytes(make([]byte, k))

	for _, algorithm := range []string{ua.RsaOaepKeyWrap, ua.RsaOaepSha256KeyWrap} {
		encrypt := func(b []byte) []byte {
			var c []byte
			var err error
			if algorithm == ua.RsaOaepKeyWrap {
				c, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, b, nil)
			} else {
				c, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, b, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			return c
		}
		valid := encrypt(plain(len(secret)+len(nonce), secret, nonce))

		cases := []struct {
			name       string
			cipherText []byte
			want       []byte
		}{
			{"valid", valid, secret},
			{"zero padding", encrypt(plain(len(secret)+len(nonce), secret, nonce, 0, 0, 0)), secret},
			{"nonzero padding", encrypt(plain(len(secret)+len(nonce), secret, nonce, 0, 1, 0)), nil},
			{"empty secret", encrypt(plain(len(nonce), nil, nonce)), []byte{}},
			{"64 byte secret", encrypt(plain(len(maxSecret)+len(nonce), maxSecret, nonce)), maxSecret},
			{"65 byte secret", encrypt(plain(len(tooLong)+len(nonce), tooLong, nonce)), nil},
			{"other nonce", encrypt(plain(len(secret)+len(otherNonce), secret, otherNonce)), nil},
			{"no nonce", encrypt(plain(len(secret), secret, nil)), nil},
			{"length shorter than nonce", encrypt(plain(4, secret, nonce)), nil},
			{"length too long", encrypt(plain(len(secret)+len(nonce)+1, secret, nonce)), nil},
			{"length overflow", encrypt(plain(-1, secret, nonce)), nil},
			{"short plain text", encrypt([]byte{1}), nil},
			{"two blocks", append(append([]byte{}, valid...), valid...), nil},
			{"invalid padding", invalidPadding, nil},
			{"partial block", valid[:len(valid)-1], nil},
			{"empty", nil, nil},
		}
		for _, c := range cases {
			got, ok := decryptUserTokenSecret(key, algorithm, c.cipherText, nonce)
			if ok != (c.want != nil) || !bytes.Equal(got, c.want) {
				t.Errorf("%s, %s: got %q, %t, want %q", algorithm, c.name, got, ok, c.want)
			}
		}
		if _, ok := decryptUserTokenSecret(key, algorithm, valid, nil); ok {
			t.Errorf("%s: decrypted without nonce", algorithm)
		}
	}

	// PKCS #1 v1.5 is not supported.
	v15, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, plain(len(secret)+len(nonce), secret, nonce))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decryptUserTokenSecret(key, ua.RsaV15KeyWrap, v15, nonce); ok {
		t.Errorf("decrypted with PKCS #1 v1.5")
	}
	if _, ok := decryptUserTokenSecret(key, "unknown", make([]byte, k), nonce); ok {
		t.Errorf("decrypted with unknown algorithm")
	}
}

// TestUserTokenEncryptionAlgorithm tests the encryption algorithm of each security policy.
func TestUserTokenEncryptionAlgorithm(t *testing.T) {
	cases := map[string]string{
		ua.SecurityPolicyURINone:                "",
		ua.SecurityPolicyURIBasic128Rsa15:       ua.RsaV15KeyWrap,
		ua.SecurityPolicyURIBasic256:            ua.RsaOaepKeyWrap,
		ua.SecurityPolicyURIBasic256Sha256:      ua.RsaOaepKeyWrap,
		ua.SecurityPolicyURIAes128Sha256RsaOaep: ua.RsaOaepKeyWrap,
		ua.SecurityPolicyURIAes256Sha256RsaPss:  ua.RsaOaepSha256KeyWrap,
		"http://example.com/unknown":            "",
	}
	for policy, want := range cases {
		if got := userTokenEncryptionAlgorithm(policy); got != want {
			t.Errorf("%s: got %q, want %q", policy, got, want)
		}
	}
}

// TestPasswordSecurityPolicyURI tests that passwords are not encrypted with PKCS #1 v1.5.
func TestPasswordSecurityPolicyURI(t *testing.T) {
	for _, policy := range []string{
		ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256, ua.SecurityPolicyURIBasic256Sha256,
		ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.SecurityPolicyURIAes256Sha256RsaPss,
	} {
		got := passwordSecurityPolicyURI(policy)
		if userTokenEncryptionAlgorithm(got) == ua.RsaV15KeyWrap {
			t.Errorf("%s: passwords are encrypted with PKCS #1 v1.5", policy)
		}
		if policy != ua.SecurityPolicyURIBasic128Rsa15 && got != policy {
			t.Errorf("%s: got %s", policy, got)
		}
		// a key that supports the policy of the endpoint supports the policy of the password.
		for _, keyLength := range []int{1024, 2048, 3072, 4096} {
			if rsaKeyLengthSupported(policy, keyLength) && !rsaKeyLengthSupported(got, keyLength) {
				t.Errorf("%s: %d bit key does not support password policy %s", policy, keyLength, got)
			}
		}
	}
}

// TestRSAKeyLengthSupported tests the key lengths of the security policies.
func TestRSAKeyLengthSupported(t *testing.T) {
	legacy := []string{ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256}
	current := []string{ua.SecurityPolicyURIBasic256Sha256, ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.SecurityPolicyURIAes256Sha256RsaPss}
	for _, c := range []struct {
		keyLength       int
		legacy, current bool
		password        string
	}{
		{0, false, false, ""},
		{512, false, false, ""},
		{1023, false, false, ""},
		{1024, true, false, ua.SecurityPolicyURIBasic256},
		{2047, true, false, ua.SecurityPolicyURIBasic256},
		{2048, true, true, ua.SecurityPolicyURIBasic256Sha256},
		{4096, true, true, ua.SecurityPolicyURIBasic256Sha256},
		{4097, false, false, ""},
		{8192, false, false, ""},
	} {
		for _, policy := range legacy {
			if got := rsaKeyLengthSupported(policy, c.keyLength); got != c.legacy {
				t.Errorf("%s, %d bits: got %t, want %t", policy, c.keyLength, got, c.legacy)
			}
		}
		for _, policy := range current {
			if got := rsaKeyLengthSupported(policy, c.keyLength); got != c.current {
				t.Errorf("%s, %d bits: got %t, want %t", policy, c.keyLength, got, c.current)
			}
		}
		if got := strongestPasswordSecurityPolicyURI(c.keyLength); got != c.password {
			t.Errorf("password policy, %d bits: got %q, want %q", c.keyLength, got, c.password)
		}
	}
}
