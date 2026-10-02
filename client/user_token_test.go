// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

// userTokenTestPort is the port of the server started by TestUserNameTokenEncryption.
const userTokenTestPort = 46412

// utEncrypt encrypts plainText with the public key of the server certificate in blocks, using the encryption
// algorithm of the user token policy securityPolicyURI. It returns the cipher text and the algorithm.
func utEncrypt(t *testing.T, serverCertificate ua.ByteString, securityPolicyURI string, plainText []byte) ([]byte, string) {
	t.Helper()
	crt, err := x509.ParseCertificate([]byte(serverCertificate))
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := crt.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("server certificate does not have a RSA key")
	}
	var algorithm string
	var blockSize int
	var encrypt func([]byte) ([]byte, error)
	switch securityPolicyURI {
	case ua.SecurityPolicyURIBasic128Rsa15:
		algorithm, blockSize = ua.RsaV15KeyWrap, pub.Size()-11
		encrypt = func(b []byte) ([]byte, error) { return rsa.EncryptPKCS1v15(rand.Reader, pub, b) }
	case ua.SecurityPolicyURIBasic256, ua.SecurityPolicyURIBasic256Sha256, ua.SecurityPolicyURIAes128Sha256RsaOaep:
		algorithm, blockSize = ua.RsaOaepKeyWrap, pub.Size()-2*sha1.Size-2
		encrypt = func(b []byte) ([]byte, error) { return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, b, nil) }
	case ua.SecurityPolicyURIAes256Sha256RsaPss:
		algorithm, blockSize = ua.RsaOaepSha256KeyWrap, pub.Size()-2*sha256.Size-2
		encrypt = func(b []byte) ([]byte, error) { return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, b, nil) }
	default:
		t.Fatalf("unsupported security policy %s", securityPolicyURI)
	}
	var cipherText []byte
	for i := 0; i < len(plainText); i += blockSize {
		block, err := encrypt(plainText[i:min(i+blockSize, len(plainText))])
		if err != nil {
			t.Fatal(err)
		}
		cipherText = append(cipherText, block...)
	}
	return cipherText, algorithm
}

// utSecret returns the plain text of an encrypted user token secret: length || secret || nonce || padding.
func utSecret(secret, nonce []byte, padding ...byte) []byte {
	plainText := binary.LittleEndian.AppendUint32(nil, uint32(len(secret)+len(nonce)))
	plainText = append(plainText, secret...)
	plainText = append(plainText, nonce...)
	return append(plainText, padding...)
}

// utUserNameToken returns a UserNameIdentityToken for the user token policy of c, with the cipher text
// of the plain text as password.
func utUserNameToken(t *testing.T, c sbConn, userName string, plainText []byte) ua.UserNameIdentityToken {
	t.Helper()
	policy := sbTokenPolicy(c, ua.UserTokenTypeUserName)
	cipherText, algorithm := utEncrypt(t, c.endpoint.ServerCertificate, policy.SecurityPolicyURI, plainText)
	return ua.UserNameIdentityToken{UserName: userName, Password: ua.ByteString(cipherText), EncryptionAlgorithm: algorithm, PolicyID: policy.PolicyID}
}

// TestUserNameTokenEncryption verifies that encrypted passwords are bound to the session nonce, and that
// all decryption failures are reported alike, without closing the secure channel.
func TestUserNameTokenEncryption(t *testing.T) {
	ctx := context.Background()
	endpointURL := fmt.Sprintf("opc.tcp://%s:%d", host, userTokenTestPort)
	var authentications, raceArrivals atomic.Int32
	var raceArmed atomic.Bool
	maxPassword := string(bytes.Repeat([]byte("p"), 64))
	// the status of the authenticator for a wrong password, which differs from the status of the server for a
	// password that does not decrypt for the session.
	const wrongPassword = ua.BadUserAccessDenied

	srv, err := server.New(
		ua.ApplicationDescription{
			ApplicationURI: fmt.Sprintf("urn:%s:testserver", host),
			ProductURI:     "http://github.com/awcullen/opcua",
			ApplicationName: ua.LocalizedText{
				Text:   fmt.Sprintf("usertokenserver@%s", host),
				Locale: "en",
			},
			ApplicationType: ua.ApplicationTypeServer,
			DiscoveryURLs:   []string{endpointURL},
		},
		"./pki/server.crt",
		"./pki/server.key",
		endpointURL,
		server.WithAuthenticateAnonymousIdentityFunc(func(userIdentity ua.AnonymousIdentity, applicationURI string, endpointURL string) error {
			return nil
		}),
		server.WithAuthenticateUserNameIdentityFunc(func(userIdentity ua.UserNameIdentity, applicationURI string, endpointURL string) error {
			authentications.Add(1)
			if userIdentity.UserName == "race" && raceArmed.Load() {
				// wait for a concurrent activation of the same session, if there is one.
				raceArrivals.Add(1)
				for deadline := time.Now().Add(2 * time.Second); raceArrivals.Load() < 2 && time.Now().Before(deadline); {
					time.Sleep(10 * time.Millisecond)
				}
			}
			switch {
			case userIdentity.UserName == "user" && userIdentity.Password == "secret",
				userIdentity.UserName == "race" && userIdentity.Password == "secret",
				userIdentity.UserName == "max" && userIdentity.Password == maxPassword:
				return nil
			}
			return wrongPassword
		}),
		server.WithSecurityPolicyNone(true),
		server.WithInsecureSkipVerify(),
	)
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()
	defer srv.Close()
	sbWaitForServer(t, endpointURL)

	appA := newSBCertificate(t, "user-token-client-a", false, nil)
	appB := newSBCertificate(t, "user-token-client-b", false, nil)
	password := []byte("secret")

	t.Run("PasswordReplayedToOtherSessionRejected", func(t *testing.T) {
		// the victim activates a session over a channel that only signs messages.
		victim := sbDial(t, ctx, endpointURL, appA, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign)
		res, err := sbCreateSession(ctx, victim.cli, appA.certificate, appA.applicationURI)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		observed := utUserNameToken(t, victim, "user", utSecret(password, []byte(res.ServerNonce)))
		act, err := sbActivate(ctx, victim, res.AuthenticationToken, res.ServerNonce, observed, ua.SignatureData{})
		if err != nil {
			t.Fatalf("ActivateSession with password: %v", err)
		}

		// an observer replays the token to a session of its own, over a secured or an unsecured channel.
		for _, attacker := range []sbConn{
			sbDial(t, ctx, endpointURL, appB, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign),
			sbDial(t, ctx, endpointURL, appB, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone),
		} {
			res2, err := sbCreateSession(ctx, attacker.cli, appB.certificate, appB.applicationURI)
			if err != nil {
				t.Fatalf("CreateSession: %v", err)
			}
			replayed := observed
			replayed.PolicyID = sbTokenPolicy(attacker, ua.UserTokenTypeUserName).PolicyID
			if _, err := sbActivate(ctx, attacker, res2.AuthenticationToken, res2.ServerNonce, replayed, ua.SignatureData{}); err != ua.BadIdentityTokenInvalid {
				t.Errorf("ActivateSession with replayed password (%s): got %v, want %v", attacker.endpoint.SecurityPolicyURI, err, ua.BadIdentityTokenInvalid)
			}
			// the password encrypted for the session is accepted.
			token := utUserNameToken(t, attacker, "user", utSecret(password, []byte(res2.ServerNonce)))
			if _, err := sbActivate(ctx, attacker, res2.AuthenticationToken, res2.ServerNonce, token, ua.SignatureData{}); err != nil {
				t.Errorf("ActivateSession with password (%s): %v", attacker.endpoint.SecurityPolicyURI, err)
			}
		}

		// the token cannot be replayed to the same session, whose nonce changed on activation.
		if _, err := sbActivate(ctx, victim, res.AuthenticationToken, act.ServerNonce, observed, ua.SignatureData{}); err != ua.BadIdentityTokenInvalid {
			t.Errorf("ActivateSession with replayed password on same session: got %v, want %v", err, ua.BadIdentityTokenInvalid)
		}
		token := utUserNameToken(t, victim, "user", utSecret(password, []byte(act.ServerNonce)))
		if _, err := sbActivate(ctx, victim, res.AuthenticationToken, act.ServerNonce, token, ua.SignatureData{}); err != nil {
			t.Errorf("ActivateSession with password encrypted for the new nonce: %v", err)
		}
	})

	for _, securityPolicyURI := range []string{ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256, ua.SecurityPolicyURIBasic256Sha256, ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.SecurityPolicyURIAes256Sha256RsaPss} {
		t.Run("DecryptionFailuresIndistinguishable/"+securityPolicyURI[len("http://opcfoundation.org/UA/SecurityPolicy#"):], func(t *testing.T) {
			c := sbDial(t, ctx, endpointURL, appA, securityPolicyURI, ua.MessageSecurityModeSign)
			policy := sbTokenPolicy(c, ua.UserTokenTypeUserName)
			crt, err := x509.ParseCertificate([]byte(c.endpoint.ServerCertificate))
			if err != nil {
				t.Fatal(err)
			}
			pub := crt.PublicKey.(*rsa.PublicKey)
			k := pub.Size()
			// a cipher text block that decrypts to 0x00 ... 0x02, which has invalid padding for every algorithm.
			invalidPadding := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(pub.E)), pub.N).FillBytes(make([]byte, k))

			res, err := sbCreateSession(ctx, c.cli, appA.certificate, appA.applicationURI)
			if err != nil {
				t.Fatalf("CreateSession: %v", err)
			}
			nonce := []byte(res.ServerNonce)
			valid := utUserNameToken(t, c, "user", utSecret(password, nonce))
			cases := map[string]ua.UserNameIdentityToken{
				"invalid padding":           {Password: ua.ByteString(invalidPadding)},
				"partial block":             {Password: valid.Password[:len(valid.Password)-1]},
				"two blocks":                {Password: valid.Password + valid.Password},
				"empty":                     {Password: ua.ByteString("")},
				"length too long":           utUserNameToken(t, c, "user", append([]byte{0xff, 0xff, 0xff, 0xff}, make([]byte, 40)...)),
				"length shorter than nonce": utUserNameToken(t, c, "user", append([]byte{4, 0, 0, 0}, nonce...)),
				"other nonce":               utUserNameToken(t, c, "user", utSecret(password, make([]byte, len(nonce)))),
				"no nonce":                  utUserNameToken(t, c, "user", utSecret(password, nil)),
				"nonzero padding":           utUserNameToken(t, c, "user", utSecret(password, nonce, 0, 1)),
				"password too long":         utUserNameToken(t, c, "max", utSecret([]byte(maxPassword+"p"), nonce)),
			}
			if securityPolicyURI == ua.SecurityPolicyURIBasic128Rsa15 {
				// passwords are encrypted with RSA-OAEP, not with PKCS #1 v1.5, on Basic128Rsa15 endpoints.
				if policy.SecurityPolicyURI != ua.SecurityPolicyURIBasic256 {
					t.Errorf("password security policy: got %s, want %s", policy.SecurityPolicyURI, ua.SecurityPolicyURIBasic256)
				}
				cipherText, algorithm := utEncrypt(t, c.endpoint.ServerCertificate, ua.SecurityPolicyURIBasic128Rsa15, utSecret(password, nonce))
				cases["pkcs1 v1.5"] = ua.UserNameIdentityToken{UserName: "user", Password: ua.ByteString(cipherText), EncryptionAlgorithm: algorithm, PolicyID: policy.PolicyID}
			}
			for name, token := range cases {
				if token.PolicyID == "" {
					token.UserName, token.PolicyID, token.EncryptionAlgorithm = "user", policy.PolicyID, valid.EncryptionAlgorithm
				}
				// every failure is reported alike, before the authenticator is called.
				want := ua.BadIdentityTokenInvalid
				before := authentications.Load()
				if _, err := sbActivate(ctx, c, res.AuthenticationToken, res.ServerNonce, token, ua.SignatureData{}); err != want {
					t.Errorf("%s: got %v, want %v", name, err, want)
				}
				if authentications.Load() != before {
					t.Errorf("%s: authenticator was called", name)
				}
				// the secure channel remains open.
				if _, err := sbCreateSession(ctx, c.cli, appA.certificate, appA.applicationURI); err != nil {
					t.Fatalf("%s: CreateSession after rejected password: %v", name, err)
				}
			}
			// a wrong password is checked by the authenticator.
			wrong := utUserNameToken(t, c, "user", utSecret([]byte("wrong"), nonce))
			if _, err := sbActivate(ctx, c, res.AuthenticationToken, res.ServerNonce, wrong, ua.SignatureData{}); err != wrongPassword {
				t.Errorf("wrong password: got %v, want %v", err, wrongPassword)
			}
			if _, err := sbActivate(ctx, c, res.AuthenticationToken, res.ServerNonce, valid, ua.SignatureData{}); err != nil {
				t.Errorf("ActivateSession with password: %v", err)
			}
		})
	}

	t.Run("ClientPasswordAccepted", func(t *testing.T) {
		// the client pads the plain text block of the password with zeros.
		for _, securityPolicyURI := range []string{ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256, ua.SecurityPolicyURIBasic256Sha256, ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.SecurityPolicyURIAes256Sha256RsaPss} {
			for _, identity := range [][2]string{{"user", "secret"}, {"max", maxPassword}} {
				cli, err := Dial(
					ctx,
					endpointURL,
					WithSecurityPolicyURI(securityPolicyURI, ua.MessageSecurityModeSignAndEncrypt),
					WithClientCertificate(appA.certificate, appA.key),
					WithInsecureSkipVerify(),
					WithUserNameIdentity(identity[0], identity[1]),
				)
				if err != nil {
					t.Errorf("Dial as %s (%s): %v", identity[0], securityPolicyURI, err)
					continue
				}
				cli.Abort(ctx)
			}
		}
	})

	t.Run("UnsecuredSessionTransferRejected", func(t *testing.T) {
		victim := sbDial(t, ctx, endpointURL, appA, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)
		res, err := sbCreateSession(ctx, victim.cli, appA.certificate, appA.applicationURI)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		act, err := sbActivate(ctx, victim, res.AuthenticationToken, res.ServerNonce, utUserNameToken(t, victim, "user", utSecret(password, []byte(res.ServerNonce))), ua.SignatureData{})
		if err != nil {
			t.Fatalf("ActivateSession: %v", err)
		}
		// an observer captures the next activation request and sends it first over another unsecured channel.
		token := utUserNameToken(t, victim, "user", utSecret(password, []byte(act.ServerNonce)))
		attacker := sbDial(t, ctx, endpointURL, appB, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)
		if _, err := sbActivate(ctx, attacker, res.AuthenticationToken, act.ServerNonce, token, ua.SignatureData{}); err != ua.BadSecurityChecksFailed {
			t.Errorf("ActivateSession on other unsecured channel: got %v, want %v", err, ua.BadSecurityChecksFailed)
		}
		if _, err := sbActivate(ctx, victim, res.AuthenticationToken, act.ServerNonce, token, ua.SignatureData{}); err != nil {
			t.Errorf("ActivateSession on creating channel: %v", err)
		}
	})

	t.Run("ConcurrentActivationsUseNonceOnce", func(t *testing.T) {
		a := sbDial(t, ctx, endpointURL, appA, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
		res, err := sbCreateSession(ctx, a.cli, appA.certificate, appA.applicationURI)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		act, err := sbActivate(ctx, a, res.AuthenticationToken, res.ServerNonce, utUserNameToken(t, a, "race", utSecret(password, []byte(res.ServerNonce))), ua.SignatureData{})
		if err != nil {
			t.Fatalf("ActivateSession: %v", err)
		}
		// the client sends the next activation request of the session over two channels at once.
		b := sbDial(t, ctx, endpointURL, appA, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
		c := sbDial(t, ctx, endpointURL, appA, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
		token := utUserNameToken(t, b, "race", utSecret(password, []byte(act.ServerNonce)))
		raceArmed.Store(true)
		defer raceArmed.Store(false)
		results := make(chan error, 2)
		for _, conn := range []sbConn{b, c} {
			go func(conn sbConn) {
				_, err := sbActivate(ctx, conn, res.AuthenticationToken, act.ServerNonce, token, ua.SignatureData{})
				results <- err
			}(conn)
		}
		successes := 0
		for i := 0; i < 2; i++ {
			switch err := <-results; err {
			case nil:
				successes++
			case ua.BadApplicationSignatureInvalid, ua.BadIdentityTokenInvalid:
				// the signature or the password is for the nonce used by the other activation.
			default:
				t.Errorf("ActivateSession: %v", err)
			}
		}
		if successes != 1 {
			t.Errorf("concurrent activations with the same nonce: got %d successes, want 1", successes)
		}
	})
}
