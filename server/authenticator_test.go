// Copyright 2021 Converter Systems LLC. All rights reserved.

package server_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

// authenticatorTestPort is the port of the server started by TestAuthenticatorErrors.
const authenticatorTestPort = 46410

// TestAuthenticatorErrors verifies that identity authenticators may reject users with
// any kind of error without crashing the server. See issue #8.
func TestAuthenticatorErrors(t *testing.T) {
	ctx := context.Background()
	authEndpointURL := fmt.Sprintf("opc.tcp://%s:%d", host, authenticatorTestPort)

	srv, err := server.New(
		ua.ApplicationDescription{
			ApplicationURI: fmt.Sprintf("urn:%s:testserver", host),
			ProductURI:     "http://github.com/awcullen/opcua",
			ApplicationName: ua.LocalizedText{
				Text:   fmt.Sprintf("authenticatorserver@%s", host),
				Locale: "en",
			},
			ApplicationType: ua.ApplicationTypeServer,
			DiscoveryURLs:   []string{authEndpointURL},
		},
		"./pki/server.crt",
		"./pki/server.key",
		authEndpointURL,
		server.WithAuthenticateUserNameIdentityFunc(func(userIdentity ua.UserNameIdentity, applicationURI string, endpointURL string) error {
			switch userIdentity.UserName {
			case "user":
				if userIdentity.Password == "secret" {
					return nil
				}
				// a plain Go error, as an application might return for invalid credentials.
				return fmt.Errorf("invalid password for user %q", userIdentity.UserName)
			case "wrapped":
				// a status code wrapped with additional context.
				return fmt.Errorf("account locked: %w", ua.BadIdentityTokenRejected)
			case "good":
				// a status code that does not indicate a rejection.
				return ua.Good
			default:
				return ua.BadUserAccessDenied
			}
		}),
		server.WithAuthenticateAnonymousIdentityFunc(func(userIdentity ua.AnonymousIdentity, applicationURI string, endpointURL string) error {
			return errors.New("anonymous access is disabled")
		}),
		server.WithAuthenticateX509IdentityFunc(func(userIdentity ua.X509Identity, applicationURI string, endpointURL string) error {
			return fmt.Errorf("certificate of %d bytes is not authorized", len(userIdentity.Certificate))
		}),
		server.WithSecurityPolicyNone(true),
		server.WithInsecureSkipVerify(),
	)
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()
	defer srv.Close()

	// wait for server to listen.
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := client.FindServers(ctx, &ua.FindServersRequest{EndpointURL: authEndpointURL})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	cases := []struct {
		name     string
		identity client.Option
		want     ua.StatusCode
	}{
		{"user with wrong password", client.WithUserNameIdentity("user", "wrong"), ua.BadUserAccessDenied},
		{"wrapped", client.WithUserNameIdentity("wrapped", "secret"), ua.BadIdentityTokenRejected},
		{"good", client.WithUserNameIdentity("good", "secret"), ua.BadUserAccessDenied},
		{"other", client.WithUserNameIdentity("other", "secret"), ua.BadUserAccessDenied},
		{"anonymous", nil, ua.BadUserAccessDenied},
		{"x509", client.WithX509IdentityPaths("./pki/client.crt", "./pki/client.key"), ua.BadUserAccessDenied},
	}
	for _, c := range cases {
		for _, secure := range []bool{false, true} {
			opts := []client.Option{
				client.WithInsecureSkipVerify(),
			}
			if c.identity != nil {
				opts = append(opts, c.identity)
			}
			if secure {
				opts = append(opts,
					client.WithSecurityPolicyURI(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt),
					client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
				)
			} else {
				opts = append(opts, client.WithSecurityPolicyURI(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone))
			}
			ch, err := client.Dial(ctx, authEndpointURL, opts...)
			if err == nil {
				ch.Close(ctx)
				t.Errorf("Dial %s (secure: %t) succeeded, want %v", c.name, secure, c.want)
				continue
			}
			if err != c.want {
				t.Errorf("Dial %s (secure: %t): got %v, want %v", c.name, secure, err, c.want)
			}
		}
	}

	// the server continues to serve requests.
	ch, err := client.Dial(ctx, authEndpointURL,
		client.WithInsecureSkipVerify(),
		client.WithSecurityPolicyURI(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone),
		client.WithUserNameIdentity("user", "secret"),
	)
	if err != nil {
		t.Fatalf("Dial with valid credentials: %v", err)
	}
	defer ch.Abort(ctx)
	res, err := ch.Read(ctx, &ua.ReadRequest{
		NodesToRead: []ua.ReadValueID{
			{NodeID: ua.VariableIDServerServerStatusState, AttributeID: ua.AttributeIDValue},
		},
	})
	if err != nil {
		t.Fatalf("Read after rejected logins: %v", err)
	}
	if len(res.Results) != 1 || res.Results[0].StatusCode.IsBad() {
		t.Fatalf("Read after rejected logins: unexpected results %v", res.Results)
	}
}
