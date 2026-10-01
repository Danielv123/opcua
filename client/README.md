# client - [![Godoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/mod/github.com/awcullen/opcua/client) [![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/awcullen/opcua/master/LICENSE)
Browse, read, write and subscribe to data published by the OPC UA servers in your network.

With this package, you can call any service of the OPC Unified Architecture, see https://reference.opcfoundation.org/v104/Core/docs/Part4/

## Usage
To connect to your OPC UA server, call client.Dial, passing the endpoint URL of the server and various security options. Dial returns a connected client or an error.

For example, to connect to an OPC UA Demo Server, and read the server's status: 

```go
package client_test

import (
	"context"
	"fmt"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
)

func ExampleClient_Read() {

	ctx := context.Background()

	// open a connection to testserver running locally. Testserver is started if not already running.
	ch, err := client.Dial(
		ctx,
		"opc.tcp://localhost:46010",
		client.WithInsecureSkipVerify(), // skips verification of server certificate
	)
	if err != nil {
		fmt.Printf("Error opening client connection. %s\n", err.Error())
		return
	}

	// prepare read request
	req := &ua.ReadRequest{
		NodesToRead: []ua.ReadValueID{
			{
				NodeID:      ua.VariableIDServerServerStatus,
				AttributeID: ua.AttributeIDValue,
			},
		},
	}

	// send request to server. receive response or error
	res, err := ch.Read(ctx, req)
	if err != nil {
		fmt.Printf("Error reading ServerStatus. %s\n", err.Error())
		ch.Abort(ctx)
		return
	}

	// print results
	if serverStatus, ok := res.Results[0].Value.(ua.ServerStatusDataType); ok {
		fmt.Printf("Server status:\n")
		fmt.Printf("  ProductName: %s\n", serverStatus.BuildInfo.ProductName)
		fmt.Printf("  ManufacturerName: %s\n", serverStatus.BuildInfo.ManufacturerName)
		fmt.Printf("  State: %s\n", serverStatus.State)
	} else {
		fmt.Println("Error decoding ServerStatus.")
	}

	// close connection
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return
	}

	// Output:
	// Server status:
	//   ProductName: testserver
	//   ManufacturerName: awcullen
	//   State: Running
}


```

## Security
Dial first asks the server for its endpoint descriptions (GetEndpoints). That request uses an unsecured channel, so an attacker on the network path can change the response, for example to remove the secure endpoints or to ask for the password without encryption. Dial therefore only uses the response to choose among endpoints that meet the client's own requirements, and checks it again once the channel is secured:

- **Endpoint selection.** Dial ranks endpoints by the server's security level, then by security mode, then by security policy strength, so the order of the discovery response doesn't matter. It picks the strongest user token policy the endpoint offers. With `WithSecurityPolicyURI`, Dial connects only to an endpoint with the requested policy and mode. If the server does not offer one, Dial fails with `BadSecurityModeRejected` instead of connecting to a weaker endpoint. A Sign or SignAndEncrypt endpoint requires a client certificate. If an eligible endpoint that ranks at least as high as the selected one is missing a usable server certificate, either for the channel or to encrypt its strongest user token policy, Dial fails with `BadCertificateInvalid` rather than falling back to a weaker endpoint.
- **Minimum security mode.** `WithMinSecurityMode(mode)` sets the weakest MessageSecurityMode Dial will accept. Dial never selects an endpoint below it and fails with `BadSecurityModeRejected` if no endpoint meets it. If you don't set it, the minimum is `MessageSecurityModeSign` when the user identity is a UserName, Issued or X509 identity and the endpoint is selected automatically. Otherwise the minimum is `MessageSecurityModeNone`. A secured channel requires a client certificate. Without one, a client with credentials can only connect if it accepts an unsecured channel explicitly, with `WithMinSecurityMode(ua.MessageSecurityModeNone)` or `WithSecurityPolicyURI(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)`. On an unsecured channel, an on-path attacker cannot read an encrypted password, but can relay the user token to the server and take over the session.
- **Credentials are never sent in plaintext.** A UserName password or an IssuedIdentity token is sent only if it is encrypted with the server certificate (the user token policy has a security policy other than None), or if the channel is SignAndEncrypt. Otherwise Dial fails with `BadSecurityModeInsufficient` before any credential bytes are sent. A token policy with an unsupported security policy is never used. `WithInsecurePlaintextCredentials()` explicitly allows plaintext credentials, for example for a legacy server on a trusted network.
- **Server certificate validation.** A secured endpoint, or a user token policy that encrypts the token, needs a valid RSA server certificate whose key is large enough for the security policy: at least 1024 bits for Basic128Rsa15 and Basic256, and at least 2048 bits for the other policies. Otherwise it is rejected (`BadCertificateInvalid`). The server certificate is checked against the trusted certificates (`WithTrustedCertificatesPaths`) whenever it is used, whether to secure the channel or to encrypt a user token on a None channel. Otherwise an attacker could swap in their own certificate. `WithInsecureSkipVerify()` turns this check off. Use it only for testing: an attacker can then impersonate the server and receive credentials encrypted with the attacker's certificate.
- **Endpoint verification.** As required by OPC UA Part 4, 5.6.2, the client checks that the endpoints returned by CreateSession match the endpoints returned by discovery, comparing security mode, security policy, security level, transport profile, and user token policies (in any order). The server certificate and application URI are compared too, unless the server leaves them out of the CreateSession response. It also checks that the server certificate matches the certificate of the secure channel. If they differ, Dial fails with `BadSecurityChecksFailed` before ActivateSession, so no credentials are sent. When the channel is secured, the CreateSession response is authenticated, so this check detects a discovery response that was altered.

For example, to require an encrypted channel and authenticate the server with a trusted certificate:

```go
ch, err := client.Dial(
	ctx,
	"opc.tcp://myserver:4840",
	client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
	client.WithTrustedCertificatesPaths("./pki/trusted/certs", "./pki/trusted/crl"),
	client.WithMinSecurityMode(ua.MessageSecurityModeSignAndEncrypt),
	client.WithUserNameIdentity("user", "password"),
)
```

### Migrating from earlier versions
- If a server only offers a user token policy with security policy None on an endpoint that is not SignAndEncrypt, Dial with a UserName or Issued identity now fails with `BadSecurityModeInsufficient`. Use a secure endpoint, or add `client.WithInsecurePlaintextCredentials()` to keep the old behavior.
- If you use a UserName, Issued or X509 identity and let Dial select the endpoint, Dial no longer connects to a None endpoint. Without a client certificate, Dial now fails with `BadSecurityModeRejected`. Configure a client certificate with `client.WithClientCertificatePaths(...)`, or, if you accept an unsecured channel, add `client.WithMinSecurityMode(ua.MessageSecurityModeNone)` or request the endpoint explicitly with `client.WithSecurityPolicyURI(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)`. The same applies if the server only offers None endpoints.
- `WithSecurityPolicyURI("", ua.MessageSecurityModeSign)` or `WithSecurityPolicyURI("", ua.MessageSecurityModeSignAndEncrypt)` without a client certificate now fails with `BadSecurityModeRejected`. Previously it silently connected with security policy None.
- If the endpoints returned by CreateSession don't match the endpoints returned by GetEndpoints, Dial now fails with `BadSecurityChecksFailed`.
