// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"crypto/rsa"
	"crypto/x509"
	"sort"

	"github.com/awcullen/opcua/ua"
)

// selectEndpoint selects the endpoint to connect to from the endpoints returned by discovery.
//
// The discovery response is received over an unauthenticated channel, so an on-path attacker may
// have altered it. It is therefore only trusted to choose among endpoints that satisfy the client's
// own requirements:
//   - the endpoint matches the security policy URI and message security mode requested with WithSecurityPolicyURI, if any.
//   - the endpoint's message security mode is at least the minimum security mode (see WithMinSecurityMode).
//   - a secured endpoint has a server certificate, and the client has a certificate.
//   - the endpoint offers a user token policy that does not expose the client's credentials (see selectUserTokenPolicy).
//
// Endpoints are considered in order of decreasing security level. Returns the selected endpoint and the user token
// policy to use, or an error describing why the most secure candidate was rejected.
func (ch *Client) selectEndpoint(endpoints []ua.EndpointDescription) (*ua.EndpointDescription, *ua.UserTokenPolicy, error) {
	// order endpoints by decreasing security level.
	orderedEndpoints := make([]ua.EndpointDescription, len(endpoints))
	copy(orderedEndpoints, endpoints)
	sort.SliceStable(orderedEndpoints, func(i, j int) bool {
		return orderedEndpoints[i].SecurityLevel > orderedEndpoints[j].SecurityLevel
	})

	minSecurityMode := ch.effectiveMinSecurityMode()
	var reason error = ua.BadSecurityModeRejected
	for i := range orderedEndpoints {
		e := &orderedEndpoints[i]
		if !isUaTcpTransport(e.TransportProfileURI) {
			continue
		}
		// filter out unsupported policy uri, and modes that are inconsistent with the policy.
		switch e.SecurityPolicyURI {
		case ua.SecurityPolicyURINone:
			if e.SecurityMode != ua.MessageSecurityModeNone {
				continue
			}
		case ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256,
			ua.SecurityPolicyURIBasic256Sha256, ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.SecurityPolicyURIAes256Sha256RsaPss:
			if e.SecurityMode != ua.MessageSecurityModeSign && e.SecurityMode != ua.MessageSecurityModeSignAndEncrypt {
				continue
			}
			// a secured channel requires a client certificate.
			if len(ch.localCertificate) == 0 {
				continue
			}
		default:
			continue
		}
		// filter out endpoints that do not match the requested policy uri and security mode.
		if ch.securityPolicyURI != ua.SecurityPolicyURIBestAvailable && e.SecurityPolicyURI != ch.securityPolicyURI {
			continue
		}
		if ch.securityMode != ua.MessageSecurityModeInvalid && e.SecurityMode != ch.securityMode {
			continue
		}
		// never select an endpoint weaker than the minimum security mode.
		if e.SecurityMode < minSecurityMode {
			continue
		}
		// a secured channel must be authenticated with the server certificate.
		if e.SecurityMode != ua.MessageSecurityModeNone && !isRSACertificate(e.ServerCertificate) {
			if reason == ua.BadSecurityModeRejected {
				reason = ua.BadCertificateInvalid
			}
			continue
		}
		tokenPolicy, err := ch.selectUserTokenPolicy(e)
		if err != nil {
			if reason == ua.BadSecurityModeRejected {
				reason = err
			}
			continue
		}
		return e, tokenPolicy, nil
	}
	return nil, nil, reason
}

// effectiveMinSecurityMode returns the minimum message security mode that endpoint selection accepts.
// Unless set with WithMinSecurityMode, this is MessageSecurityModeSign when the endpoint is selected
// automatically, the client has a certificate (so it can open a secure channel), and the user identity
// carries credentials. Otherwise it is MessageSecurityModeNone.
func (ch *Client) effectiveMinSecurityMode() ua.MessageSecurityMode {
	if ch.minSecurityMode != ua.MessageSecurityModeInvalid {
		return ch.minSecurityMode
	}
	if ch.securityPolicyURI == ua.SecurityPolicyURIBestAvailable && ch.securityMode == ua.MessageSecurityModeInvalid && len(ch.localCertificate) > 0 {
		switch ch.userIdentity.(type) {
		case ua.UserNameIdentity, ua.IssuedIdentity, ua.X509Identity:
			return ua.MessageSecurityModeSign
		}
	}
	return ua.MessageSecurityModeNone
}

// selectUserTokenPolicy selects the user token policy of the endpoint to use for the client's user identity.
// A secret (the password of a UserNameIdentity or the token of an IssuedIdentity) is only sent
// if it is encrypted with the server certificate, or if it is protected by a SignAndEncrypt channel,
// unless sending it in plaintext was allowed with WithInsecurePlaintextCredentials.
// A token policy that encrypts the token is preferred over one that does not.
// A token policy with an unsupported security policy uri is never used.
func (ch *Client) selectUserTokenPolicy(e *ua.EndpointDescription) (*ua.UserTokenPolicy, error) {
	var tokenType ua.UserTokenType
	var secret bool
	switch ch.userIdentity.(type) {
	case ua.UserNameIdentity:
		tokenType, secret = ua.UserTokenTypeUserName, true
	case ua.IssuedIdentity:
		tokenType, secret = ua.UserTokenTypeIssuedToken, true
	case ua.X509Identity:
		tokenType = ua.UserTokenTypeCertificate
	default:
		tokenType = ua.UserTokenTypeAnonymous
	}
	var reason error = ua.BadIdentityTokenRejected
	var unencrypted *ua.UserTokenPolicy
	for i := range e.UserIdentityTokens {
		t := &e.UserIdentityTokens[i]
		if t.TokenType != tokenType {
			continue
		}
		if tokenType == ua.UserTokenTypeAnonymous {
			return t, nil
		}
		switch tokenSecurityPolicyURI(t, e) {
		case ua.SecurityPolicyURINone:
			// token is sent without encryption.
			if secret && e.SecurityMode != ua.MessageSecurityModeSignAndEncrypt && !ch.allowPlaintextCredentials {
				reason = ua.BadSecurityModeInsufficient
				continue
			}
			if unencrypted == nil {
				unencrypted = t
			}
		case ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256,
			ua.SecurityPolicyURIBasic256Sha256, ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.SecurityPolicyURIAes256Sha256RsaPss:
			// token is encrypted (or signed) with the server certificate.
			if !isRSACertificate(e.ServerCertificate) {
				reason = ua.BadCertificateInvalid
				continue
			}
			return t, nil
		}
		// unsupported token security policy uri.
	}
	if unencrypted != nil {
		return unencrypted, nil
	}
	return nil, reason
}

// tokenSecurityPolicyURI returns the security policy uri used to encrypt or sign a user token.
// If the token policy does not specify one, the endpoint's security policy uri is used.
func tokenSecurityPolicyURI(t *ua.UserTokenPolicy, e *ua.EndpointDescription) string {
	if t.SecurityPolicyURI != "" {
		return t.SecurityPolicyURI
	}
	return e.SecurityPolicyURI
}

// isRSACertificate returns true if the certificate (or chain) can be parsed and the leaf has an RSA public key.
func isRSACertificate(certificate ua.ByteString) bool {
	certs, err := x509.ParseCertificates([]byte(certificate))
	if err != nil || len(certs) == 0 {
		return false
	}
	_, ok := certs[0].PublicKey.(*rsa.PublicKey)
	return ok
}

// isUaTcpTransport returns true if the transport profile uri is UA TCP. An empty uri is accepted for compatibility.
func isUaTcpTransport(uri string) bool {
	return uri == ua.TransportProfileURIUaTcpTransport || uri == ""
}

// verifyServerEndpoints verifies that the endpoints the server returned in the CreateSessionResponse
// match the endpoints that were returned by discovery. The discovery response is not authenticated,
// so this detects an attacker who altered it, for example to remove the more secure endpoints or to
// weaken the user token policies. When the session's channel is secured, the CreateSessionResponse is
// authenticated by the server certificate.
// Compares the security mode, security policy uri, security level, user token policies and, if both are present,
// the server certificate of the endpoints that use the UA TCP transport.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.2/
func verifyServerEndpoints(discoveryEndpoints, sessionEndpoints []ua.EndpointDescription) error {
	if !containsEndpoints(discoveryEndpoints, sessionEndpoints) || !containsEndpoints(sessionEndpoints, discoveryEndpoints) {
		return ua.BadSecurityChecksFailed
	}
	return nil
}

// containsEndpoints returns true if every UA TCP endpoint in b has a matching endpoint in a.
func containsEndpoints(a, b []ua.EndpointDescription) bool {
outer:
	for i := range b {
		if !isUaTcpTransport(b[i].TransportProfileURI) {
			continue
		}
		for j := range a {
			if isUaTcpTransport(a[j].TransportProfileURI) && endpointsMatch(&a[j], &b[i]) {
				continue outer
			}
		}
		return false
	}
	return true
}

// endpointsMatch returns true if the security relevant fields of the endpoints are equal.
// The EndpointURL is not compared, as servers may return a different host name for the same endpoint.
func endpointsMatch(a, b *ua.EndpointDescription) bool {
	if a.SecurityMode != b.SecurityMode ||
		a.SecurityPolicyURI != b.SecurityPolicyURI ||
		a.SecurityLevel != b.SecurityLevel ||
		len(a.UserIdentityTokens) != len(b.UserIdentityTokens) {
		return false
	}
	for i := range a.UserIdentityTokens {
		if a.UserIdentityTokens[i] != b.UserIdentityTokens[i] {
			return false
		}
	}
	// servers may omit the certificates from the endpoints returned in the CreateSessionResponse.
	if len(a.ServerCertificate) > 0 && len(b.ServerCertificate) > 0 && a.ServerCertificate != b.ServerCertificate {
		return false
	}
	return true
}
