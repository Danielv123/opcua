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
//   - a secured endpoint has a usable server certificate, and the client has a certificate.
//   - the endpoint offers a user token policy that does not expose the client's credentials (see selectUserTokenPolicy).
//
// Endpoints are ranked by decreasing security level, then security mode, then security policy strength, so the
// order of the discovery response does not matter. Among endpoints of equal rank, the endpoint with the strongest
// user token policy is selected. If a candidate that ranks above the selected endpoint has a missing or unusable
// server certificate, selection fails, rather than falling back to a weaker endpoint, since the server may omit
// certificates from the endpoints returned by CreateSession, which are later compared with the discovery response.
//
// Returns the selected endpoint and the user token policy to use, or an error describing why no endpoint was selected.
func (ch *Client) selectEndpoint(endpoints []ua.EndpointDescription) (*ua.EndpointDescription, *ua.UserTokenPolicy, error) {
	orderedEndpoints := make([]ua.EndpointDescription, len(endpoints))
	copy(orderedEndpoints, endpoints)
	sort.SliceStable(orderedEndpoints, func(i, j int) bool {
		return compareEndpointRank(&orderedEndpoints[i], &orderedEndpoints[j]) > 0
	})

	minSecurityMode := ch.effectiveMinSecurityMode()
	var reason error = ua.BadSecurityModeRejected
	var selected *ua.EndpointDescription
	var selectedTokenPolicy *ua.UserTokenPolicy
	for i := range orderedEndpoints {
		e := &orderedEndpoints[i]
		// only consider endpoints of equal rank to the selected endpoint.
		if selected != nil && compareEndpointRank(e, selected) < 0 {
			break
		}
		if !isUaTcpTransport(e.TransportProfileURI) {
			continue
		}
		// filter out unsupported policy uri, and modes that are inconsistent with the policy.
		switch securityPolicyStrength(e.SecurityPolicyURI) {
		case -1:
			continue
		case 0:
			if e.SecurityMode != ua.MessageSecurityModeNone {
				continue
			}
		default:
			if e.SecurityMode != ua.MessageSecurityModeSign && e.SecurityMode != ua.MessageSecurityModeSignAndEncrypt {
				continue
			}
			// a secured channel requires a client certificate.
			if len(ch.localCertificate) == 0 {
				continue
			}
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
		if e.SecurityMode != ua.MessageSecurityModeNone && !isUsableCertificate(e.ServerCertificate, e.SecurityPolicyURI) {
			if selected == nil {
				return nil, nil, ua.BadCertificateInvalid
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
		if selected == nil || userTokenStrength(tokenPolicy, e) > userTokenStrength(selectedTokenPolicy, selected) {
			selected, selectedTokenPolicy = e, tokenPolicy
		}
	}
	if selected == nil {
		return nil, nil, reason
	}
	return selected, selectedTokenPolicy, nil
}

// compareEndpointRank compares the security of two endpoints by security level, then security mode,
// then security policy strength. Returns a positive number if a ranks above b, negative if below, or zero.
func compareEndpointRank(a, b *ua.EndpointDescription) int {
	if a.SecurityLevel != b.SecurityLevel {
		return int(a.SecurityLevel) - int(b.SecurityLevel)
	}
	if a.SecurityMode != b.SecurityMode {
		return int(a.SecurityMode) - int(b.SecurityMode)
	}
	return securityPolicyStrength(a.SecurityPolicyURI) - securityPolicyStrength(b.SecurityPolicyURI)
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
// The token policy with the strongest security policy is selected, so a token policy that encrypts the
// token is preferred over one that does not. A token policy with an unsupported security policy uri is never used.
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
	var selected *ua.UserTokenPolicy
	for i := range e.UserIdentityTokens {
		t := &e.UserIdentityTokens[i]
		if t.TokenType != tokenType {
			continue
		}
		if tokenType == ua.UserTokenTypeAnonymous {
			return t, nil
		}
		policyURI := tokenSecurityPolicyURI(t, e)
		switch securityPolicyStrength(policyURI) {
		case -1:
			// unsupported token security policy uri.
			continue
		case 0:
			// token is sent without encryption.
			if secret && e.SecurityMode != ua.MessageSecurityModeSignAndEncrypt && !ch.allowPlaintextCredentials {
				reason = ua.BadSecurityModeInsufficient
				continue
			}
		default:
			// token is encrypted (or signed) with the server certificate.
			if !isUsableCertificate(e.ServerCertificate, policyURI) {
				reason = ua.BadCertificateInvalid
				continue
			}
		}
		if selected == nil || userTokenStrength(t, e) > userTokenStrength(selected, e) {
			selected = t
		}
	}
	if selected == nil {
		return nil, reason
	}
	return selected, nil
}

// tokenSecurityPolicyURI returns the security policy uri used to encrypt or sign a user token.
// If the token policy does not specify one, the endpoint's security policy uri is used.
func tokenSecurityPolicyURI(t *ua.UserTokenPolicy, e *ua.EndpointDescription) string {
	if t.SecurityPolicyURI != "" {
		return t.SecurityPolicyURI
	}
	return e.SecurityPolicyURI
}

// userTokenStrength returns the strength of the security policy used to encrypt or sign the user token.
func userTokenStrength(t *ua.UserTokenPolicy, e *ua.EndpointDescription) int {
	if t.TokenType == ua.UserTokenTypeAnonymous {
		return 0
	}
	return securityPolicyStrength(tokenSecurityPolicyURI(t, e))
}

// securityPolicyStrength ranks the supported security policies, from 0 for None to 5 for the strongest.
// Returns -1 if the security policy is not supported.
func securityPolicyStrength(uri string) int {
	switch uri {
	case ua.SecurityPolicyURINone:
		return 0
	case ua.SecurityPolicyURIBasic128Rsa15:
		return 1
	case ua.SecurityPolicyURIBasic256:
		return 2
	case ua.SecurityPolicyURIBasic256Sha256:
		return 3
	case ua.SecurityPolicyURIAes128Sha256RsaOaep:
		return 4
	case ua.SecurityPolicyURIAes256Sha256RsaPss:
		return 5
	default:
		return -1
	}
}

// isUsableCertificate returns true if the certificate (or chain) can be parsed, and the leaf has an RSA public key
// at least as large as the security policy requires. Basic128Rsa15 and Basic256 require 1024 bits, and the other
// policies require 2048 bits. See https://reference.opcfoundation.org/v104/Core/docs/Part7/6.6/
func isUsableCertificate(certificate ua.ByteString, securityPolicyURI string) bool {
	certs, err := x509.ParseCertificates([]byte(certificate))
	if err != nil || len(certs) == 0 {
		return false
	}
	key, ok := certs[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		return false
	}
	minKeySize := 2048
	switch securityPolicyURI {
	case ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256:
		minKeySize = 1024
	}
	return key.N.BitLen() >= minKeySize
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
// Only endpoints that use the UA TCP transport are compared, in any order. See endpointsMatch for the fields compared.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.2/
func verifyServerEndpoints(discoveryEndpoints, sessionEndpoints []ua.EndpointDescription) error {
	// every discovered endpoint must be returned by the server.
outer1:
	for i := range discoveryEndpoints {
		d := &discoveryEndpoints[i]
		if !isUaTcpTransport(d.TransportProfileURI) {
			continue
		}
		for j := range sessionEndpoints {
			if s := &sessionEndpoints[j]; isUaTcpTransport(s.TransportProfileURI) && endpointsMatch(d, s) {
				continue outer1
			}
		}
		return ua.BadSecurityChecksFailed
	}
	// every endpoint returned by the server must have been discovered.
outer2:
	for j := range sessionEndpoints {
		s := &sessionEndpoints[j]
		if !isUaTcpTransport(s.TransportProfileURI) {
			continue
		}
		for i := range discoveryEndpoints {
			if d := &discoveryEndpoints[i]; isUaTcpTransport(d.TransportProfileURI) && endpointsMatch(d, s) {
				continue outer2
			}
		}
		return ua.BadSecurityChecksFailed
	}
	return nil
}

// endpointsMatch returns true if the security relevant fields of the discovered endpoint d are equal to the
// endpoint s returned by CreateSession: the security mode, security policy uri, security level, transport
// profile uri, and user token policies (in any order). The server certificate and the server's ApplicationURI
// are compared unless the server omitted them from s.
// The EndpointURL is not compared, as servers may return a different host name for the same endpoint,
// and the client always connects to the URL passed to Dial.
func endpointsMatch(d, s *ua.EndpointDescription) bool {
	if d.SecurityMode != s.SecurityMode ||
		d.SecurityPolicyURI != s.SecurityPolicyURI ||
		d.SecurityLevel != s.SecurityLevel ||
		d.TransportProfileURI != s.TransportProfileURI ||
		!sameUserTokenPolicies(d.UserIdentityTokens, s.UserIdentityTokens) {
		return false
	}
	// servers may omit the certificates from the endpoints returned in the CreateSessionResponse.
	// A certificate missing from discovery does not match, as an attacker may have removed it.
	if len(s.ServerCertificate) > 0 && d.ServerCertificate != s.ServerCertificate {
		return false
	}
	if s.Server.ApplicationURI != "" && d.Server.ApplicationURI != s.Server.ApplicationURI {
		return false
	}
	return true
}

// sameUserTokenPolicies returns true if the lists contain the same user token policies, in any order.
func sameUserTokenPolicies(a, b []ua.UserTokenPolicy) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
outer:
	for i := range a {
		for j := range b {
			if !used[j] && a[i] == b[j] {
				used[j] = true
				continue outer
			}
		}
		return false
	}
	return true
}
