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
// user token policy is selected. If a candidate that ranks above or equal to the selected endpoint has a missing or
// unusable server certificate, for the channel or for its user token policy, selection fails, rather than falling
// back to a weaker endpoint or user token policy, since the server may omit certificates from the endpoints returned
// by CreateSession, which are later compared with the discovery response.
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
		// An attacker may remove the certificate to force a weaker endpoint, so fail rather than skip it.
		if e.SecurityMode != ua.MessageSecurityModeNone && !isUsableCertificate(e.ServerCertificate, e.SecurityPolicyURI) {
			return nil, nil, ua.BadCertificateInvalid
		}
		tokenPolicy, err := ch.selectUserTokenPolicy(e)
		if err != nil {
			// the server certificate needed to encrypt the user token is missing or unusable.
			if err == ua.BadCertificateInvalid {
				return nil, nil, err
			}
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
// automatically and the user identity carries credentials, since on a channel without security an on-path
// attacker can relay the (encrypted or signed) user token to the server to take over the session.
// Opening a secured channel requires a client certificate. Otherwise it is MessageSecurityModeNone.
func (ch *Client) effectiveMinSecurityMode() ua.MessageSecurityMode {
	if ch.minSecurityMode != ua.MessageSecurityModeInvalid {
		return ch.minSecurityMode
	}
	if ch.securityPolicyURI == ua.SecurityPolicyURIBestAvailable && ch.securityMode == ua.MessageSecurityModeInvalid {
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
// If the server certificate needed to encrypt the secret is missing or unusable for a token policy stronger than
// the selected one, selection fails with BadCertificateInvalid, rather than falling back to a weaker token policy.
// An X509 identity's token is signed with the identity's key, which must be large enough for the token policy.
// For an IssuedIdentity, only token policies with the same IssuedTokenType and IssuerEndpointURL as the first
// IssuedToken policy are considered, since the token data is only valid for one token type.
func (ch *Client) selectUserTokenPolicy(e *ua.EndpointDescription) (*ua.UserTokenPolicy, error) {
	var tokenType ua.UserTokenType
	var secret bool
	var signingKey *rsa.PrivateKey
	switch ui := ch.userIdentity.(type) {
	case ua.UserNameIdentity:
		tokenType, secret = ua.UserTokenTypeUserName, true
	case ua.IssuedIdentity:
		tokenType, secret = ua.UserTokenTypeIssuedToken, true
	case ua.X509Identity:
		tokenType, signingKey = ua.UserTokenTypeCertificate, ui.Key
	default:
		tokenType = ua.UserTokenTypeAnonymous
	}
	var reason error = ua.BadIdentityTokenRejected
	var first, selected *ua.UserTokenPolicy
	certificateRejected := -1 // strength of the strongest token policy rejected because of the server certificate
	for i := range e.UserIdentityTokens {
		t := &e.UserIdentityTokens[i]
		if t.TokenType != tokenType {
			continue
		}
		if tokenType == ua.UserTokenTypeAnonymous {
			return t, nil
		}
		if first == nil {
			first = t
		} else if tokenType == ua.UserTokenTypeIssuedToken && (t.IssuedTokenType != first.IssuedTokenType || t.IssuerEndpointURL != first.IssuerEndpointURL) {
			continue
		}
		policyURI := tokenSecurityPolicyURI(t, e)
		strength := securityPolicyStrength(policyURI)
		switch {
		case strength < 0:
			// unsupported token security policy uri.
			continue
		case strength == 0:
			// token is sent without encryption.
			if secret && e.SecurityMode != ua.MessageSecurityModeSignAndEncrypt && !ch.allowPlaintextCredentials {
				reason = ua.BadSecurityModeInsufficient
				continue
			}
		default:
			// a secret is encrypted with the server certificate.
			if secret && !isUsableCertificate(e.ServerCertificate, policyURI) {
				if strength > certificateRejected {
					certificateRejected = strength
				}
				continue
			}
			// the X509 identity's key signs the token, so it must be large enough for the policy.
			if signingKey != nil && signingKey.N.BitLen() < minRSAKeySize(policyURI) {
				continue
			}
		}
		if selected == nil || strength > userTokenStrength(selected, e) {
			selected = t
		}
	}
	// an attacker may remove the server certificate to force a weaker token policy.
	if certificateRejected >= 0 && (selected == nil || certificateRejected > userTokenStrength(selected, e)) {
		return nil, ua.BadCertificateInvalid
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
// at least as large as the security policy requires.
func isUsableCertificate(certificate ua.ByteString, securityPolicyURI string) bool {
	certs, err := x509.ParseCertificates([]byte(certificate))
	if err != nil || len(certs) == 0 {
		return false
	}
	key, ok := certs[0].PublicKey.(*rsa.PublicKey)
	return ok && key.N.BitLen() >= minRSAKeySize(securityPolicyURI)
}

// minRSAKeySize returns the minimum RSA key size in bits that the security policy requires.
// Basic128Rsa15 and Basic256 require 1024 bits, and the other policies require 2048 bits.
// See https://reference.opcfoundation.org/v104/Core/docs/Part7/6.6/
func minRSAKeySize(securityPolicyURI string) int {
	switch securityPolicyURI {
	case ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256:
		return 1024
	default:
		return 2048
	}
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
	if len(s.ServerCertificate) > 0 && !sameLeafCertificate(d.ServerCertificate, s.ServerCertificate) {
		return false
	}
	if s.Server.ApplicationURI != "" && d.Server.ApplicationURI != s.Server.ApplicationURI {
		return false
	}
	return true
}

// sameLeafCertificate returns true if the certificates have the same leaf certificate.
// A certificate may be sent with or without its chain of issuer certificates.
func sameLeafCertificate(a, b ua.ByteString) bool {
	if a == b {
		return true
	}
	ca, err := x509.ParseCertificates([]byte(a))
	if err != nil || len(ca) == 0 {
		return false
	}
	cb, err := x509.ParseCertificates([]byte(b))
	if err != nil || len(cb) == 0 {
		return false
	}
	return ca[0].Equal(cb[0])
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
