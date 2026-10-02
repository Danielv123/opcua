package server

import "github.com/awcullen/opcua/ua"

// UserNameIdentityAuthenticator authenticates AnonymousIdentity.
type AnonymousIdentityAuthenticator interface {
	// AuthenticateAnonymousIdentity returns nil when user identity is authenticated, or an error otherwise.
	// See UserNameIdentityAuthenticator for how errors are reported to the client, and for the applicationURI.
	AuthenticateAnonymousIdentity(userIdentity ua.AnonymousIdentity, applicationURI string, endpointURL string) error
}

// AuthenticateUserNameIdentityFunc authenticates AnonymousIdentity.
type AuthenticateAnonymousIdentityFunc func(userIdentity ua.AnonymousIdentity, applicationURI string, endpointURL string) error

// AuthenticateUserNameIdentity ...
func (f AuthenticateAnonymousIdentityFunc) AuthenticateAnonymousIdentity(userIdentity ua.AnonymousIdentity, applicationURI string, endpointURL string) error {
	return f(userIdentity, applicationURI, endpointURL)
}

// UserNameIdentityAuthenticator authenticates UserNameIdentity.
type UserNameIdentityAuthenticator interface {
	// AuthenticateUserNameIdentity returns nil when user identity is authenticated, or an error otherwise,
	// typically BadUserAccessDenied. If the error is (or wraps) a bad ua.StatusCode, that status code is
	// returned to the client. Any other error is logged by the server and the client receives BadUserAccessDenied.
	//
	// applicationURI is the application uri of the client, verified against the client certificate that was
	// authenticated by the secure channel. It is empty if the secure channel does not use security, because
	// the identity of the client application cannot be verified.
	AuthenticateUserNameIdentity(userIdentity ua.UserNameIdentity, applicationURI string, endpointURL string) error
}

// AuthenticateUserNameIdentityFunc authenticates UserNameIdentity.
type AuthenticateUserNameIdentityFunc func(userIdentity ua.UserNameIdentity, applicationURI string, endpointURL string) error

// AuthenticateUserNameIdentity ...
func (f AuthenticateUserNameIdentityFunc) AuthenticateUserNameIdentity(userIdentity ua.UserNameIdentity, applicationURI string, endpointURL string) error {
	return f(userIdentity, applicationURI, endpointURL)
}

// X509IdentityAuthenticator authenticates X509Identity.
type X509IdentityAuthenticator interface {
	// AuthenticateX509Identity returns nil when user is authenticated, or an error otherwise.
	// See UserNameIdentityAuthenticator for how errors are reported to the client, and for the applicationURI.
	AuthenticateX509Identity(userIdentity ua.X509Identity, applicationURI string, endpointURL string) error
}

// AuthenticateX509IdentityFunc authenticates X509Identity.
type AuthenticateX509IdentityFunc func(userIdentity ua.X509Identity, applicationURI string, endpointURL string) error

// AuthenticateX509Identity ...
func (f AuthenticateX509IdentityFunc) AuthenticateX509Identity(userIdentity ua.X509Identity, applicationURI string, endpointURL string) error {
	return f(userIdentity, applicationURI, endpointURL)
}

// IssuedIdentityAuthenticator authenticates user identities.
type IssuedIdentityAuthenticator interface {
	// AuthenticateIssuedIdentity returns nil when user is authenticated, or an error otherwise.
	// See UserNameIdentityAuthenticator for how errors are reported to the client, and for the applicationURI.
	AuthenticateIssuedIdentity(userIdentity ua.IssuedIdentity, applicationURI string, endpointURL string) error
}

// AuthenticateIssuedIdentityFunc authenticates user identities.
type AuthenticateIssuedIdentityFunc func(userIdentity ua.IssuedIdentity, applicationURI string, endpointURL string) error

// AuthenticateIssuedIdentity ...
func (f AuthenticateIssuedIdentityFunc) AuthenticateIssuedIdentity(userIdentity ua.IssuedIdentity, applicationURI string, endpointURL string) error {
	return f(userIdentity, applicationURI, endpointURL)
}
