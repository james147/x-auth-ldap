package main

import (
	"errors"
	"fmt"

	"gopkg.in/ldap.v1"
)

// Auth is an interface that describe how to validate, authenticate and autorize
// a user
type Auth interface {
	ValidateUser(username string) (bool, error)
	AuthenticateUser(username, password string) (bool, error)
	AuthorizeUser(username, group string) (bool, error)
	Close()
}

// LDAPAuth is an implmentation of Auth that is backed by an ldap server
type LDAPAuth struct {
	conn         *ldap.Conn
	bindUser     string
	bindPassword string
}

// LDAPConnectAndBind connects and binds to an ldap server
func LDAPConnectAndBind(server string, port uint16, bindUser, bindPassword string) (*LDAPAuth, error) {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
	if err != nil {
		return nil, err
	}

	err = l.Bind(bindUser, bindPassword)
	if err != nil {
		return nil, err
	}
	return &LDAPAuth{l, bindUser, bindPassword}, nil
}

// Close closes the connection to the ldap server
func (l *LDAPAuth) Close() {
	l.conn.Close()
}

// ValidateUser checks to see if the user exists
func (l *LDAPAuth) ValidateUser(username string) (bool, error) {
	filter = fmt.Sprintf("(&(uid=%s))", username)

	search := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil)

	sr, err := l.conn.Search(search)
	if err != nil {
		return false, err
	}

	if len(sr.Entries) == 0 {
		return false, nil
	} else if len(sr.Entries) > 1 {
		return false, fmt.Errorf("Found too many users: %d", len(sr.Entries))
	}

	return true, nil
}

// AuthenticateUser verifies the users password is valid by binding as that user
// before rebinding as the bind user. Returns an error only if it fails to
// rebind as the bind user otherwise return true if the user bind was
// successful, or false if it was not.
func (l *LDAPAuth) AuthenticateUser(username, password string) (bool, error) {
	usererr := l.conn.Bind(bindUser, bindPassword)
	rebinderr := l.conn.Bind(l.bindUser, l.bindPassword)
	if rebinderr != nil {
		return false, rebinderr
	}
	// It is not an error if the user fails to bind, just likley just invalid
	// password
	return usererr == nil, nil
}

// AuthorizeUser verifies the user belongs to the given group
func (l *LDAPAuth) AuthorizeUser(username, group string) (bool, error) {
	return false, errors.New("Not yet implmented")
}
