package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"gopkg.in/ldap.v1"
)

var (
	ldapServer   string
	ldapPort     uint16
	baseDN       string
	filter       string
	attributes   []string
	bindUser     string
	bindPassword string
)

func authFailed(w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", `Basic realm="LDAP"`)
	http.Error(w, "Unauthorized", 401)
}

func handelError(w http.ResponseWriter, err error) {
	log.Println(err)
	http.Error(w, "Internal server error", 500)
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		authFailed(w)
		return
	}

	// Bind to ldap server
	l, err := connect(bindUser, bindPassword)
	if err != nil {
		handelError(w, err)
		return
	}
	defer l.Close()

	// See if the user exists
	user, err := findUser(l, username)
	if err != nil {
		handelError(w, err)
		return
	}

	if user == nil {
		authFailed(w)
		return
	}

	// Validate users password
	userconn, err := connect(user.DN, password)
	if err != nil {
		authFailed(w)
		return
	}
	userconn.Close()

	// Validate user is in correct group
	// TODO

	w.Header().Set("X-Accel-Redirect", "/protected"+r.URL.RequestURI())
	w.Header().Set("Content-Type", "1")
	w.WriteHeader(204)
}

func main() {
	ldapServer = os.Getenv("LDAP_URL")
	p, err := strconv.Atoi(os.Getenv("LDAP_PORT"))
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	ldapPort = uint16(p)
	baseDN = os.Getenv("LDAP_BASE_DN")
	attributes = []string{"dn", "cn", "uid", "memberOf"}
	bindUser = os.Getenv("LDAP_BIND_USERNAME")
	bindPassword = os.Getenv("LDAP_BIND_PASSWORD")

	http.HandleFunc("/", handleAuth)
	http.ListenAndServe(":8080", nil)
}

func connect(bindUser, bindPassword string) (*ldap.Conn, error) {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapServer, ldapPort))
	if err != nil {
		return nil, err
	}

	err = l.Bind(bindUser, bindPassword)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func findUser(l *ldap.Conn, username string) (*ldap.Entry, error) {
	filter = fmt.Sprintf("(&(uid=%s))", username)

	search := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil)

	sr, err := l.Search(search)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) == 0 {
		return nil, nil
	} else if len(sr.Entries) > 1 {
		return nil, fmt.Errorf("Found too many users: %d", len(sr.Entries))
	}

	return sr.Entries[0], nil
}
