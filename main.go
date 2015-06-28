package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

var (
	ldapServer   string
	ldapPort     uint16
	baseDN       string
	filter       string
	attributes   []string
	bindUser     string
	bindPassword string
	group        string
)

func authFailed(w http.ResponseWriter) {
}

func handelError(w http.ResponseWriter, err error) {
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	validate := func(ok bool, err error) bool {
		if err != nil {
			log.Println(err)
			http.Error(w, "Internal server error", 500)
			return false
		} else if !ok {
			w.Header().Add("WWW-Authenticate", `Basic realm="LDAP"`)
			http.Error(w, "Unauthorized", 401)
			return false
		}
		return true
	}

	username, password, ok := r.BasicAuth()
	if !validate(ok, nil) {
		return
	}

	l, err := LDAPConnectAndBind(ldapServer, ldapPort, bindUser, bindPassword)
	if !validate(true, err) {
		return
	}
	defer l.Close()

	ok, err = l.ValidateUser(username)
	if !validate(ok, err) {
		return
	}
	ok, err = l.AuthenticateUser(username, password)
	if !validate(ok, err) {
		return
	}
	ok, err = l.AuthorizeUser(username, group)
	if !validate(ok, err) {
		return
	}

	w.Header().Set("X-Accel-Redirect", "/protected/index.html")
	w.Header().Set("Content-Type", "1")
	w.WriteHeader(204)
}

func main() {
	ldapServer = os.Getenv("LDAP_URL")
	p, err := strconv.Atoi(os.Getenv("LDAP_PORT"))
	if err != nil {
		fmt.Printf("Invalid port '%s'", os.Getenv("LDAP_PORT"))
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
