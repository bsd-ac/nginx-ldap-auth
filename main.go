/*
 * Copyright (c) 2022 Aisha Tammy <aisha@bsd.ac>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"suah.dev/protect"

	ldap "github.com/go-ldap/ldap/v3"
)

///// loggers
var zlog *zap.Logger
var klog *zap.SugaredLogger

///// default config
var LDAPConfig = map[string]string{
	"X-LDAP-URL": "/tmp/slapd.sock",
	"X-LDAP-Scheme": "ldapi",
	"X-LDAP-Realm": "Resticted",
	"X-LDAP-Template": "mail=%[1]s@%[2]s",
	"X-LDAP-CookieName": "",
}

///// custom flag set
type unveilDirs []string

func (arr *unveilDirs) String() string {
	dirs := []string(*arr)
	return "[" + strings.Join(dirs, ", ") + "]"
}

func (arr *unveilDirs) Set(str string) error {
	*arr = append(*arr, str)
	return nil
}

func main() {
	var debugLevel, listenOn, outputFormat string
	var uDirs unveilDirs
	var uDirArr []string
	flag.StringVar(&debugLevel, "d", "warn", "debug level of output (debug, info, warn, error, dpanic, panic, fatal)")
	flag.StringVar(&listenOn, "l", ":8888", "listening socket (absolute path for unix socket)")
	flag.StringVar(&outputFormat, "o", "console", "debug output format (console, json)")
	flag.Var(&uDirs, "x", "extra directories to unveil")
	flag.Parse()
	uDirArr = []string(uDirs)

	var err error
	var zconf zap.Config
	var zlevel zapcore.Level
	var undoRedirect func()
	zconf = zap.NewProductionConfig()
	zconf.Encoding = outputFormat
	zlevel, err = zapcore.ParseLevel(debugLevel)
	if err != nil {
		log.Fatalf("ERROR: could not set debug level: %v", err)
	}
	zconf.Level = zap.NewAtomicLevelAt(zlevel)
	zlog, err = zconf.Build()
	if err != nil {
		log.Fatalf("ERROR: could not initialize logger: %v", err)
	}
	zap.ReplaceGlobals(zlog)
	klog = zlog.Sugar()
	undoRedirect, err = zap.RedirectStdLogAt(zlog, zapcore.DebugLevel)
	defer zlog.Sync()
	defer klog.Sync()
	defer undoRedirect()

	klog.Debugf("Securing with pledge and unveil")
	protect.Pledge("stdio unveil rpath wpath cpath flock dns inet tty unix tmppath")
	protect.Unveil("/etc/resolv.conf", "r")
	protect.Unveil("/etc/ssl/cert.pem", "r")
	protect.Unveil("/tmp", "rwx")
	for _, dir := range uDirArr {
		protect.Unveil(dir, "rwxc")
	}

	var listenSocket net.Listener
	var lType string
	if strings.HasPrefix(listenOn, "/") {
		lType = "unix"
		protect.Unveil(filepath.Dir(listenOn), "rwxc")
	} else {
		lType = "tcp"
	}
	listenSocket, err = net.Listen(lType, listenOn)
	if err != nil {
		klog.Fatalf("Could not create listener: %v", err)
	}
	protect.UnveilBlock()
	klog.Debugf("Finished securing")

	defer listenSocket.Close()
	defer os.Remove(listenOn)
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/", LDAPAuthHandler)
	server := &http.Server{Handler: serverMux}
	klog.Debugf("Starting to listen on '%s'", listenOn)
	go func() {
		err = server.Serve(listenSocket)
		if err != nil && err != http.ErrServerClosed {
			klog.Warnf("Failed while listening: %v", err)
		}
	}()

	sig := <-done
	klog.Infof("Caught signal '%v'", sig)
	klog.Infof("Shutting down...")
	server.Close()
}

func Reverse(data []string) {
	var l = len(data)
	for i := 0; i < l/2; i++ {
		data[i], data[l-i-1] = data[l-i-1], data[i]
	}
}

func ValidateEmail(address string) []interface{} {
	var err error
	var addr *mail.Address
	var ind int
	var localPart, domainPart, strVal string
	var domainSplit []string
	var retvalStr []string
	var retval []interface{}

	addr, err = mail.ParseAddress(address)
	if err != nil {
		return []interface{}{address}
	}
	ind = strings.LastIndex(addr.Address, "@")
	if ind < 0 {
		localPart = addr.Address
		domainPart = ""
	} else {
		localPart = addr.Address[:ind]
		domainPart = addr.Address[ind+1:]
		domainSplit = strings.Split(domainPart, ".")
		Reverse(domainSplit)
	}
	retvalStr = append([]string{localPart, domainPart}, domainSplit...)
	retval = make([]interface{}, len(retvalStr))
	for ind, strVal = range retvalStr {
		retval[ind] = strVal
	}
	return retval
}

func DecodeCredentials(data string) (string, string, error) {
	authBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", "", err
	}
	authString := string(authBytes)
	ind := strings.LastIndex(authString, ":")
	authCred := []string{}
	if ind < 0 {
		authCred = []string{authString, ""}
	} else {
		authCred = []string{authString[:ind], authString[ind+1:]}
	}
	return authCred[0], authCred[1], nil
}

func LDAPAuthHandler(res http.ResponseWriter, req *http.Request) {
	klog.Debugf("Got a connection")
	var err error
	var ind int
	var headers http.Header
	var cookies []*http.Cookie
	var cookie *http.Cookie
	var hkey, hval, encodedCredentials, decodedCredentials string
	var ldapURL, ldapScheme, ldapRealm, ldapTemplate, ldapCookieName string
	var authVal, connType string

	var username, ldapUsername, password string
	var userParams []interface{}
	var credentialBytes []byte
	var ldapConn *ldap.Conn

	switch req.Method {
	case http.MethodGet:
		{
		}
	default:
		klog.Warnf("Incorrect request type: %s", req.Method)
		goto unauthorized
	}

	headers = req.Header.Clone()
	cookies = req.Cookies()[:]
	for hkey, hval = range LDAPConfig {
		if headers.Get(hkey) == "" {
			headers.Set(hkey, hval)
		}
	}
	ldapURL = headers.Get("X-LDAP-URL")
	ldapScheme = headers.Get("X-LDAP-Scheme")
	ldapRealm = headers.Get("X-LDAP-Realm")
	ldapTemplate = headers.Get("X-LDAP-Template")
	ldapCookieName = headers.Get("X-LDAP-CookieName")

	encodedCredentials = ""
	if ldapCookieName != "" && cookies != nil && len(cookies) > 0 {
		for _, cookie = range cookies {
			if cookie.Name == ldapCookieName {
				encodedCredentials = cookie.Value
				break
			}
		}
	}
	if encodedCredentials == "" {
		authVal = headers.Get("Authorization")
		if authVal != "" && strings.HasPrefix(strings.ToLower(authVal), "basic ") {
			encodedCredentials = authVal[6:]
		}
	}
	username = ""
	password = ""
	credentialBytes, err = base64.StdEncoding.DecodeString(encodedCredentials)
	if err == nil {
		decodedCredentials = string(credentialBytes)
		ind = strings.LastIndex(decodedCredentials, ":")
		if ind < 0 {
			username = decodedCredentials
		} else {
			username = decodedCredentials[:ind]
			password = decodedCredentials[ind+1:]
		}
	}
	klog.Debugf("Got username: %s", username)

	connType = "tcp"
	if ldapScheme == "ldapi" {
		connType = "unix"
	}
	ldapConn, err = ldap.Dial(connType, ldapURL)

	if err == nil {
		klog.Debugf("Connected to LDAP server at: %s", ldapURL)
		userParams = ValidateEmail(username)

		ldapUsername = fmt.Sprintf(ldapTemplate, userParams...)

		klog.Debugf("Performing validation with DN: %s", ldapUsername)
		err = ldapConn.Bind(ldapUsername, password)
		if err == nil {
			res.WriteHeader(http.StatusOK)
			klog.Debugf("Request authorized")
			return
		} else {
			klog.Debugf("Could not validate credentials: %v", err)
		}
	} else {
		klog.Debugf("Could not open the connection: %v", err)
	}

unauthorized:
	res.Header().Set("Cache-Control", "no-cache")
	res.Header().Set("WWW-Authenticate", "Basic realm=\""+ldapRealm+"\"")
	res.WriteHeader(http.StatusUnauthorized)
	klog.Debugf("Could not authorize request")
}
