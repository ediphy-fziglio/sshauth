// sshauthd: server side of sshauth (see sshauth.c for the protocol).
//
// For each connection it reads the request, validates it and starts the
// command. If either step fails it replies "ERR!". Otherwise it replies
// "OKAY" passing one end of a new socketpair as errfd, then:
//
//	socket -> command stdin
//	command stdout -> socket
//	command stderr -> errfd, as "TEXT" messages of at most 1024 bytes
//
// and finally sends "EXIT" on errfd. All stdout is written to the socket
// before EXIT, because the client exits as soon as it reads EXIT.
//
// Build: go build -o sshauthd ./cmd/sshauthd
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"syscall"

	"github.com/ediphy-fziglio/sshauth/sockcmdproto"
)

// validate decides whether the peer may run args. Returning an error
// rejects the request, and the error text is sent to the client.
func validate(cred *syscall.Ucred, args []string) ([]string, error) {
	if len(args) != 3 {
		return nil, fmt.Errorf("expected 3 arguments, got %d", len(args))
	}
	if args[0] != "git@github.com" {
		return nil, errors.New("wrong user/server")
	}
	switch args[1] {
	case "git-upload-pack", "git-receive-pack":
	default:
		return nil, fmt.Errorf("command not allowed %q", args[1])
	}
	args[2] = shellUnquote(args[2])
	if !safeArg.MatchString(args[2]) {
		return nil, fmt.Errorf("invalid argument %q", args[2])
	}
	args[2] = fmt.Sprintf("'%s'", args[2])
	return append([]string{"ssh"}, args...), nil
}

func shellUnquote(s string) string {
	if len(s) < 2 || s[0] != s[len(s)-1] || (s[0] != '\'' && s[0] != '"') {
		return s
	}
	return s[1 : len(s)-1]
}

// safeArg matches a non-empty string of [A-Za-z0-9._/-] not starting
// with "-", so it can't be taken as an option.
var safeArg = regexp.MustCompile(`^[A-Za-z0-9._/][A-Za-z0-9._/-]*$`)

func main() {
	sockPath := flag.String("socket", "/root/.ssh/sshauth.sock", "unix socket to listen on")
	flag.Parse()

	// Remove a socket left over by a previous run, but nothing else.
	if fi, err := os.Lstat(*sockPath); err == nil && fi.Mode()&os.ModeSocket != 0 {
		os.Remove(*sockPath)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: *sockPath, Net: "unix"})
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer conn.Close()
			if err := sockcmdproto.Serve(conn, validate); err != nil {
				log.Print(err)
			}
		}()
	}
}
