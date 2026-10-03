package sockcmdproto

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

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	maxCmd  = 4096
	maxMsg  = 1024
	version = 1
	// Time allowed for the client to send its request.
	requestTimeout = 10 * time.Second
)

type Validate = func(cred *syscall.Ucred, args []string) ([]string, error)

func Serve(conn *net.UnixConn, validate Validate) error {
	cred, err := peerCred(conn)
	if err != nil {
		return err
	}
	args, err := readRequest(conn)
	if err != nil {
		return fmt.Errorf("pid %d uid %d: %w", cred.Pid, cred.Uid, err)
	}
	//log.Printf("pid %d uid %d: %q", cred.Pid, cred.Uid, args)

	if len(args) == 0 {
		return sendErr(conn, "empty command")
	}
	if args, err = validate(cred, args); err != nil {
		return sendErr(conn, err.Error())
	}

	// The command gets plain pipes rather than the socket itself: its
	// output must not reach the socket before OKAY, and a dup of the
	// socket would be non-blocking, which commands don't expect.
	inR, inW, err := os.Pipe()
	if err != nil {
		return err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		closeAll(inR, inW)
		return err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		closeAll(inR, inW, outR, outW)
		return err
	}
	defer closeAll(inW, outR, errR)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	err = cmd.Start()
	closeAll(inR, outW, errW)
	if err != nil {
		return sendErr(conn, err.Error())
	}

	errfd, err := sendOkay(conn)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return err
	}
	defer errfd.Close()

	// stdin: runs until the client sends EOF or the socket is closed.
	go func() {
		io.Copy(inW, conn)
		inW.Close()
	}()

	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		if _, err := io.Copy(conn, outR); err != nil {
			// The client is gone: stop the command, and keep
			// draining in case something else holds the pipe.
			cmd.Process.Kill()
			io.Copy(io.Discard, outR)
		}
	}()

	// stderr is copied here; a failed write to errfd only stops the
	// copying, the command keeps running and its stderr is dropped.
	buf := make([]byte, 6+maxMsg)
	copy(buf, "TEXT")
	errfdOK := true
	for {
		n, err := errR.Read(buf[6:])
		if n > 0 && errfdOK {
			binary.BigEndian.PutUint16(buf[4:], uint16(n))
			if _, werr := errfd.Write(buf[:6+n]); werr != nil {
				errfdOK = false
			}
		}
		if err != nil {
			break
		}
	}
	<-outDone

	code := exitCode(cmd.Wait())
	msg := make([]byte, 8)
	copy(msg, "EXIT")
	binary.BigEndian.PutUint32(msg[4:], uint32(code))
	if _, err := errfd.Write(msg); err != nil {
		return fmt.Errorf("pid %d: sending EXIT: %w", cred.Pid, err)
	}
	return nil
}

func peerCred(conn *net.UnixConn) (*syscall.Ucred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *syscall.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err == nil {
		err = credErr
	}
	return cred, err
}

// readRequest reads "SSHA" | u16 version | u16 len | command line and
// returns the arguments, which the command line separates with NUL.
func readRequest(conn *net.UnixConn) ([]string, error) {
	conn.SetReadDeadline(time.Now().Add(requestTimeout))
	defer conn.SetReadDeadline(time.Time{})

	var hdr [8]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("reading request: %w", err)
	}
	if string(hdr[:4]) != "SSHA" {
		return nil, errors.New("bad request magic")
	}
	if v := binary.BigEndian.Uint16(hdr[4:]); v != version {
		return nil, fmt.Errorf("unsupported version %d", v)
	}
	n := binary.BigEndian.Uint16(hdr[6:])
	if n > maxCmd {
		return nil, fmt.Errorf("command line of %d bytes", n)
	}
	if n == 0 {
		return nil, nil
	}
	line := make([]byte, n)
	if _, err := io.ReadFull(conn, line); err != nil {
		return nil, fmt.Errorf("reading command line: %w", err)
	}
	return strings.Split(string(line), "\x00"), nil
}

// sendErr replies "ERR!" | u16 len | msg, truncating msg to maxMsg bytes.
func sendErr(conn *net.UnixConn, msg string) error {
	if len(msg) > maxMsg {
		msg = msg[:maxMsg]
	}
	buf := make([]byte, 6, 6+len(msg))
	copy(buf, "ERR!")
	binary.BigEndian.PutUint16(buf[4:], uint16(len(msg)))
	_, err := conn.Write(append(buf, msg...))
	return err
}

// sendOkay creates a socketpair, replies "OKAY" passing one end to the
// client and returns the other one.
func sendOkay(conn *net.UnixConn) (*os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, os.NewSyscallError("socketpair", err)
	}
	defer syscall.Close(fds[1])
	errfd := os.NewFile(uintptr(fds[0]), "errfd")
	if _, _, err := conn.WriteMsgUnix([]byte("OKAY"), syscall.UnixRights(fds[1]), nil); err != nil {
		errfd.Close()
		return nil, err
	}
	return errfd, nil
}

// exitCode returns the command's exit code, or 128 + the signal number
// when a signal killed it, as shells do.
func exitCode(err error) int32 {
	var ee *exec.ExitError
	if err == nil {
		return 0
	}
	if !errors.As(err, &ee) {
		return 255
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int32(ws.Signal())
	}
	return int32(ee.ExitCode())
}

func closeAll(files ...*os.File) {
	for _, f := range files {
		f.Close()
	}
}
