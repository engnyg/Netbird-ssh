package NBSSHKit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	nbssh "github.com/netbirdio/netbird/client/ssh"
)

const dialTimeout = 30 * time.Second

// HostKeyHandler is implemented by the app (Swift). It is asked whether an
// unknown or changed host key should be trusted, like Termius / OpenSSH's
// "authenticity of host can't be established" prompt.
type HostKeyHandler interface {
	// Verify is called with the host, key type (e.g. "ssh-ed25519") and SHA256
	// fingerprint. knownFingerprint is empty on first connect, or the previously
	// trusted fingerprint when the key changed. Return true to trust.
	Verify(host, keyType, fingerprint, knownFingerprint string) bool
}

// SessionListener receives terminal output. Callbacks come from a Go thread.
type SessionListener interface {
	OnData(data []byte)
	OnClose(reason string)
}

// AuthConfig carries credentials for one connection.
type AuthConfig struct {
	Password   string
	PrivateKey string // PEM, optional
	Passphrase string // for PrivateKey, optional
	// KnownFingerprint is the SHA256 fingerprint previously trusted for this
	// host ("" on first connect).
	KnownFingerprint string
}

// Session is one interactive SSH shell.
type Session struct {
	mu       sync.Mutex
	client   *ssh.Client
	pty      *nbssh.PTYSession
	listener SessionListener
	closed   bool
}

// NewSession creates an unconnected session.
func NewSession(listener SessionListener) *Session {
	return &Session{listener: listener}
}

// Connect dials host:port and performs the SSH handshake. If network is non-nil
// and viaNetbird is true the TCP connection goes through the NetBird overlay,
// otherwise through the regular device network.
func (s *Session) Connect(network *Network, viaNetbird bool, host string, port int, user string, auth *AuthConfig, hk HostKeyHandler) error {
	if auth == nil {
		auth = &AuthConfig{}
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	methods, err := authMethods(auth)
	if err != nil {
		return err
	}

	var nbVerify func(addr string, key []byte) error
	var d dialer = &net.Dialer{Timeout: dialTimeout}
	if viaNetbird {
		if network == nil || network.current() == nil {
			return errors.New("NetBird is not connected")
		}
		c := network.current()
		d = c
		nbVerify = c.VerifySSHHostKey
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: hostKeyCallback(host, auth.KnownFingerprint, nbVerify, hk),
		Timeout:         dialTimeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	client, err := nbssh.Handshake(ctx, conn, addr, cfg)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.client = client
	s.mu.Unlock()
	return nil
}

// Start opens a PTY shell and starts pumping output to the listener.
func (s *Session) Start(cols, rows int) error {
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	if client == nil {
		return errors.New("not connected")
	}
	pty, err := nbssh.StartPTYSession(client, cols, rows)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.pty = pty
	s.mu.Unlock()

	var wg sync.WaitGroup
	pump := func(r io.Reader) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				s.listener.OnData(chunk)
			}
			if err != nil {
				return
			}
		}
	}
	wg.Add(2)
	go pump(pty.Stdout)
	go pump(pty.Stderr)
	go func() {
		err := pty.Session.Wait()
		wg.Wait()
		reason := ""
		var exit *ssh.ExitError
		switch {
		case err == nil:
			reason = "Connection closed"
		case errors.As(err, &exit):
			reason = fmt.Sprintf("Process exited with status %d", exit.ExitStatus())
		default:
			reason = err.Error()
		}
		s.shutdown()
		s.listener.OnClose(reason)
	}()
	return nil
}

// Write sends user input (keystrokes, paste) to the remote shell.
func (s *Session) Write(data []byte) error {
	s.mu.Lock()
	pty := s.pty
	s.mu.Unlock()
	if pty == nil {
		return errors.New("session not started")
	}
	_, err := pty.Stdin.Write(data)
	return err
}

// Resize informs the remote PTY of a new terminal size.
func (s *Session) Resize(cols, rows int) error {
	s.mu.Lock()
	pty := s.pty
	s.mu.Unlock()
	if pty == nil {
		return errors.New("session not started")
	}
	return pty.Session.WindowChange(rows, cols)
}

// Close terminates the session and the underlying connection.
func (s *Session) Close() { s.shutdown() }

func (s *Session) shutdown() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	pty, client := s.pty, s.client
	s.mu.Unlock()
	if pty != nil {
		_ = pty.Session.Close()
	}
	if client != nil {
		_ = client.Close()
	}
}

func authMethods(a *AuthConfig) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if a.PrivateKey != "" {
		signer, _, err := parseSigner([]byte(a.PrivateKey), a.Passphrase)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if a.Password != "" {
		pw := a.Password
		methods = append(methods, ssh.Password(pw))
		// Many servers only offer keyboard-interactive for password logins.
		methods = append(methods, ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			}))
	}
	if len(methods) == 0 {
		return nil, errors.New("no credentials: set a password or private key")
	}
	return methods, nil
}

// hostKeyCallback trusts, in order: a key matching NetBird's own record of the
// peer, a key matching the fingerprint the user previously accepted, and
// otherwise whatever the app's HostKeyHandler decides (trust on first use).
func hostKeyCallback(host, known string, nbVerify func(string, []byte) error, hk HostKeyHandler) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		if nbVerify != nil {
			for _, a := range []string{hostname, remoteHost(remote)} {
				if a != "" && nbVerify(a, key.Marshal()) == nil {
					return nil
				}
			}
		}
		if known != "" && known == fp {
			return nil
		}
		if hk != nil && hk.Verify(host, key.Type(), fp, known) {
			return nil
		}
		if known != "" {
			return fmt.Errorf("host key for %s changed (%s)", host, fp)
		}
		return fmt.Errorf("host key for %s not trusted (%s)", host, fp)
	}
}

func remoteHost(a net.Addr) string {
	if a == nil {
		return ""
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return ""
	}
	return h
}

// RunCommand executes a single command and returns its combined output. Used
// for e.g. installing a public key into authorized_keys.
func (s *Session) RunCommand(command string) ([]byte, error) {
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	if client == nil {
		return nil, errors.New("not connected")
	}
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	var out bytes.Buffer
	sess.Stdout, sess.Stderr = &out, &out
	err = sess.Run(command)
	return out.Bytes(), err
}
