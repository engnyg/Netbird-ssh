package NBSSHKit

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestGenerateAndParseKeys(t *testing.T) {
	for _, typ := range []string{"ed25519", "ecdsa", "rsa"} {
		if typ == "rsa" && testing.Short() {
			continue
		}
		for _, pass := range []string{"", "s3cret"} {
			k, err := GenerateKey(typ, "me@phone", pass)
			if err != nil {
				t.Fatalf("%s: %v", typ, err)
			}
			if k.Encrypted != (pass != "") || !strings.HasPrefix(k.Fingerprint, "SHA256:") {
				t.Fatalf("%s bad info: %+v", typ, k)
			}
			if pass != "" {
				if _, err := ParsePrivateKey(k.PrivateKey, ""); err == nil || !strings.HasPrefix(err.Error(), "passphrase required") {
					t.Fatalf("expected passphrase error, got %v", err)
				}
			}
			p, err := ParsePrivateKey(k.PrivateKey, pass)
			if err != nil {
				t.Fatalf("%s parse: %v", typ, err)
			}
			if p.Fingerprint != k.Fingerprint || p.Type != typ {
				t.Fatalf("%s mismatch: %+v vs %+v", typ, p, k)
			}
		}
	}
	if _, err := ParsePrivateKey("garbage", ""); err == nil {
		t.Fatal("expected error")
	}
}

type recorder struct {
	mu     sync.Mutex
	data   strings.Builder
	closed chan string
}

func (r *recorder) OnData(b []byte)       { r.mu.Lock(); r.data.Write(b); r.mu.Unlock() }
func (r *recorder) OnClose(reason string) { r.closed <- reason }
func (r *recorder) String() string        { r.mu.Lock(); defer r.mu.Unlock(); return r.data.String() }

type hk struct {
	answer bool
	calls  int
	fp     string
}

func (h *hk) Verify(host, keyType, fp, known string) bool { h.calls++; h.fp = fp; return h.answer }

// startServer runs a tiny SSH server that accepts one public key, echoes
// stdin with a prefix, and exits on 'q'.
func startServer(t *testing.T, authorized ssh.PublicKey) (addr string, hostFP string) {
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if string(k.Marshal()) == string(authorized.Marshal()) {
				return nil, nil
			}
			return nil, ssh.ErrNoAuth
		},
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) == "hunter2" {
				return nil, nil
			}
			return nil, ssh.ErrNoAuth
		},
	}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c, cfg)
		}
	}()
	return ln.Addr().String(), ssh.FingerprintSHA256(hostSigner.PublicKey())
}

func serve(c net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range creqs {
				if r.Type == "pty-req" || r.Type == "shell" || r.Type == "window-change" {
					r.Reply(true, nil)
				} else {
					r.Reply(false, nil)
				}
			}
		}()
		go func() {
			ch.Write([]byte("welcome\r\n"))
			buf := make([]byte, 256)
			for {
				n, err := ch.Read(buf)
				if err != nil {
					return
				}
				if buf[0] == 'q' {
					ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
					ch.Close()
					return
				}
				ch.Write(append([]byte("echo:"), buf[:n]...))
			}
		}()
	}
}

func hostPort(t *testing.T, addr string) (string, int) {
	h, p, _ := net.SplitHostPort(addr)
	var port int
	for _, c := range p {
		port = port*10 + int(c-'0')
	}
	return h, port
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timeout")
}

func TestSessionKeyAuthAndTOFU(t *testing.T) {
	key, err := GenerateKey("ed25519", "t", "")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(key.PublicKey))
	addr, hostFP := startServer(t, pub)
	host, port := hostPort(t, addr)

	// Rejected host key -> connection fails.
	rec := &recorder{closed: make(chan string, 1)}
	s := NewSession(rec)
	deny := &hk{answer: false}
	if err := s.Connect(nil, false, host, port, "u", &AuthConfig{PrivateKey: key.PrivateKey}, deny); err == nil || deny.calls != 1 {
		t.Fatalf("expected rejection, err=%v calls=%d", err, deny.calls)
	}

	// Accepted -> shell works end to end.
	s = NewSession(rec)
	allow := &hk{answer: true}
	if err := s.Connect(nil, false, host, port, "u", &AuthConfig{PrivateKey: key.PrivateKey}, allow); err != nil {
		t.Fatal(err)
	}
	if allow.fp != hostFP {
		t.Fatalf("fingerprint mismatch %s != %s", allow.fp, hostFP)
	}
	if err := s.Start(80, 24); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return strings.Contains(rec.String(), "welcome") })
	if err := s.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return strings.Contains(rec.String(), "echo:hi") })
	if err := s.Resize(120, 40); err != nil {
		t.Fatal(err)
	}
	s.Write([]byte("q"))
	select {
	case r := <-rec.closed:
		if !strings.Contains(r, "status 0") && r != "Connection closed" {
			t.Fatalf("unexpected close reason %q", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no close")
	}

	// Known fingerprint skips the prompt; wrong one is refused as "changed".
	s = NewSession(&recorder{closed: make(chan string, 1)})
	never := &hk{}
	if err := s.Connect(nil, false, host, port, "u", &AuthConfig{PrivateKey: key.PrivateKey, KnownFingerprint: hostFP}, never); err != nil || never.calls != 0 {
		t.Fatalf("known fp should be trusted silently: %v calls=%d", err, never.calls)
	}
	s.Close()
	s = NewSession(&recorder{closed: make(chan string, 1)})
	if err := s.Connect(nil, false, host, port, "u", &AuthConfig{PrivateKey: key.PrivateKey, KnownFingerprint: "SHA256:other"}, never); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("expected changed-key error, got %v", err)
	}
}

func TestSessionPassword(t *testing.T) {
	key, _ := GenerateKey("ed25519", "", "")
	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(key.PublicKey))
	addr, _ := startServer(t, pub)
	host, port := hostPort(t, addr)
	s := NewSession(&recorder{closed: make(chan string, 1)})
	if err := s.Connect(nil, false, host, port, "u", &AuthConfig{Password: "wrong"}, &hk{answer: true}); err == nil {
		t.Fatal("wrong password should fail")
	}
	s = NewSession(&recorder{closed: make(chan string, 1)})
	if err := s.Connect(nil, false, host, port, "u", &AuthConfig{Password: "hunter2"}, &hk{answer: true}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := s.Connect(nil, true, host, port, "u", &AuthConfig{Password: "x"}, nil); err == nil {
		t.Fatal("netbird not running should fail")
	}
	if err := NewSession(nil).Connect(nil, false, host, port, "u", &AuthConfig{}, nil); err == nil {
		t.Fatal("no creds should fail")
	}
}

func TestNewNetworkCreatesLogs(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewNetwork("dev", "", "https://example.invalid:443", dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(LogDir(dir), "crash.log")); err != nil {
		t.Fatalf("crash.log missing: %v", err)
	}
	n, _ := NewNetwork("dev", "", "https://example.invalid:443", dir)
	if n.HasIdentity() {
		t.Fatal("fresh dir must have no identity")
	}
	if err := n.Start(1); err == nil || !strings.Contains(err.Error(), "not signed in") {
		t.Fatalf("expected not-signed-in error, got %v", err)
	}
}
