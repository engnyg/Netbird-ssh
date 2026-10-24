// Package NBSSHKit is the gomobile bridge used by the iOS app. It embeds a
// userspace NetBird peer (no Network Extension needed) and exposes an SSH
// client that can dial hosts through the NetBird overlay.
package NBSSHKit

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	netbird "github.com/netbirdio/netbird/client/embed"
)

// Dialer opens a TCP connection, optionally through the NetBird overlay.
type dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Network is an embedded NetBird peer running entirely inside the app process.
type Network struct {
	mu     sync.Mutex
	client *netbird.Client
	opts   netbird.Options
}

// NewNetwork prepares (but does not start) an embedded NetBird peer.
// setupKey may be empty if the peer was already registered earlier; the
// persisted config in dataDir is then reused.
func NewNetwork(deviceName, setupKey, managementURL, dataDir string) (*Network, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("dataDir is required")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	opts := netbird.Options{
		DeviceName:    deviceName,
		SetupKey:      setupKey,
		ManagementURL: managementURL,
		ConfigPath:    filepath.Join(dataDir, "netbird.json"),
		StatePath:     filepath.Join(dataDir, "netbird.state"),
		LogLevel:      "info",
	}
	return &Network{opts: opts}, nil
}

// Start registers with the management server and brings the tunnel up.
// timeoutSeconds bounds the initial connection.
func (n *Network) Start(timeoutSeconds int) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.client != nil {
		return nil
	}
	c, err := netbird.New(n.opts)
	if err != nil {
		return err
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 60
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		return fmt.Errorf("start netbird: %w", err)
	}
	n.client = c
	logrus.Info("netbird: started")
	return nil
}

// Stop tears the tunnel down.
func (n *Network) Stop() error {
	n.mu.Lock()
	c := n.client
	n.client = nil
	n.mu.Unlock()
	if c == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.Stop(ctx)
}

// IsRunning reports whether the tunnel is up.
func (n *Network) IsRunning() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.client != nil
}

// Peers returns one line per known peer: "fqdn|ip|status".
// Handy for populating a host picker from the NetBird network.
func (n *Network) Peers() (string, error) {
	n.mu.Lock()
	c := n.client
	n.mu.Unlock()
	if c == nil {
		return "", fmt.Errorf("netbird not started")
	}
	st, err := c.Status()
	if err != nil {
		return "", err
	}
	out := ""
	for _, p := range st.Peers {
		out += fmt.Sprintf("%s|%s|%s\n", p.FQDN, p.IP, p.ConnStatus.String())
	}
	return out, nil
}

func (n *Network) current() *netbird.Client {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.client
}
