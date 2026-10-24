package NBSSHKit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KeyInfo describes an SSH key pair. Fields are plain strings so gomobile can
// expose them to Swift.
type KeyInfo struct {
	// PrivateKey is the OpenSSH-format private key (PEM). Empty for ParsePublicKey.
	PrivateKey string
	// PublicKey is the authorized_keys line, e.g. "ssh-ed25519 AAAA... comment".
	PublicKey string
	// Fingerprint is the SHA256 fingerprint ("SHA256:...").
	Fingerprint string
	// Type is "ed25519", "rsa" or "ecdsa".
	Type string
	// Encrypted is true if the private key is passphrase protected.
	Encrypted bool
}

// GenerateKey creates a new key pair. keyType is "ed25519" (default), "rsa"
// (4096 bit) or "ecdsa" (P-256). passphrase may be empty.
func GenerateKey(keyType, comment, passphrase string) (*KeyInfo, error) {
	var priv interface{}
	var err error
	switch strings.ToLower(keyType) {
	case "", "ed25519":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		keyType = "ed25519"
	case "rsa":
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
	case "ecdsa":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported key type %q", keyType)
	}
	if err != nil {
		return nil, err
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}

	var block *pem.Block
	if passphrase != "" {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, comment, []byte(passphrase))
	} else {
		block, err = ssh.MarshalPrivateKey(priv, comment)
	}
	if err != nil {
		return nil, err
	}
	pemBytes := string(pem.EncodeToMemory(block))

	return &KeyInfo{
		PrivateKey:  pemBytes,
		PublicKey:   authorizedKey(signer.PublicKey(), comment),
		Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		Type:        strings.ToLower(keyType),
		Encrypted:   passphrase != "",
	}, nil
}

// ParsePrivateKey validates an imported private key (OpenSSH, PKCS#1, PKCS#8,
// EC; optionally encrypted) and derives its public half. For an encrypted key
// with a missing/incorrect passphrase it returns an error whose message starts
// with "passphrase required" so the UI can prompt.
func ParsePrivateKey(pemData, passphrase string) (*KeyInfo, error) {
	signer, encrypted, err := parseSigner([]byte(pemData), passphrase)
	if err != nil {
		return nil, err
	}
	return &KeyInfo{
		PrivateKey:  pemData,
		PublicKey:   authorizedKey(signer.PublicKey(), ""),
		Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		Type:        keyTypeName(signer.PublicKey().Type()),
		Encrypted:   encrypted,
	}, nil
}

func parseSigner(pemData []byte, passphrase string) (ssh.Signer, bool, error) {
	signer, err := ssh.ParsePrivateKey(pemData)
	if err == nil {
		return signer, false, nil
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if passphrase == "" {
			return nil, true, errors.New("passphrase required")
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pemData, []byte(passphrase))
		if err != nil {
			return nil, true, fmt.Errorf("passphrase required: %w", err)
		}
		return signer, true, nil
	}
	return nil, false, fmt.Errorf("invalid private key: %w", err)
}

func authorizedKey(pub ssh.PublicKey, comment string) string {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if comment != "" {
		line += " " + comment
	}
	return line
}

func keyTypeName(t string) string {
	switch {
	case strings.Contains(t, "ed25519"):
		return "ed25519"
	case strings.Contains(t, "rsa"):
		return "rsa"
	case strings.Contains(t, "ecdsa"):
		return "ecdsa"
	}
	return t
}
