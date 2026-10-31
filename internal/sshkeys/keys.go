// Package sshkeys handles OpenSSH keys and SSH logins to stations.
package sshkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

type PubKey struct {
	Type    string // ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256, ...
	Blob    string // base64
	Comment string
}

func (k PubKey) Line() string {
	s := k.Type + " " + k.Blob
	if k.Comment != "" {
		s += " " + k.Comment
	}
	return s
}

var knownTypes = map[string]bool{
	"ssh-ed25519":                        true,
	"ssh-rsa":                            true,
	"ssh-dss":                            true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
	"sk-ed25519@openssh.com":             true,
}

func ParseAuthorizedKeys(text string) ([]PubKey, error) {
	var keys []PubKey
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := ParseKeyLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", i+1, err)
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, errors.New("no keys given")
	}
	return keys, nil
}

func ParseKeyLine(line string) (PubKey, error) {
	f := strings.Fields(line)
	if len(f) < 2 {
		return PubKey{}, errors.New("expected \"type base64-key [comment]\"")
	}
	k := PubKey{Type: f[0], Blob: f[1], Comment: strings.Join(f[2:], " ")}
	if !knownTypes[k.Type] {
		return PubKey{}, fmt.Errorf("unknown key type %q", k.Type)
	}
	if err := validateBlob(k.Type, k.Blob); err != nil {
		return PubKey{}, err
	}
	return k, nil
}

func validateBlob(keyType, blob string) error {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return fmt.Errorf("key is not valid base64: %v", err)
	}
	if len(raw) < 4 {
		return errors.New("key is too short")
	}
	l := binary.BigEndian.Uint32(raw)
	if int(l) > len(raw)-4 {
		return errors.New("key is corrupt (bad length)")
	}
	if got := string(raw[4 : 4+l]); got != keyType {
		return fmt.Errorf("type %q does not match key data (%q)", keyType, got)
	}
	return nil
}

func MergeKeys(existing, adding []PubKey) []PubKey {
	seen := map[string]bool{}
	var out []PubKey
	add := func(ks []PubKey) {
		for _, k := range ks {
			id := k.Type + " " + k.Blob
			if !seen[id] {
				seen[id] = true
				out = append(out, k)
			}
		}
	}
	add(existing)
	add(adding)
	return out
}

// ParseDeviceAuthorizedKeys skips invalid lines instead of failing.
func ParseDeviceAuthorizedKeys(text string) []PubKey {
	var keys []PubKey
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, err := ParseKeyLine(line); err == nil {
			keys = append(keys, k)
		}
	}
	return keys
}

func GenerateEd25519(comment string) (privPEM string, pubLine string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", "", fmt.Errorf("cannot serialize the private key: %v", err)
	}
	privPEM = string(pem.EncodeToMemory(block))
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	pubLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		pubLine += " " + comment
	}
	return privPEM, pubLine, nil
}

func LoadPrivateKey(path, passphrase string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", path, err)
	}
	return ParsePrivateKeyBytes(data, passphrase)
}

func ParsePrivateKeyBytes(data []byte, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		signer, err := ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("passphrase rejected: %v", err)
		}
		return signer, nil
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, errors.New("key is encrypted — enter the passphrase")
		}
		return nil, err
	}
	return signer, nil
}
