package main

import (
	"bufio"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/42wim/sagent/bech32"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const EnvSSHAuthSock = "SSH_AUTH_SOCK"

func main() {
	conn, err := net.Dial("unix", os.Getenv(EnvSSHAuthSock))
	if err != nil {
		log.Fatalf("failed to connect to agent: %q", err)
	}
	client, err := agent.NewClient(conn), err
	if err != nil {
		log.Fatalf("failed to instanciate client: %q", err)
	}
	str, err := os.Open("/home/max/.ssh/test.age")
	if err != nil {
		log.Fatalf("failed to read key file: %q", err)
	}
	ids, err := ParseIdentities(str)
	if err != nil {
		log.Fatalf("failed to parse identity: %q", err)
	}
	for _, i := range ids {
		key := ed25519.PrivateKey(append(i.secretKey, i.ourPublicKey...))
		pub, err := ssh.NewPublicKey(key.Public())
		if err != nil {
			log.Fatalf("failed to create ssh public key")
		}
		fmt.Printf("%s", ssh.MarshalAuthorizedKey(pub))
		added := agent.AddedKey{PrivateKey: key, Comment: "testing!"}
		if err := client.Add(added); err != nil {
			log.Fatalf("failed to push age key: %q", err)
		}
	}
}

type X25519Identity struct {
	secretKey, ourPublicKey []byte
}

func ParseIdentities(f io.Reader) (ids []*X25519Identity, _ error) {
	const privateKeySizeLimit = 1 << 24 // 16 MiB
	scanner := bufio.NewScanner(io.LimitReader(f, privateKeySizeLimit))
	var n int
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		i, err := ParseX25519Identity(line)
		if err != nil {
			return nil, fmt.Errorf("error at line %d: %v", n, err)
		}
		ids = append(ids, i)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read secret keys file: %v", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no secret keys found")
	}
	return ids, nil
}

func ParseX25519Identity(s string) (*X25519Identity, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	if t != "AGE-SECRET-KEY-" {
		return nil, fmt.Errorf("malformed secret key: unknown type %q", t)
	}
	r, err := newX25519IdentityFromScalar(k)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	return r, nil
}

// newX25519IdentityFromScalar returns a new X25519Identity from a raw Curve25519 scalar.
func newX25519IdentityFromScalar(secretKey []byte) (*X25519Identity, error) {
	if len(secretKey) != curve25519.ScalarSize {
		return nil, errors.New("invalid X25519 secret key")
	}
	i := &X25519Identity{
		secretKey: make([]byte, curve25519.ScalarSize),
	}
	copy(i.secretKey, secretKey)
	i.ourPublicKey, _ = curve25519.X25519(i.secretKey, curve25519.Basepoint)
	return i, nil
}
