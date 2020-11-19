package janus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"io/ioutil"
	"net"
	"sync"

	"github.com/pkg/errors"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/IxDay/janus/internal"
)

type SSHAgent struct {
	mu      sync.RWMutex
	keys    map[string]*sshKey
	pass    []byte
	logger  *zap.Logger
	context context.Context
	cancel  context.CancelFunc
}

type sshKey struct {
	signer  ssh.Signer
	comment string
	pk      interface{}
}

var ErrLocked = errors.New("agent locked")
var ErrInternal = errors.New("internal error")

const ExtensionAge = "decrypt@age-tool.com"

const EnvSSHAuthSock = "SSH_AUTH_SOCK"

func NewSSHAgent(logger *zap.Logger) *SSHAgent {
	ctx, cancel := context.WithCancel(context.Background())
	return &SSHAgent{keys: map[string]*sshKey{}, logger: logger,
		context: ctx, cancel: cancel,
	}
}

func (s *SSHAgent) Close() { s.cancel() }

func (s *SSHAgent) Serve(listener net.Listener) error {
	conns, errs := make(chan net.Conn), make(chan error)
	go func() {
		for {
			if conn, err := listener.Accept(); err != nil {
				errs <- err
			} else {
				conns <- conn
			}
		}
	}()
	for {
		select {
		case <-s.context.Done():
			if err := s.context.Err(); err == context.Canceled {
				return nil
			} else {
				return errors.Wrap(s.context.Err(), "stop listening")
			}
		case conn := <-conns:
			s.logger.Info("receiving new connection")
			go func(conn net.Conn) {
				if err := agent.ServeAgent(s, conn); err != nil && err != io.EOF {
					errs <- err
				}
			}(conn)
		case err := <-errs:
			return errors.Wrap(err, "unexpected error")
		}
	}

}

func (s *SSHAgent) List() (keys []*agent.Key, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.pass != nil {
		return
	}

	var ids []*agent.Key
	for _, k := range s.keys {
		pub := k.signer.PublicKey()
		ids = append(ids, &agent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: k.comment})
	}
	return ids, nil
}

func (s *SSHAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return s.SignWithFlags(key, data, 0)
}

func (s *SSHAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	s.logger.Debug("signing key", zap.Uint32("flags", uint32(flags)),
		zap.ByteString("key", key.Marshal()))
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.pass != nil {
		return nil, ErrLocked
	}

	wanted := key.Marshal()
	for _, k := range s.keys {
		if bytes.Equal(k.signer.PublicKey().Marshal(), wanted) {
			s.logger.Debug("found a matching key", zap.String("comment", k.comment))
		}
		sig, err := k.signer.Sign(rand.Reader, data)
		if err != nil {
			return sig, err
		}
		return sig, err
	}
	return nil, errors.New("not found")
}

func (s *SSHAgent) Add(key agent.AddedKey) error {
	s.logger.Debug("adding new key", zap.String("comment", key.Comment))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pass != nil {
		return ErrLocked
	}

	signer, err := ssh.NewSignerFromKey(key.PrivateKey)
	if err != nil {
		s.logger.Error("newsignerfromkey failed", zap.Error(err))
	}
	s.keys[sshFingerprint(signer.PublicKey())] = &sshKey{
		signer:  signer,
		comment: key.Comment,
		pk:      key.PrivateKey,
	}
	return nil
}

func (s *SSHAgent) Remove(key ssh.PublicKey) error {
	s.logger.Debug("removing a key", zap.ByteString("key", key.Marshal()))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pass != nil {
		return ErrLocked
	}

	hash := sshFingerprint(key)
	if _, ok := s.keys[hash]; ok {
		delete(s.keys, hash)
	}
	return nil
}

func (s *SSHAgent) RemoveAll() error {
	s.logger.Debug("removing all keys")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pass != nil {
		return ErrLocked
	}
	s.keys = map[string]*sshKey{}
	return nil
}

func (s *SSHAgent) Lock(passphrase []byte) error {
	s.logger.Debug("locking agent")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pass != nil {
		return ErrLocked
	}
	s.pass = passphrase
	return nil
}

func (s *SSHAgent) Unlock(passphrase []byte) error {
	s.logger.Debug("unlocking agent")
	s.mu.Lock()
	defer s.mu.Unlock()
	if !bytes.Equal(passphrase, s.pass) {
		return ErrLocked
	}
	s.pass = nil
	return nil
}

func (s *SSHAgent) Signers() (out []ssh.Signer, _ error) {
	s.logger.Debug("returning signers")
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.pass != nil {
		return out, nil
	}
	for _, key := range s.keys {
		out = append(out, key.signer)
	}
	return
}

func (s *SSHAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != ExtensionAge {
		s.logger.Error("unsupported extension", zap.String("type", extensionType))
		return nil, agent.ErrExtensionUnsupported
	}
	headers, _, err := internal.Parse(bytes.NewBuffer(contents))
	if err != nil {
		return nil, err
	}
	for _, stanza := range headers.Recipients {
		switch stanza.Type {
		case "ssh-ed25519":
			if key, ok := s.keys[stanza.Args[0]]; ok {
				id, err := identity(key.pk)
				if err != nil {
					return nil, err
				}
				reader, err := age.Decrypt(bytes.NewBuffer(contents), id)
				if err != nil {
					return nil, err
				}
				return ioutil.ReadAll(reader)
			}
		}
	}

	return nil, ErrInternal
}

func sshFingerprint(pk ssh.PublicKey) string {
	h := sha256.Sum256(pk.Marshal())
	return internal.EncodeToString(h[:4])
}

func identity(key interface{}) (age.Identity, error) {
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		return agessh.NewEd25519Identity(*k)
	case *rsa.PrivateKey:
		return agessh.NewRSAIdentity(k)
	default:
		return nil, nil
	}
}
