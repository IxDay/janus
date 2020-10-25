package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io/ioutil"
	"log"
	"sync"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type SSHAgent struct {
	mu   sync.RWMutex
	keys map[string]*sshKey
	pass []byte
}

type sshKey struct {
	signer  ssh.Signer
	comment string
	pk      interface{}
}

var ErrLocked = errors.New("agent locked")

func NewSSHAgent() *SSHAgent { return &SSHAgent{keys: map[string]*sshKey{}} }

func (s *SSHAgent) List() (keys []*agent.Key, err error) {
	log.Println("List()")
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
	log.Println("Sign()")
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.pass != nil {
		return nil, ErrLocked
	}

	wanted := key.Marshal()
	for _, k := range s.keys {
		if bytes.Equal(k.signer.PublicKey().Marshal(), wanted) {
			log.Println("Found a matching key", k.comment, "for", key)
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
	log.Println("Add()", key.Comment)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pass != nil {
		return ErrLocked
	}

	signer, err := ssh.NewSignerFromKey(key.PrivateKey)
	if err != nil {
		log.Fatalf("newsignerfromkey failed: %s", err)
	}
	s.keys[sshFingerprint(signer.PublicKey())] = &sshKey{
		signer:  signer,
		comment: key.Comment,
		pk:      key.PrivateKey,
	}
	return nil
}

func (s *SSHAgent) Remove(key ssh.PublicKey) error {
	log.Println("Remove()", key)
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
	log.Println("RemoveAll()")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pass != nil {
		return ErrLocked
	}
	s.keys = map[string]*sshKey{}
	return nil
}

func (s *SSHAgent) Lock(passphrase []byte) error {
	log.Println("Lock()")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pass != nil {
		return ErrLocked
	}
	s.pass = passphrase
	return nil
}

func (s *SSHAgent) Unlock(passphrase []byte) error {
	log.Println("Unlock()")
	s.mu.Lock()
	defer s.mu.Unlock()
	if !bytes.Equal(passphrase, s.pass) {
		return ErrLocked
	}
	s.pass = nil
	return nil
}

func (s *SSHAgent) Signers() (out []ssh.Signer, _ error) {
	log.Println("Signers()")
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
	if extensionType != "decrypt@age-tool.com" {
		return nil, agent.ErrExtensionUnsupported
	}
	headers, _, err := Parse(bytes.NewBuffer(contents))
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

	return nil, agent.ErrExtensionUnsupported
}

func sshFingerprint(pk ssh.PublicKey) string {
	h := sha256.Sum256(pk.Marshal())
	return EncodeToString(h[:4])
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
