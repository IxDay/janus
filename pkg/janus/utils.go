package janus

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

type StringerFunc func() string

func (s StringerFunc) String() string { return s() }

func marshal(key ssh.PublicKey) fmt.Stringer {
	return StringerFunc(func() string {
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	})
}

func marshalPrivate(key interface{}) fmt.Stringer {
	return StringerFunc(func() string {
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return fmt.Sprint(key)
		}
		return marshal(signer.PublicKey()).String()
	})
}
