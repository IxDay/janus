package janus

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

type LogSignatureFlags agent.SignatureFlags

func (lsf LogSignatureFlags) String() string {
	out, underlying := "", agent.SignatureFlags(lsf)
	if underlying&agent.SignatureFlagReserved == agent.SignatureFlagReserved {
		out += "|reserved"
	}
	if underlying&agent.SignatureFlagRsaSha256 == agent.SignatureFlagRsaSha256 {
		out += "|rsa-sha256"
	}
	if underlying&agent.SignatureFlagRsaSha512 == agent.SignatureFlagRsaSha512 {
		out += "|rsa-sha256"
	}
	if out == "" {
		return "none"
	}
	return out[1:]
}
