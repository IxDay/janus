package janus

import (
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

func NewClient() (agent.ExtendedAgent, error) {
	conn, err := net.Dial("unix", os.Getenv(EnvSSHAuthSock))
	if err != nil {
		return nil, err
	}
	return agent.NewClient(conn), err
}
