package main

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/pkg/errors"
	ssh "golang.org/x/crypto/ssh/agent"

	"github.com/IxDay/janus/pkg/janus"
)

func main() {
	ctx := janus.WithInterrupt(context.Background())
	agent := janus.NewSSHAgent()
	cb := func(conn net.Conn) error {
		if err := ssh.ServeAgent(agent, conn); err != nil && err != io.EOF {
			return err
		}
		return nil
	}
	if err := listen(ctx, cb); err != nil {
		log.Printf("failed to listen: %q", err)
		os.Exit(1)
	}
}

func listen(ctx context.Context, cb func(net.Conn) error) error {
	syscall.Umask(0077)
	listener, err := net.Listen("unix", os.Getenv(janus.EnvSSHAuthSock))
	if err != nil {
		return errors.Wrap(err, "failed to open socket")
	}
	defer listener.Close()
	defer os.Remove(os.Getenv(janus.EnvSSHAuthSock))
	log.Printf("start listening")
	conns, errs := accept(listener)
	for {
		select {
		case <-ctx.Done():
			if err := ctx.Err(); err == janus.Interrupted {
				return nil
			} else {
				return errors.Wrap(ctx.Err(), "stop listening")
			}
		case conn := <-conns:
			go func(conn net.Conn) {
				if err := cb(conn); err != nil {
					errs <- err
				}
			}(conn)
		case err := <-errs:
			return errors.Wrap(err, "unexpected error")
		}
	}
}

func accept(listener net.Listener) (chan net.Conn, chan error) {
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
	return conns, errs
}
