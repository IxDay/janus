package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	ssh "golang.org/x/crypto/ssh/agent"

	"github.com/IxDay/janus/pkg/janus"
)

const (
	// EnvPrefix is prefix for all the environments variables (see 12 factor app).
	EnvPrefix = "JANUS"
)

var (
	command = &cobra.Command{
		Short: "SSH Agent with extension support",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// https://github.com/spf13/cobra/issues/340
			cmd.SilenceUsage = true

			return run()
		},
	}
)

func init() {
	flags := command.PersistentFlags()
	flags.BoolP("debug", "d", false, "Trigger debug logs")
	flags.BoolP("no-timestamp", "", false, "Disable timestamp on logs")

	viper.SetEnvPrefix(EnvPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	_ = viper.BindPFlag("debug", flags.Lookup("debug"))
	_ = viper.BindPFlag("no_timestamp", flags.Lookup("no-timestamp"))
}

func run() error {
	ctx := janus.WithInterrupt(context.Background())
	agent := janus.NewSSHAgent()
	cb := func(conn net.Conn) error {
		if err := ssh.ServeAgent(agent, conn); err != nil && err != io.EOF {
			return err
		}
		return nil
	}
	cfg, err := config()
	if err != nil {
		return err
	}
	logger, err := cfg.NewLogger()
	if err != nil {
		return err
	}
	logger.Debug("debug mode enabled")
	return listen(ctx, cb)
}

func main() {
	if err := command.Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

func config() (config Configuration, _ error) { return config, viper.Unmarshal(&config) }

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
