package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

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
	cfg, err := config()
	if err != nil {
		return err
	}
	logger, err := cfg.NewLogger()
	if err != nil {
		return err
	}
	logger.Debug("debug mode enabled")

	agent := janus.NewSSHAgent(logger)
	socket := os.Getenv(janus.EnvSSHAuthSock)

	logger.Info("start listening", zap.String("socket", socket))
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return errors.Wrap(err, "failed to open socket")
	}
	defer listener.Close()
	defer os.Remove(socket)

	go interrupt(logger, agent)
	return agent.Serve(listener)
}

func interrupt(logger *zap.Logger, agent *janus.SSHAgent) {
	ctx := janus.WithInterrupt(context.Background())
	<-ctx.Done()
	if ctx.Err() == janus.Interrupted {
		os.Stdout.WriteString("\n")
		logger.Info("interrupted")
	}
	agent.Close()
}

func main() {
	if err := command.Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

func config() (config Configuration, _ error) { return config, viper.Unmarshal(&config) }
