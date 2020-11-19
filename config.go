package main

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type (
	// Configuration hold the current fields to tune the application
	Configuration struct {
		Debug       bool
		NoTimestamp bool `mapstructure:"no_timestamp"`
	}
)

func (c Configuration) NewLogger() (*zap.Logger, error) {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	if !c.Debug {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	if c.NoTimestamp {
		config.EncoderConfig.TimeKey = zapcore.OmitKey
	}
	return config.Build()
}
