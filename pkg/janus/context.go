package janus

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
)

type interruptCtx struct {
	context.Context
	cancel      context.CancelFunc
	interrupted bool
}

var interrupt = make(chan os.Signal)
var contexts = []*interruptCtx{}
var Interrupted = errors.New("context interrupted")

func WithInterrupt(parent context.Context) context.Context {
	child := &interruptCtx{}
	child.Context, child.cancel = context.WithCancel(parent)

	contexts = append(contexts, child)

	return child
}

func (ctx *interruptCtx) Err() error {
	if ctx.interrupted {
		return Interrupted
	}
	return ctx.Context.Err()
}

func init() {
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interrupt
		os.Stdout.WriteString("\n")
		log.Printf("interruption")
		for _, ctx := range contexts {
			ctx.interrupted = true
			ctx.cancel()
		}
	}()
}
