package main

import (
	"context"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// safego runs fn in a new goroutine with a recover that logs the panic instead
// of tearing down the process. Every long-lived background goroutine in the
// worker and serve pods goes through here: an unrecovered panic in one of them
// (the Ladybug rebuild reads ClickHouse and the graph engine on every boot) kills
// the whole single-binary process, which on this platform means a restart loop
// rather than a degraded subsystem.
//
// name identifies the goroutine in the panic log line.
func safego(ctx context.Context, name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.FromContext(ctx).Error().Str("goroutine", name).Interface("panic", r).
					Msg("background goroutine panicked — recovered, subsystem is now stopped")
			}
		}()
		fn()
	}()
}
