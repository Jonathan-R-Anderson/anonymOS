//go:build !tray

package main

import (
	"context"
	"log"
)

// Without -tags tray the node is a headless daemon, which is how it runs on a
// server. Closing a window was never what stopped it.
func init() { runTray = nil }

var _ = func(context.Context, string, *log.Logger, func()) {}
