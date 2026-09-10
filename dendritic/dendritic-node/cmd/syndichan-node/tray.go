//go:build tray

// Tray icon, built only with `-tags tray`.
//
// WHY A BUILD TAG. systray talks to the desktop's status-notifier over DBus and
// needs CGO on Linux and macOS. The release build is deliberately CGO_ENABLED=0
// and cross-compiles to six targets from one machine; linking this in
// unconditionally would break every one of those. Servers also have no tray at
// all -- syndichan-node runs headless in Kubernetes -- so the daemon must stay
// buildable and runnable without any of this.
//
// Closing the window has never stopped the node: it is a background service
// whose UI is just a local web page. The tray exists so that fact is VISIBLE,
// and so there is somewhere to click to get the dashboard back.
package main

import (
	"context"
	"log"
	"os/exec"
	"runtime"

	"fyne.io/systray"

	"github.com/syndichan/maniwani/storage-client/internal/ui"
)

func init() {
	runTray = startTray
}

func startTray(ctx context.Context, dashboardURL string, logger *log.Logger, shutdown func()) {
	go systray.Run(func() {
		systray.SetIcon(ui.IconPNG)
		systray.SetTitle("Syndichan")
		systray.SetTooltip("Syndichan storage node - running")

		open := systray.AddMenuItem("Open dashboard", dashboardURL)
		systray.AddSeparator()
		quit := systray.AddMenuItem("Quit", "Stop sharing and exit")

		go func() {
			for {
				select {
				case <-open.ClickedCh:
					if err := openBrowser(dashboardURL); err != nil {
						logger.Printf("could not open dashboard: %v", err)
					}
				case <-quit.ClickedCh:
					// Only this explicitly stops the node. Closing the window
					// does not, which is the whole point of the tray.
					systray.Quit()
					shutdown()
					return
				case <-ctx.Done():
					systray.Quit()
					return
				}
			}
		}()
	}, func() {})
}

func openBrowser(target string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", target).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
	default:
		return exec.Command("xdg-open", target).Start()
	}
}
