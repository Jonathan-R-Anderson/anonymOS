package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/syndichan/maniwani/storage-client/internal/config"
)

// Running without a browser.
//
// The management page is convenient on a laptop and useless on a rented server:
// it binds loopback by default and may only be moved to a PRIVATE address, and
// only with a ui_password (see config.validateDashboard) — so an operator with
// only SSH into a public host cannot reach it at all, and should not want to.
//
// So every setting lives in the config JSON and can be edited with any text
// editor, and the handful that people actually change on first run have flags.
// The dashboard is one way to write that file, never the only way.

type headlessFlags struct {
	payout     string
	capacityGB float64
	uiListen   string
	showConfig bool
	printPath  bool
}

func registerHeadlessFlags() *headlessFlags {
	f := &headlessFlags{}
	flag.StringVar(&f.payout, "payout", "",
		"payout address for CREDIT earnings (0x…); saved to the config and used from then on")
	flag.Float64Var(&f.capacityGB, "capacity-gib", 0,
		"disk to donate, in GiB; 0 leaves the configured value alone")
	flag.StringVar(&f.uiListen, "ui-listen", "",
		`management page address; "off" disables it entirely for headless servers`)
	flag.BoolVar(&f.showConfig, "show-config", false,
		"print the effective configuration and exit")
	flag.BoolVar(&f.printPath, "config-path", false,
		"print the config file path and exit")
	return f
}

// applyHeadlessFlags folds the flags into the config and saves if anything
// changed. Returns true when the caller should exit (a query-only flag).
func applyHeadlessFlags(f *headlessFlags, cfg *config.Config, path string) (bool, error) {
	if f.printPath {
		fmt.Println(path)
		return true, nil
	}

	changed := false
	if f.payout != "" {
		normalized, err := config.NormalizePayoutAddress(f.payout)
		if err != nil {
			// Refused rather than saved-and-warned: a typo here sends every
			// reward this node ever earns to an address nobody controls.
			return true, fmt.Errorf("--payout: %w", err)
		}
		if normalized != cfg.PayoutAddress {
			cfg.PayoutAddress = normalized
			changed = true
		}
	}
	if f.capacityGB > 0 {
		capacity := int64(f.capacityGB * (1 << 30))
		if capacity != cfg.CapacityBytes {
			cfg.CapacityBytes = capacity
			changed = true
		}
	}
	if f.uiListen != "" {
		value := strings.TrimSpace(f.uiListen)
		if strings.EqualFold(value, "off") || strings.EqualFold(value, "none") {
			value = ""
		}
		if value != cfg.UIListen {
			cfg.UIListen = value
			changed = true
		}
	}

	if changed {
		if err := config.Save(path, *cfg, cfg.ResolvedRole()); err != nil {
			return true, fmt.Errorf("could not save %s: %w", path, err)
		}
		fmt.Fprintf(os.Stderr, "saved %s\n", path)
	}

	if f.showConfig {
		encoded, err := json.MarshalIndent(redactedConfig(*cfg), "", "  ")
		if err != nil {
			return true, err
		}
		fmt.Println(string(encoded))
		return true, nil
	}
	return false, nil
}

// redactedConfig blanks the secrets before printing. `--show-config` is the
// thing an operator pastes into a support thread, and these authenticate their
// storage gateway and — when the dashboard is on a LAN address — every setting
// on this node.
func redactedConfig(cfg config.Config) config.Config {
	if cfg.SecretKey != "" {
		cfg.SecretKey = "(hidden — see the config file)"
	}
	if cfg.UIPassword != "" {
		cfg.UIPassword = "(hidden — see the config file)"
	}
	return cfg
}

// headlessSummary is what a server operator needs to see at startup, since they
// have no dashboard to look at.
func headlessSummary(cfg config.Config, path string) string {
	payout := cfg.PayoutAddress
	if payout == "" {
		payout = "NOT SET — this node will earn nothing (use --payout 0x…)"
	}
	ui := cfg.UIListen
	switch {
	case ui == "":
		ui = "disabled"
	case !config.ListenIsLoopback(ui):
		ui += " (reachable from your local network, password required)"
	}
	return fmt.Sprintf("config %s | payout %s | dashboard %s", path, payout, ui)
}
