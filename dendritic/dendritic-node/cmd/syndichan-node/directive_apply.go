package main

import (
	"log"

	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/directive"
)

// originURLs are the settings that point at the origin, and are therefore the
// ones a move has to carry with it. Named individually rather than found by
// scanning the config, because "any field containing a URL" would also catch
// the management page, the SAM bridge and the I2P proxy -- all of which are
// local and must never follow a directive anywhere.
func originURLs(cfg *config.Config) map[string]*string {
	return map[string]*string{
		"gateway registration API": &cfg.Gateway.RegistrationAPI,
		"validator origin":         &cfg.Gateway.Validator.OriginURL,
		"content gateway origin":   &cfg.Gateway.Content.OriginURL,
		// Only when the operator SET it. An unset value resolves to
		// computeimage.DefaultBaseURL, a compiled-in constant that no directive
		// can move — the same property heartbeat.Endpoint has, and for the same
		// reason: a node that could be told where to download executable images
		// by something it received over the network would be trusting the wrong
		// half of the pair. The digest is what makes the download safe, and the
		// digest is compiled in.
		"compute image source": &cfg.Compute.ImageBaseURL,
	}
}

// applyDirective rewrites this node's origin-derived URLs to follow a move.
//
// IN MEMORY ONLY -- the config file on disk is left alone. That is deliberate:
// the file is what an operator edits and reads, and silently rewriting it would
// mean a directive that turned out to be wrong could not be undone by putting
// the old value back. The directive store is the record of the move; the config
// stays the record of what the operator chose.
func applyDirective(cfg *config.Config, store *directive.Store,
	held *directive.Directive, logger *log.Logger) {

	if held == nil || held.Kind != directive.KindMove || held.OriginDomain == "" {
		return
	}

	// Everything this node has ever been told is the origin: what it was
	// installed with, plus every domain adopted since. The install-time value
	// has to stay, or a directive moving the network BACK -- the ordinary
	// outcome of a registrar dispute being resolved -- would match nothing.
	installed := ""
	if len(cfg.NetworkDirective.Sources) > 0 {
		installed = cfg.NetworkDirective.Sources[0]
	}
	if installed == "" {
		installed = cfg.Gateway.RegistrationAPI
	}
	known := directive.KnownOrigins(installed, store.Domains())

	fields := originURLs(cfg)
	current := make(map[string]string, len(fields))
	for what, target := range fields {
		current[what] = *target
	}

	plan := directive.Plan(held, known, current)
	if len(plan) == 0 {
		logger.Printf("network directive: sequence %d names %s, and nothing in "+
			"this config points at a previous origin -- no URLs changed",
			held.Sequence, held.OriginDomain)
		return
	}
	for _, step := range plan {
		if target, ok := fields[step.What]; ok {
			*target = step.To
		}
		// Logged one line per change, at every start. This is the record an
		// operator reads when a node is talking to somewhere they did not
		// expect, and a summary count would not answer that question.
		logger.Printf("network directive: %s %s -> %s", step.What, step.From, step.To)
	}

	// The directive sources move too. A node that kept polling only the old
	// domain would be asking a host that may be gone whether it has moved --
	// and would never hear about the NEXT move.
	for i, source := range cfg.NetworkDirective.Sources {
		if updated, changed := directive.RewriteOrigin(source, known, held.OriginDomain); changed {
			logger.Printf("network directive: source %s -> %s", source, updated)
			cfg.NetworkDirective.Sources[i] = updated
		}
	}
}
