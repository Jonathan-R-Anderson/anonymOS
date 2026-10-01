package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sync"
)

// Releases: the channel pointer the OS update client polls (roadmap §3, §7).  What it serves is
// the wallet-signed manifest exactly as published -- this server cannot alter it without breaking
// the signature clients check, and cannot invent one.  Files themselves travel through the
// dendritic network (the manifest's locators); this only says what is current.
//
// Layout in the state directory: releases/<channel>/manifest.json + manifest.sig, written by
// `hos-release` through the upload endpoint (P3) or copied in by the operator.

var reChannel = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

type Releases struct {
	store *Store
	mu    sync.Mutex
}

func NewReleases(store *Store) *Releases { return &Releases{store: store} }

type releasePointer struct {
	Channel   string          `json:"channel"`
	Manifest  json.RawMessage `json:"manifest"`
	Signature string          `json:"signature"` // the wallet's EIP-191 signature, hex
}

func (rs *Releases) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/releases/{channel}", func(w http.ResponseWriter, r *http.Request) {
		ch := r.PathValue("channel")
		if !reChannel.MatchString(ch) {
			writeJSON(w, 400, map[string]string{"error": "invalid channel"})
			return
		}
		rs.mu.Lock()
		defer rs.mu.Unlock()
		var p releasePointer
		if err := rs.store.LoadJSON("releases/"+ch+"/current.json", &p); err != nil {
			writeJSON(w, 404, map[string]string{"error": "no release published on this channel"})
			return
		}
		writeJSON(w, 200, p)
	})
}
