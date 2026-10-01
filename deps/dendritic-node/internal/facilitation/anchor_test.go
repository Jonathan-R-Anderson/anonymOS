package facilitation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEpochAnchorCountsFromTheChainsOrigin(t *testing.T) {
	// Genesis was submitted as epoch 0 at this instant.
	anchor := EpochAnchor{Epoch: 0, At: 1_770_000_000, Seconds: 3600}

	cases := []struct {
		name string
		at   int64
		want uint64
	}{
		{"the anchor instant is the genesis epoch", 1_770_000_000, 0},
		{"one second before the first boundary", 1_770_003_599, 0},
		{"the first boundary", 1_770_003_600, 1},
		{"a day later", 1_770_000_000 + 24*3600, 24},
	}
	for _, tc := range cases {
		if got := anchor.EpochAt(time.Unix(tc.at, 0)); got != tc.want {
			t.Errorf("%s: EpochAt = %d, want %d", tc.name, got, tc.want)
		}
	}

	// A clock behind the anchor must not count backwards into epochs that
	// never existed — it audits the first epoch instead.
	if got := anchor.EpochAt(time.Unix(1_000_000_000, 0)); got != 0 {
		t.Errorf("a clock before genesis gave epoch %d, want 0", got)
	}
}

func TestEpochAnchorDoesNotShareTheClockNumbering(t *testing.T) {
	// The bug this exists to prevent: a node counting unix/3600 asks the chain
	// about an epoch five hundred thousand ahead of anything it holds.
	now := time.Unix(1_785_000_000, 0)
	anchor := EpochAnchor{Epoch: 0, At: 1_784_996_400, Seconds: 3600}
	if EpochAt(now) == anchor.EpochAt(now) {
		t.Fatal("clock-derived and anchored numbering agree; the test is not exercising the gap")
	}
	if got := anchor.EpochAt(now); got != 1 {
		t.Errorf("anchored epoch = %d, want 1", got)
	}
}

func TestIncompleteAnchorIsRefused(t *testing.T) {
	// Half an anchor is worse than none: a zero length divides by zero and a
	// zero timestamp puts genesis in 1970.
	for _, a := range []EpochAnchor{
		{Epoch: 0, At: 0, Seconds: 3600},
		{Epoch: 0, At: 1_770_000_000, Seconds: 0},
	} {
		if a.Valid() {
			t.Errorf("%+v reported itself valid", a)
		}
	}
}

func TestFetchEpochAnchorWaitsForGenesis(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"armed":false,"error":"Genesis has not been armed yet."}`))
	}))
	defer server.Close()

	if _, err := NewGatewayClient(server.URL).FetchEpochAnchor(context.Background()); err == nil {
		t.Fatal("an unarmed network produced an anchor; it must produce an error instead")
	}
}

func TestFetchEpochAnchorReadsThePublishedOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"armed":true,"epoch":0,"epoch_anchor":1770000000,"epoch_seconds":3600}`))
	}))
	defer server.Close()

	anchor, err := NewGatewayClient(server.URL).FetchEpochAnchor(context.Background())
	if err != nil {
		t.Fatalf("FetchEpochAnchor: %v", err)
	}
	if anchor.At != 1_770_000_000 || anchor.Seconds != 3600 || anchor.Epoch != 0 {
		t.Fatalf("anchor = %+v, want {0 1770000000 3600}", anchor)
	}
}
