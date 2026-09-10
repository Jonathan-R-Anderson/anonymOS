package ui

import (
	"net/http"
	"strings"

	"github.com/syndichan/maniwani/storage-client/internal/config"
)

// setPayout records where this node's CREDIT earnings should be sent.
//
// Validated before saving rather than at payout time: once rewards are
// committed to an epoch's Merkle root they are payable only to the address in
// the leaf, so a typo is unrecoverable. Refusing bad input here is the only
// place that can still help.
func (s *Server) setPayout(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	raw := strings.TrimSpace(r.FormValue("payout_address"))
	normalized, err := config.NormalizePayoutAddress(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if applyErr := s.cfgApply(func(c *config.Config) error {
		c.PayoutAddress = normalized
		return nil
	}); applyErr != nil {
		http.Error(w, applyErr.Error(), http.StatusBadRequest)
		return
	}
	if normalized == "" {
		s.logger.Printf("payout address cleared — this node will earn nothing until one is set")
	} else {
		s.logger.Printf("payout address set to %s", normalized)
	}
	http.Redirect(w, r, "/?saved=payout", http.StatusSeeOther)
}
