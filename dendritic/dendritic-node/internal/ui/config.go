package ui

import (
	"crypto/subtle"
	"github.com/syndichan/maniwani/storage-client/internal/compute"
	"net/http"
	"strconv"
	"strings"

	"github.com/syndichan/maniwani/storage-client/internal/config"
)

// This file makes the management page the single place a node is configured:
// storage, the volunteer gateway, and Docker facilitation (DCS) are all edited
// here and persisted to config.json. The node launches with no posture flags --
// the config file, edited from this page, decides everything.

// SetConfigAccess wires the dashboard to the live configuration. snapshot returns
// a copy of the current config; apply loads the current config, runs the mutator,
// validates for the resolved role, persists it, and updates the in-memory copy.
// Kept off New() so existing callers/tests are unaffected.
func (s *Server) SetConfigAccess(snapshot func() config.Config, apply func(func(*config.Config) error) error) {
	s.cfgSnapshot = snapshot
	s.cfgApply = apply
}

func (s *Server) hasConfig() bool { return s.cfgSnapshot != nil && s.cfgApply != nil }

// checkToken is the CSRF comparison on its own; a mismatch is a hard 403.
//
// Split from checkCSRF because those were two guards in one: "this request came
// from our own page" and "this node has an editable config file". They are
// unrelated, and a handler that is not editing configuration — settling a
// channel, say — should not be refused because no config file is loaded.
func (s *Server) checkToken(w http.ResponseWriter, r *http.Request) bool {
	if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrf)) != 1 {
		http.Error(w, "invalid request token", http.StatusForbidden)
		return false
	}
	return true
}

// checkCSRF guards every mutating CONFIG handler: the token, and that there is
// a config to edit.
func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	if !s.checkToken(w, r) {
		return false
	}
	if !s.hasConfig() {
		http.Error(w, "configuration is not editable here", http.StatusBadRequest)
		return false
	}
	return true
}

func formBool(r *http.Request, name string) bool {
	switch strings.ToLower(strings.TrimSpace(r.FormValue(name))) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

func formInt(r *http.Request, name string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(r.FormValue(name)))
	if err != nil {
		return fallback
	}
	return v
}

// setRunMode changes what the node runs (storage | gateway-only | probe-only).
// It takes effect on the next start, because switching modes opens or closes the
// shard store, I2P and the S3 gateway -- not something to do under a live process.
func (s *Server) setRunMode(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	mode := strings.TrimSpace(r.FormValue("run_mode"))
	switch mode {
	case "storage", string(config.RoleGatewayOnly), string(config.RoleProbeOnly):
	default:
		http.Error(w, "unknown run mode", http.StatusBadRequest)
		return
	}
	if err := s.cfgApply(func(c *config.Config) error {
		c.RunMode = mode
		return nil
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.logger.Printf("run mode set to %q (effective next start)", mode)
	http.Redirect(w, r, "/?saved=mode", http.StatusSeeOther)
}

// setGateway edits the volunteer-gateway configuration.
func (s *Server) setGateway(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	err := s.cfgApply(func(c *config.Config) error {
		c.Gateway.Enabled = formBool(r, "gateway_enabled")
		c.Gateway.ProbeEnabled = formBool(r, "gateway_probe")
		if v := strings.TrimSpace(r.FormValue("gateway_listen")); v != "" {
			c.Gateway.ListenAddress = v
		}
		c.Gateway.ListenPort = formInt(r, "gateway_port", c.Gateway.ListenPort)
		c.Gateway.PublicHostname = strings.TrimSpace(r.FormValue("gateway_hostname"))
		if v := strings.TrimSpace(r.FormValue("gateway_registration")); v != "" {
			c.Gateway.RegistrationAPI = v
		}
		if v := strings.TrimSpace(r.FormValue("gateway_tls_mode")); v != "" {
			c.Gateway.TLS.Mode = v
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.logger.Printf("gateway configuration updated (effective next start)")
	http.Redirect(w, r, "/?saved=gateway", http.StatusSeeOther)
}

// setStorageSettings edits the storage/S3 posture that used to be flags
// (-s3-listen, -cache-only, -tls-cert/-tls-key).
func (s *Server) setStorageSettings(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	draining := formBool(r, "draining")
	err := s.cfgApply(func(c *config.Config) error {
		c.CacheOnly = formBool(r, "cache_only")
		c.Draining = draining
		c.S3Listen = strings.TrimSpace(r.FormValue("s3_listen"))
		c.TLSCert = strings.TrimSpace(r.FormValue("tls_cert"))
		c.TLSKey = strings.TrimSpace(r.FormValue("tls_key"))
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Draining takes effect NOW, unlike everything else on this form. The rest of
	// these settings change what the node is; this one starts a process that ends
	// with the machine being switched off, and telling an operator who has just
	// asked to retire a node that it will begin at the next restart would mean the
	// node kept accepting shards for as long as they left it running.
	if node, ok := s.node.(interface{ SetDraining(bool) }); ok && node != nil {
		node.SetDraining(draining)
	}
	if draining {
		s.logger.Printf("draining: this node is being retired -- watch for the drain report before switching it off")
	}
	s.logger.Printf("storage/S3 settings updated (effective next start)")
	http.Redirect(w, r, "/?saved=storage", http.StatusSeeOther)
}

// setRouter edits the payment-routing role.
func (s *Server) setRouter(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	err := s.cfgApply(func(c *config.Config) error {
		c.Router.Enabled = formBool(r, "router_enabled")
		c.Router.PrivateRoutingOnly = formBool(r, "router_private_only")
		c.Router.WatchtowerEnabled = formBool(r, "router_watchtower")
		c.Router.Operator = strings.TrimSpace(r.FormValue("router_operator"))
		c.Router.FaultDomain = strings.TrimSpace(r.FormValue("router_fault_domain"))
		c.Router.MaxChannels = formInt(r, "router_max_channels", c.Router.MaxChannels)
		c.Router.MaxInFlight = formInt(r, "router_max_inflight", c.Router.MaxInFlight)
		c.Router.MinTimelockBlocks = formInt(r, "router_min_timelock", c.Router.MinTimelockBlocks)
		c.Router.TotalCommittedMax = int64(formInt(r, "router_total_max", int(c.Router.TotalCommittedMax)))
		c.Router.MinChannelCapacity = int64(formInt(r, "router_min_channel", int(c.Router.MinChannelCapacity)))
		c.Router.MaxChannelCapacity = int64(formInt(r, "router_max_channel", int(c.Router.MaxChannelCapacity)))
		c.Router.BaseFeeMilli = int64(formInt(r, "router_base_fee", int(c.Router.BaseFeeMilli)))
		c.Router.ProportionalFeePPM = int64(formInt(r, "router_prop_fee", int(c.Router.ProportionalFeePPM)))
		c.Router = c.Router.Normalise()
		// Say why a configured router will not be selected, rather than letting
		// the operator discover it through silence.
		if c.Router.Enabled {
			if ok, why := c.Router.CanRoute(); !ok {
				s.logger.Printf("router enabled but not routable: %s", why)
			}
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.logger.Printf("router configuration updated (effective next start)")
	http.Redirect(w, r, "/?saved=router", http.StatusSeeOther)
}

// setCompute edits what this machine lends to the compute network.
//
// The two device switches are independent of Enabled, and all three are read
// from the form rather than inferred. An operator who unticks "lend the GPU"
// must end up with OfferGPU false even though compute is still on — inferring
// one from the other is how a checkbox comes to mean something other than what
// it says.
func (s *Server) setCompute(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	err := s.cfgApply(func(c *config.Config) error {
		c.Compute.Enabled = formBool(r, "compute_enabled")
		c.Compute.OfferCPU = formBool(r, "offer_cpu")
		c.Compute.OfferGPU = formBool(r, "offer_gpu")
		c.Compute.IdleOnly = formBool(r, "compute_idle_only")
		c.Compute.ReserveCores = formInt(r, "compute_reserve_cores", c.Compute.ReserveCores)
		c.Compute.MaxCores = formInt(r, "compute_max_cores", c.Compute.MaxCores)
		c.Compute.MaxTempC = formInt(r, "compute_max_temp", c.Compute.MaxTempC)
		c.Compute.Hours = strings.TrimSpace(r.FormValue("compute_hours"))
		c.Compute.MicroVMKernel = strings.TrimSpace(r.FormValue("compute_vm_kernel"))
		c.Compute.MicroVMRootFS = strings.TrimSpace(r.FormValue("compute_vm_rootfs"))
		// Say why arbitrary code is or is not available, rather than leaving the
		// operator to infer it from work never arriving.
		if c.Compute.Enabled {
			if ok, why := c.Compute.CanRunArbitrary(
				compute.Probe(compute.Options{SkipBenchmark: true}).MicroVM.Isolated()); !ok {
				s.logger.Printf("compute: catalogue images only — %s", why)
			} else {
				s.logger.Printf("compute: arbitrary code enabled (microVM isolation)")
			}
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.logger.Printf("compute configuration updated (effective next start)")
	http.Redirect(w, r, "/?saved=compute", http.StatusSeeOther)
}

// setDCS edits Docker facilitation: whether this node runs containers for the
// network, its limits, and (for a website's bridge) the loopback deploy API.
func (s *Server) setDCS(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	err := s.cfgApply(func(c *config.Config) error {
		c.DCS.Enabled = formBool(r, "dcs_enabled")
		c.DCS.Role.Worker = formBool(r, "dcs_worker")
		c.DCS.Role.Lab = formBool(r, "dcs_lab")
		c.DCS.Limits.MaxContainers = formInt(r, "dcs_max_containers", c.DCS.Limits.MaxContainers)
		if gib := strings.TrimSpace(r.FormValue("dcs_ram_gib")); gib != "" {
			if f, e := strconv.ParseFloat(gib, 64); e == nil && f > 0 {
				c.DCS.Limits.RAMBytes = int64(f * (1 << 30))
			}
		}
		c.DCS.Limits.MaxRuntimeSeconds = formInt(r, "dcs_max_runtime", c.DCS.Limits.MaxRuntimeSeconds)
		if v := strings.TrimSpace(r.FormValue("dcs_docker_endpoint")); v != "" {
			c.DCS.DockerEndpoint = v
		}
		c.DCS.APIListen = strings.TrimSpace(r.FormValue("dcs_api_listen"))
		// Trusted brokers: one node id per line.
		var brokers []string
		for _, line := range strings.Split(r.FormValue("dcs_trusted_brokers"), "\n") {
			if b := strings.TrimSpace(line); b != "" {
				brokers = append(brokers, b)
			}
		}
		c.DCS.Policy.TrustedBrokers = brokers
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.logger.Printf("Docker (DCS) configuration updated (effective next start)")
	http.Redirect(w, r, "/?saved=dcs", http.StatusSeeOther)
}
