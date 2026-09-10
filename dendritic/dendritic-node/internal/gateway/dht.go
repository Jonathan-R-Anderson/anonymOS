package gateway

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const DHTNamespace = "syndichan-gateway"

type DHTValidator struct {
	TrustedProbes   map[string]string
	MinimumProbes   int
	MinimumNetworks int
	Now             func() time.Time
}

func (v DHTValidator) Validate(key string, value []byte) error {
	nodeID, ok := dhtNodeID(key)
	if !ok {
		return errors.New("invalid gateway DHT key")
	}
	var registration Registration
	if len(value) > 256<<10 || json.Unmarshal(value, &registration) != nil {
		return errors.New("invalid gateway registration encoding")
	}
	if registration.NodeID != nodeID {
		return errors.New("gateway record stored under another node ID")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	return registration.Validate(v.TrustedProbes, now, v.MinimumProbes, v.MinimumNetworks)
}

func (v DHTValidator) Select(key string, values [][]byte) (int, error) {
	best := -1
	var sequence uint64
	for index, value := range values {
		if v.Validate(key, value) != nil {
			continue
		}
		var registration Registration
		_ = json.Unmarshal(value, &registration)
		if best == -1 || registration.Sequence > sequence {
			best, sequence = index, registration.Sequence
		}
	}
	if best < 0 {
		return 0, errors.New("no valid gateway registrations")
	}
	return best, nil
}

func DHTKey(nodeID string) string {
	return "/" + DHTNamespace + "/" + nodeID
}

func dhtNodeID(key string) (string, bool) {
	prefix := "/" + DHTNamespace + "/"
	if !strings.HasPrefix(key, prefix) {
		return "", false
	}
	value := strings.TrimPrefix(key, prefix)
	return value, value != "" && !strings.Contains(value, "/")
}
