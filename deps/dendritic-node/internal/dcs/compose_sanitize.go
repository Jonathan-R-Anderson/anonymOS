package dcs

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// SanitizeComposeForContainment prepares a docker-compose project for a DCS
// worker. It does two things, in one pass over the project so document order and
// comments survive:
//
//  1. REMOVES every host port publish (`ports:`) from every service. A lab must
//     be reachable ONLY over the I2P destination the agent attaches, never on the
//     worker operator's clearnet -- and `docker compose up` would otherwise bind
//     those ports on the host. Container ports keep working: the app still
//     listens inside its network namespace, which is exactly where the I2P proxy
//     dials, so stripping host publishing costs nothing but the leak.
//
//  2. Reports the PRIMARY service -- the internet-facing one the inbound stream is
//     routed to. It is the service whose `ports:`/`expose:` include primaryPort;
//     failing that, the first service in document order.
//
// `expose:` is left intact: it only makes a port reachable to the other services
// on the compose network, never to the host.
func SanitizeComposeForContainment(data []byte, primaryPort int) (sanitized []byte, primaryService string, err error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, "", fmt.Errorf("parse compose: %w", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, "", fmt.Errorf("compose: not a mapping at the top level")
	}
	services := mappingValue(doc.Content[0], "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil, "", fmt.Errorf("compose: no services block")
	}

	type svc struct {
		name  string
		ports []int
	}
	var ordered []svc
	for i := 0; i+1 < len(services.Content); i += 2 {
		name := services.Content[i].Value
		body := services.Content[i+1]
		var ports []int
		if body.Kind == yaml.MappingNode {
			ports = append(ports, containerPortsFromSeq(mappingValue(body, "ports"))...)
			ports = append(ports, containerPortsFromSeq(mappingValue(body, "expose"))...)
			removeMappingKey(body, "ports") // containment: no host publishing
		}
		ordered = append(ordered, svc{name: name, ports: ports})
	}

	for _, s := range ordered {
		for _, p := range s.ports {
			if p == primaryPort {
				primaryService = s.name
				break
			}
		}
		if primaryService != "" {
			break
		}
	}
	if primaryService == "" && len(ordered) > 0 {
		primaryService = ordered[0].name
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, "", err
	}
	return out, primaryService, nil
}

func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func removeMappingKey(m *yaml.Node, key string) {
	if m == nil || m.Kind != yaml.MappingNode {
		return
	}
	kept := make([]*yaml.Node, 0, len(m.Content))
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			continue
		}
		kept = append(kept, m.Content[i], m.Content[i+1])
	}
	m.Content = kept
}

var composePortNum = regexp.MustCompile(`\d+`)

// containerPortsFromSeq extracts the CONTAINER-side ports from a `ports:` or
// `expose:` sequence, across the short forms ("8080:8080", "80",
// "127.0.0.1:8080:8080", "53:53/udp") and the long form (target:/published:).
func containerPortsFromSeq(seq *yaml.Node) []int {
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil
	}
	var ports []int
	for _, item := range seq.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			s := item.Value
			if idx := strings.IndexByte(s, '/'); idx >= 0 {
				s = s[:idx] // drop /tcp, /udp
			}
			nums := composePortNum.FindAllString(s, -1)
			if len(nums) > 0 {
				// "H:C" and "IP:H:C" -> last number is the container port;
				// a lone "C" -> itself.
				if n, e := strconv.Atoi(nums[len(nums)-1]); e == nil {
					ports = append(ports, n)
				}
			}
		case yaml.MappingNode:
			if t := mappingValue(item, "target"); t != nil {
				if n, e := strconv.Atoi(strings.TrimSpace(t.Value)); e == nil {
					ports = append(ports, n)
				}
			}
		}
	}
	return ports
}
