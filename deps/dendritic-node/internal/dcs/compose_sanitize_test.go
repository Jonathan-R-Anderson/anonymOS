package dcs

import (
	"strings"
	"testing"
)

func TestSanitizeComposeStripsPortsAndPicksPrimary(t *testing.T) {
	in := []byte(`services:
  web:
    image: vulhub/app:1
    ports:
      - "8080:8080"
      - "127.0.0.1:9000:9000"
    depends_on:
      - db
  db:
    image: mysql:5.7
    ports:
      - "3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: root
`)
	out, primary, err := SanitizeComposeForContainment(in, 8080)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if primary != "web" {
		t.Fatalf("primary = %q, want web", primary)
	}
	s := string(out)
	// No host publishing survives anywhere.
	if strings.Contains(s, "8080:8080") || strings.Contains(s, "3306:3306") || strings.Contains(s, "ports:") {
		t.Fatalf("host ports were not stripped:\n%s", s)
	}
	// The rest of the project is intact.
	for _, want := range []string{"web:", "db:", "image: vulhub/app:1", "MYSQL_ROOT_PASSWORD", "depends_on"} {
		if !strings.Contains(s, want) {
			t.Fatalf("sanitized compose dropped %q:\n%s", want, s)
		}
	}
}

func TestSanitizeComposePrimaryByExposeThenFirst(t *testing.T) {
	// primaryPort matches an `expose` entry on the second service.
	in := []byte("services:\n  a:\n    image: x\n  b:\n    image: y\n    expose:\n      - \"7001\"\n")
	_, primary, err := SanitizeComposeForContainment(in, 7001)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if primary != "b" {
		t.Fatalf("primary = %q, want b (matched by expose)", primary)
	}

	// primaryPort matches nothing -> first service in document order.
	_, primary, err = SanitizeComposeForContainment(in, 12345)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if primary != "a" {
		t.Fatalf("primary = %q, want a (first service)", primary)
	}
}

func TestSanitizeComposeLongFormPorts(t *testing.T) {
	in := []byte("services:\n  web:\n    image: x\n    ports:\n      - target: 80\n        published: 8080\n        protocol: tcp\n")
	out, primary, err := SanitizeComposeForContainment(in, 80)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if primary != "web" {
		t.Fatalf("primary = %q, want web (long-form target 80)", primary)
	}
	if strings.Contains(string(out), "published") {
		t.Fatalf("long-form host publish not stripped:\n%s", out)
	}
}
