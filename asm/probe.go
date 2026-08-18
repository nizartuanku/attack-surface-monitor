package asm

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Exposure is one open port/service found on a host, already classified for
// severity. The collector turns each into a core.Finding.
type Exposure struct {
	Host        string
	Port        int
	Service     string // human name, e.g. "PostgreSQL"
	Severity    string // tlsprobe.Sev* string values
	Title       string
	Remediation string
	Evidence    map[string]any
}

// Prober checks one host for exposed ports/services. Real implementation dials;
// tests inject a fake. It must be polite (bounded, rate-limited) — it only ever
// runs against verified targets, but courtesy is still the rule.
type Prober interface {
	Probe(ctx context.Context, host string) ([]Exposure, error)
}

// portClass describes how to treat a given port if it's found open.
type portClass struct {
	service     string
	severity    string
	sensitive   bool // true → its own high/critical finding; false → inventory only
	remediation string
}

// portCatalog is the curated set of ports ASM probes and how it grades them.
// Databases reachable from the internet are critical; remote-access and legacy
// clear-text services are high; common web/mail ports are inventory (low).
var portCatalog = map[int]portClass{
	// Databases — should never be internet-facing.
	5432:  {"PostgreSQL", sevCritical, true, "Bind PostgreSQL to localhost or a private network and put it behind a firewall. A database reachable from the internet is a direct breach path."},
	3306:  {"MySQL/MariaDB", sevCritical, true, "Restrict MySQL to trusted networks only; it should not accept connections from the public internet."},
	27017: {"MongoDB", sevCritical, true, "Bind MongoDB to localhost/VPC and enable authentication. Exposed MongoDB is a classic ransomware target."},
	6379:  {"Redis", sevCritical, true, "Never expose Redis to the internet — it usually has no auth. Bind to localhost and firewall the port."},
	9200:  {"Elasticsearch", sevCritical, true, "Put Elasticsearch behind authentication and a private network. Open clusters leak entire datasets."},
	5984:  {"CouchDB", sevCritical, true, "Restrict CouchDB to a private network and require authentication."},
	// Remote access.
	3389: {"RDP", sevHigh, true, "Do not expose RDP to the internet. Put it behind a VPN or a bastion, and enable NLA + MFA."},
	5900: {"VNC", sevHigh, true, "VNC exposed to the internet is high risk. Tunnel it over SSH/VPN and require strong authentication."},
	23:   {"Telnet", sevHigh, true, "Telnet is clear-text and must never be internet-facing. Disable it and use SSH instead."},
	// SSH is common and often intentional — flag as inventory, not an alarm.
	22: {"SSH", sevLow, false, "SSH exposure is common but keep it patched, key-only, and consider restricting source IPs."},
	// Web / mail — inventory unless content checks find more (see httpChecks).
	80:   {"HTTP", sevLow, false, ""},
	443:  {"HTTPS", sevLow, false, ""},
	8080: {"HTTP-alt", sevLow, false, ""},
	8443: {"HTTPS-alt", sevLow, false, ""},
	25:   {"SMTP", sevLow, false, ""},
}

// dialProber is the production Prober: it dials each catalogued port with a
// short timeout and a small bounded concurrency, then classifies what answered.
type dialProber struct {
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	timeout time.Duration
}

func newDialProber() *dialProber {
	var d net.Dialer
	return &dialProber{dial: d.DialContext, timeout: 3 * time.Second}
}

func (p *dialProber) Probe(ctx context.Context, host string) ([]Exposure, error) {
	var out []Exposure
	// Sequential + short timeout keeps it polite; the scheduler already bounds
	// how many hosts are probed at once across targets.
	for port, class := range portCatalog {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		pctx, cancel := context.WithTimeout(ctx, p.timeout)
		conn, err := p.dial(pctx, "tcp", net.JoinHostPort(host, itoa(port)))
		cancel()
		if err != nil {
			continue // closed/filtered — not open
		}
		conn.Close()
		out = append(out, classify(host, port, class))
	}
	return out, nil
}

// classify builds the Exposure for an open port. Pure function → unit-tested.
func classify(host string, port int, class portClass) Exposure {
	title := fmt.Sprintf("%s exposed on %s:%d", class.service, host, port)
	if !class.sensitive {
		title = fmt.Sprintf("Open port %d (%s) on %s", port, class.service, host)
	}
	rem := class.remediation
	if rem == "" {
		rem = "Confirm this service is meant to be internet-facing; if not, restrict it to a private network or firewall the port."
	}
	return Exposure{
		Host: host, Port: port, Service: class.service,
		Severity: class.severity, Title: title, Remediation: rem,
		Evidence: map[string]any{"host": host, "port": port, "service": class.service},
	}
}

// classifyPort looks up a port in the catalog (helper for tests/collector).
func classifyPort(host string, port int) (Exposure, bool) {
	class, ok := portCatalog[port]
	if !ok {
		return Exposure{}, false
	}
	return classify(host, port, class), true
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
