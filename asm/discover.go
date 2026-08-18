package asm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Discoverer finds the hostnames belonging to a root domain. Real
// implementation uses passive sources (Certificate Transparency + DNS); tests
// inject a fake. Passive-only by default keeps discovery safe and quiet — it
// touches public records, not the target's infrastructure.
type Discoverer interface {
	Discover(ctx context.Context, rootDomain string) (Assets, error)
}

// Assets is the discovered inventory for a root domain.
type Assets struct {
	// Hostnames includes the root and every discovered subdomain that currently
	// resolves. Sorted, de-duplicated.
	Hostnames []string
	// Sources notes which discovery methods actually contributed, so the UI can
	// be honest about coverage (e.g. "CT unavailable, DNS only").
	Sources []string
}

// ctDNSDiscoverer is the production Discoverer: Certificate Transparency (via
// crt.sh) for candidate names, then DNS resolution to keep only live ones.
type ctDNSDiscoverer struct {
	httpGet  func(ctx context.Context, url string) (string, error)
	resolve  func(ctx context.Context, host string) bool // does it resolve?
	ctBudget int                                         // max candidate names to resolve
}

func newDiscoverer() *ctDNSDiscoverer {
	return &ctDNSDiscoverer{
		httpGet:  httpGet,
		resolve:  resolves,
		ctBudget: 500,
	}
}

func (d *ctDNSDiscoverer) Discover(ctx context.Context, root string) (Assets, error) {
	root = strings.ToLower(strings.TrimSuffix(root, "."))
	candidates := map[string]struct{}{root: {}}
	var sources []string

	// Certificate Transparency: names that ever had a cert issued.
	if names, err := d.ctNames(ctx, root); err == nil && len(names) > 0 {
		sources = append(sources, "certificate-transparency")
		for _, n := range names {
			candidates[n] = struct{}{}
		}
	}

	// Keep only names that currently resolve (live assets), within budget.
	live := map[string]struct{}{}
	budget := d.ctBudget
	for name := range candidates {
		if budget <= 0 {
			break
		}
		budget--
		if d.resolve(ctx, name) {
			live[name] = struct{}{}
		}
	}
	if len(live) > 0 {
		sources = appendUnique(sources, "dns")
	}
	// The root is always included even if DNS was flaky, so a scan never returns
	// an empty inventory for a domain the user verified.
	live[root] = struct{}{}

	out := make([]string, 0, len(live))
	for n := range live {
		out = append(out, n)
	}
	sort.Strings(out)
	return Assets{Hostnames: out, Sources: sources}, nil
}

// ctNames queries crt.sh for subject/SAN names of certs issued for the domain.
func (d *ctDNSDiscoverer) ctNames(ctx context.Context, root string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", root)
	body, err := d.httpGet(ctx, url)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var names []string
	for _, r := range rows {
		for _, n := range strings.Split(r.NameValue, "\n") {
			n = strings.ToLower(strings.TrimSpace(n))
			n = strings.TrimPrefix(n, "*.") // wildcard → base name
			if n == "" || strings.ContainsAny(n, " ") || !strings.HasSuffix(n, root) {
				continue
			}
			if _, dup := seen[n]; dup {
				continue
			}
			seen[n] = struct{}{}
			names = append(names, n)
		}
	}
	return names, nil
}

// --- default network helpers (injected out in tests) ------------------------

func httpGet(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // 8 MB cap
	return string(b), err
}

func resolves(ctx context.Context, host string) bool {
	var r net.Resolver
	addrs, err := r.LookupHost(ctx, host)
	return err == nil && len(addrs) > 0
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
