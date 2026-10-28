package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/nizartuanku/attack-surface-monitor/notify"
	"github.com/nizartuanku/hexward-core/hfs"
	"github.com/nizartuanku/hexward-core/sink"
)

// channelFlags are the alert and SIEM export settings. Every channel here is
// available in every edition, Free included.
type channelFlags struct {
	webhook           string
	webhookFormat     string // v1 | v2
	webhookSecretFile string

	syslogAddr    string
	syslogNetwork string // udp | tcp | tls
	syslogFormat  string // kv | json | cef
	syslogRFC     int    // 5424 | 3164 (json and cef only)
	syslogCAFile  string

	exportFile string

	hecURL       string
	hecTokenFile string
	hecIndex     string
	hecCAFile    string

	evidence string // redacted | none
}

func registerChannelFlags(fs *flag.FlagSet) *channelFlags {
	c := &channelFlags{}
	fs.StringVar(&c.webhook, "webhook", "", "webhook URL for alerts")
	fs.StringVar(&c.webhookFormat, "webhook-format", "v1", "webhook payload: v1 (digest, the original format) or v2 (Hexward Finding Schema events)")
	fs.StringVar(&c.webhookSecretFile, "webhook-secret-file", "", "file holding a shared secret, sent as the X-Hexward-Token header")
	fs.StringVar(&c.syslogAddr, "syslog", "", "syslog collector host:port for findings, e.g. 127.0.0.1:5514 (point this at Loglight to correlate across products)")
	fs.StringVar(&c.syslogNetwork, "syslog-network", "udp", "syslog transport: udp, tcp or tls (tls needs -syslog-format json or cef)")
	fs.StringVar(&c.syslogFormat, "syslog-format", "kv", "syslog message format: kv (key=value, the original format), json (Hexward Finding Schema) or cef")
	fs.IntVar(&c.syslogRFC, "syslog-rfc", 5424, "syslog header for json/cef: 5424 or 3164")
	fs.StringVar(&c.syslogCAFile, "syslog-ca-file", "", "PEM CA file trusted for -syslog-network tls, in addition to the system roots")
	fs.StringVar(&c.exportFile, "export-file", "", "append findings as Hexward Finding Schema NDJSON to this file, for Wazuh, Splunk or Elastic agents to read")
	fs.StringVar(&c.hecURL, "hec-url", "", "Splunk HTTP Event Collector URL, e.g. https://splunk.example:8088")
	fs.StringVar(&c.hecTokenFile, "hec-token-file", "", "file holding the Splunk HEC token (required with -hec-url)")
	fs.StringVar(&c.hecIndex, "hec-index", "", "Splunk index for findings (optional; must be allowed for the token)")
	fs.StringVar(&c.hecCAFile, "hec-ca-file", "", "PEM CA file trusted for -hec-url, in addition to the system roots")
	fs.StringVar(&c.evidence, "export-evidence", "redacted", "evidence in exported findings: redacted (secret-like keys dropped) or none")
	return c
}

// build turns the flags into channels. It fails on any inconsistent
// setting, so a typo stops the binary at start-up instead of silently
// dropping alerts later.
func (c *channelFlags) build(meta hfs.Meta) ([]notify.Channel, error) {
	mode, ok := hfs.ParseEvidenceMode(c.evidence)
	if !ok {
		return nil, fmt.Errorf("-export-evidence %q: want redacted or none", c.evidence)
	}
	opt := hfs.Options{Evidence: mode}
	var out []notify.Channel

	if c.webhook != "" {
		secret := ""
		if c.webhookSecretFile != "" {
			s, err := sink.ReadSecretFile(c.webhookSecretFile)
			if err != nil {
				return nil, fmt.Errorf("-webhook-secret-file: %w", err)
			}
			secret = s
		}
		switch c.webhookFormat {
		case "", "v1":
			out = append(out, &notify.WebhookChannel{URL: c.webhook, Secret: secret})
		case "v2":
			out = append(out, &notify.HFSChannel{Sink: &sink.Webhook{URL: c.webhook, Secret: secret}, Meta: meta, Options: opt})
		default:
			return nil, fmt.Errorf("-webhook-format %q: want v1 or v2", c.webhookFormat)
		}
	}

	if c.syslogAddr != "" {
		switch c.syslogFormat {
		case "", "kv":
			if c.syslogNetwork != "udp" && c.syslogNetwork != "tcp" {
				return nil, fmt.Errorf("-syslog-network %q with -syslog-format kv: want udp or tcp (tls needs json or cef)", c.syslogNetwork)
			}
			out = append(out, &notify.SyslogChannel{Addr: c.syslogAddr, Network: c.syslogNetwork})
		case sink.FormatJSON, sink.FormatCEF:
			s := &sink.Syslog{Addr: c.syslogAddr, Network: c.syslogNetwork, Format: c.syslogFormat, RFC: c.syslogRFC}
			if c.syslogNetwork == "tls" {
				host, _, _ := net.SplitHostPort(c.syslogAddr)
				tc, err := sink.TLSConfig(c.syslogCAFile, host)
				if err != nil {
					return nil, fmt.Errorf("-syslog-ca-file: %w", err)
				}
				s.TLS = tc
			}
			if err := s.Validate(); err != nil {
				return nil, err
			}
			out = append(out, &notify.HFSChannel{Sink: s, Meta: meta, Options: opt})
		default:
			return nil, fmt.Errorf("-syslog-format %q: want kv, json or cef", c.syslogFormat)
		}
	}

	if c.exportFile != "" {
		out = append(out, &notify.HFSChannel{Sink: &sink.File{Path: c.exportFile}, Meta: meta, Options: opt})
	}

	if c.hecURL != "" {
		if c.hecTokenFile == "" {
			return nil, fmt.Errorf("-hec-url needs -hec-token-file")
		}
		tok, err := sink.ReadSecretFile(c.hecTokenFile)
		if err != nil {
			return nil, fmt.Errorf("-hec-token-file: %w", err)
		}
		h := &sink.HEC{URL: c.hecURL, Token: tok, Index: c.hecIndex}
		if _, err := h.Endpoint(); err != nil {
			return nil, fmt.Errorf("-hec-url: %w", err)
		}
		if c.hecCAFile != "" {
			tc, err := sink.TLSConfig(c.hecCAFile, "")
			if err != nil {
				return nil, fmt.Errorf("-hec-ca-file: %w", err)
			}
			h.TLS = tc
		}
		out = append(out, &notify.HFSChannel{Sink: h, Meta: meta, Options: opt})
	}
	return out, nil
}

// evidenceMode is the validated -export-evidence value (build has already
// rejected anything else).
func (c *channelFlags) evidenceMode() hfs.EvidenceMode {
	m, _ := hfs.ParseEvidenceMode(c.evidence)
	return m
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
